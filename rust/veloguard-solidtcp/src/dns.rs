//! DNS handling with Fake-IP support

use crate::error::{Result, SolidTcpError};
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

/// Fake-IP configuration
#[derive(Debug, Clone)]
pub struct FakeIpConfig {
    pub range_start: Ipv4Addr,
    pub pool_size: u32,
    pub ttl: Duration,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            range_start: Ipv4Addr::new(198, 18, 0, 0),
            pool_size: 65536,
            ttl: Duration::from_secs(600),
        }
    }
}

/// Fake-IP entry
#[derive(Debug, Clone)]
pub struct FakeIpEntry {
    pub ip: Ipv4Addr,
    pub domain: String,
    pub expires: Instant,
}

/// Fake-IP pool
pub struct FakeIpPool {
    config: FakeIpConfig,
    domain_to_ip: DashMap<String, FakeIpEntry>,
    ip_to_domain: DashMap<Ipv4Addr, String>,
    next_offset: AtomicU32,
    lru: Mutex<LruCache<String, Ipv4Addr>>,
}

impl FakeIpPool {
    pub fn new() -> Self {
        Self::with_config(FakeIpConfig::default())
    }

    // - 198.18.0.0 (network address)
    // - 198.18.0.1 (TUN device address)
    // - 198.18.0.2 (DNS server address)
    pub fn with_config(config: FakeIpConfig) -> Self {
        let sz =
            NonZeroUsize::new(config.pool_size as usize).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            config,
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
            next_offset: AtomicU32::new(3),
            lru: Mutex::new(LruCache::new(sz)),
        }
    }

    pub fn allocate(&self, domain: &str) -> Result<Ipv4Addr> {
        let domain = domain.to_lowercase();
        if let Some(e) = self.domain_to_ip.get(&domain) {
            if Instant::now() < e.expires {
                self.lru.lock().put(domain.clone(), e.ip);
                return Ok(e.ip);
            }
        }

        let offset = self.next_offset.fetch_add(1, Ordering::Relaxed);
        let effective_offset = if offset >= self.config.pool_size {
            self.next_offset.store(3, Ordering::Relaxed);
            self.cleanup();
            if self.domain_to_ip.len() >= self.config.pool_size as usize - 3 {
                return Err(SolidTcpError::FakeIpPoolExhausted);
            }
            3
        } else if offset < 3 {
            self.next_offset.store(3, Ordering::Relaxed);
            3
        } else {
            offset
        };

        let ip = self.offset_to_ip(effective_offset);
        if let Some((_, old)) = self.ip_to_domain.remove(&ip) {
            self.domain_to_ip.remove(&old);
        }

        let entry = FakeIpEntry {
            ip,
            domain: domain.clone(),
            expires: Instant::now() + self.config.ttl,
        };
        self.domain_to_ip.insert(domain.clone(), entry);
        self.ip_to_domain.insert(ip, domain.clone());
        self.lru.lock().put(domain.clone(), ip);
        info!("Fake-IP allocated: {} -> {}", ip, domain);
        Ok(ip)
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(&ip).map(|d| d.clone())
    }

    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        let start = u32::from(self.config.range_start);
        let val = u32::from(ip);
        val >= start && val < start + self.config.pool_size
    }

    fn offset_to_ip(&self, offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.config.range_start) + offset)
    }

    pub fn cleanup(&self) {
        let expired: Vec<_> = self
            .domain_to_ip
            .iter()
            .filter(|e| Instant::now() >= e.expires)
            .map(|e| (e.key().clone(), e.ip))
            .collect();
        for (domain, ip) in expired {
            self.domain_to_ip.remove(&domain);
            self.ip_to_domain.remove(&ip);
        }
    }

    pub fn cleanup_expired(&self) {
        self.cleanup();
    }
    pub fn size(&self) -> usize {
        self.domain_to_ip.len()
    }

    pub fn clear(&self) {
        self.domain_to_ip.clear();
        self.ip_to_domain.clear();
        self.lru.lock().clear();
        self.next_offset.store(3, Ordering::Relaxed);
        info!("Fake-IP pool cleared, next_offset reset to 3");
    }
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS query type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQueryType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    Other = 0,
}

impl DnsQueryType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            _ => Self::Other,
        }
    }
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Parsed DNS query
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: String,
    pub qtype: DnsQueryType,
    pub qclass: u16,
}

/// DNS handler
pub struct DnsHandler {
    fake_ip_pool: Arc<FakeIpPool>,
}

impl DnsHandler {
    pub fn new(pool: Arc<FakeIpPool>) -> Self {
        Self { fake_ip_pool: pool }
    }

    pub fn parse_query(&self, data: &[u8]) -> Result<DnsQuery> {
        if data.len() < 12 {
            return Err(SolidTcpError::DnsError("Too short".into()));
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        if data[2] & 0x80 != 0 {
            return Err(SolidTcpError::DnsError("Not a query".into()));
        }
        let (domain, offset) = self.parse_name(data, 12)?;
        if offset + 4 > data.len() {
            return Err(SolidTcpError::DnsError("Truncated".into()));
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        Ok(DnsQuery {
            id,
            domain,
            qtype: DnsQueryType::from_u16(qtype),
            qclass,
        })
    }

    fn parse_name(&self, data: &[u8], start: usize) -> Result<(String, usize)> {
        let mut labels = Vec::new();
        let mut pos = start;
        let mut jumped = false;
        let mut jump_pos = 0;
        loop {
            if pos >= data.len() {
                return Err(SolidTcpError::DnsError("Name truncated".into()));
            }
            let len = data[pos] as usize;
            if len == 0 {
                if !jumped {
                    pos += 1;
                }
                break;
            }
            if len & 0xC0 == 0xC0 {
                if pos + 1 >= data.len() {
                    return Err(SolidTcpError::DnsError("Ptr truncated".into()));
                }
                let ptr = ((len & 0x3F) << 8) | data[pos + 1] as usize;
                if !jumped {
                    jump_pos = pos + 2;
                    jumped = true;
                }
                pos = ptr;
                continue;
            }
            pos += 1;
            if pos + len > data.len() {
                return Err(SolidTcpError::DnsError("Label truncated".into()));
            }
            labels.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
            pos += len;
        }
        Ok((labels.join("."), if jumped { jump_pos } else { pos }))
    }

    pub fn build_response(&self, query: &DnsQuery, ip: Ipv4Addr) -> Vec<u8> {
        let mut r = Vec::with_capacity(512);
        r.extend_from_slice(&query.id.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        self.encode_name(&mut r, &query.domain);
        r.extend_from_slice(&query.qtype.to_u16().to_be_bytes());
        r.extend_from_slice(&query.qclass.to_be_bytes());
        r.extend_from_slice(&0xC00Cu16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&60u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&ip.octets());
        r
    }

    pub fn build_nxdomain(&self, query: &DnsQuery) -> Vec<u8> {
        let mut r = Vec::with_capacity(512);
        r.extend_from_slice(&query.id.to_be_bytes());
        r.extend_from_slice(&0x8183u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        self.encode_name(&mut r, &query.domain);
        r.extend_from_slice(&query.qtype.to_u16().to_be_bytes());
        r.extend_from_slice(&query.qclass.to_be_bytes());
        r
    }

    fn encode_name(&self, buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            if !label.is_empty() {
                buf.push(label.len() as u8);
                buf.extend_from_slice(label.as_bytes());
            }
        }
        buf.push(0);
    }

    pub fn handle_query(&self, data: &[u8]) -> Result<(Vec<u8>, Option<String>)> {
        let query = self.parse_query(data)?;
        info!("DNS query received: {} ({:?})", query.domain, query.qtype);
        match query.qtype {
            DnsQueryType::A => {
                let ip = self.fake_ip_pool.allocate(&query.domain)?;
                info!("DNS A query: {} -> {} (Fake-IP allocated)", query.domain, ip);
                let response = self.build_response(&query, ip);
                info!("DNS response built: {} bytes for {}", response.len(), query.domain);
                Ok((response, Some(query.domain)))
            }
            DnsQueryType::AAAA => {
                // Return empty response for AAAA to force IPv4
                // This prevents apps from trying IPv6 which we don't support
                info!("DNS AAAA query: {} -> empty response (force IPv4)", query.domain);
                Ok((self.build_empty_response(&query), None))
            }
            _ => {
                info!("DNS other query type {:?}: {} -> NXDOMAIN", query.qtype, query.domain);
                Ok((self.build_nxdomain(&query), None))
            }
        }
    }

    /// Build empty response (no answers, but not NXDOMAIN)
    pub fn build_empty_response(&self, query: &DnsQuery) -> Vec<u8> {
        let mut r = Vec::with_capacity(512);
        r.extend_from_slice(&query.id.to_be_bytes());
        // Flags: Response, No error, Recursion available
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        r.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        r.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        self.encode_name(&mut r, &query.domain);
        r.extend_from_slice(&query.qtype.to_u16().to_be_bytes());
        r.extend_from_slice(&query.qclass.to_be_bytes());
        r
    }

    pub fn pool(&self) -> &Arc<FakeIpPool> {
        &self.fake_ip_pool
    }
}
