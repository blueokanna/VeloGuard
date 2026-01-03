//! Fake IP implementation for DNS
//! 
//! This is used in fake-ip DNS mode to return fake IPs for domain resolution.
//! The fake-ip range is typically 198.18.0.0/16, with reserved addresses:
//! - 198.18.0.0 = network address (reserved)
//! - 198.18.0.1 = TUN device address (reserved)
//! - 198.18.0.2 = DNS server address (reserved)
//! - 198.18.0.3+ = available for Fake-IP allocation

use crate::dns::error::{DnsError, DnsResult};
use dashmap::DashMap;
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{debug, info};

/// Fake IP pool manager
pub struct FakeIpPool {
    /// IP range for fake IPs
    range: Ipv4Net,
    /// Current IP counter
    counter: AtomicU32,
    /// Domain to IP mapping
    domain_to_ip: DashMap<String, Ipv4Addr>,
    /// IP to domain mapping (reverse lookup)
    ip_to_domain: DashMap<Ipv4Addr, String>,
    /// Start IP as u32
    start_ip: u32,
    /// End IP as u32
    end_ip: u32,
}

impl FakeIpPool {
    /// Create a new fake IP pool with the given CIDR range
    pub fn new(cidr: &str) -> DnsResult<Self> {
        let range: Ipv4Net = cidr.parse()
            .map_err(|e| DnsError::FakeIpError(format!("Invalid CIDR range: {}", e)))?;

        let network = range.network();
        let broadcast = range.broadcast();

        // Skip network address, TUN address (x.x.0.1), and DNS server (x.x.0.2)
        // For 198.18.0.0/16:
        // - 198.18.0.0 = network address (reserved)
        // - 198.18.0.1 = TUN device address (reserved)
        // - 198.18.0.2 = DNS server address (reserved)
        // - 198.18.0.3+ = available for Fake-IP allocation
        let start_ip = u32::from(network) + 3; // Skip .0, .1, .2
        let end_ip = u32::from(broadcast) - 1;

        if start_ip >= end_ip {
            return Err(DnsError::FakeIpError("CIDR range too small".to_string()));
        }

        debug!("Fake IP pool initialized: {} ({} IPs available, starting from offset 3)", cidr, end_ip - start_ip);

        Ok(Self {
            range,
            counter: AtomicU32::new(0),
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
            start_ip,
            end_ip,
        })
    }

    /// Allocate a fake IP for a domain
    pub fn allocate(&mut self, domain: &str) -> Option<IpAddr> {
        // Normalize domain to lowercase for consistent lookup
        let domain = domain.to_lowercase();
        
        // Check if domain already has an IP
        if let Some(ip) = self.domain_to_ip.get(&domain) {
            debug!("Fake-IP cache hit: {} -> {}", domain, *ip);
            return Some(IpAddr::V4(*ip));
        }

        // Allocate new IP
        let offset = self.counter.fetch_add(1, Ordering::SeqCst);
        let pool_size = self.end_ip - self.start_ip;

        // Wrap around if we've exhausted the pool
        let offset = offset % pool_size;
        let ip_u32 = self.start_ip + offset;
        let ip = Ipv4Addr::from(ip_u32);
        
        info!("Fake-IP allocated: {} -> {} (offset={}, pool_size={})", domain, ip, offset, pool_size);

        // If this IP was previously used, remove old mapping
        if let Some((_, old_domain)) = self.ip_to_domain.remove(&ip) {
            self.domain_to_ip.remove(&old_domain);
            debug!("Evicted old mapping: {} -> {}", ip, old_domain);
        }

        // Store mappings
        self.domain_to_ip.insert(domain.clone(), ip);
        self.ip_to_domain.insert(ip, domain.clone());

        debug!("Allocated fake IP {} for domain {}", ip, domain);
        Some(IpAddr::V4(ip))
    }

    /// Look up the domain for a fake IP
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(&ip).map(|r| r.clone())
    }

    /// Look up the fake IP for a domain
    pub fn lookup_domain(&self, domain: &str) -> Option<Ipv4Addr> {
        self.domain_to_ip.get(domain).map(|r| *r)
    }

    /// Check if an IP is in the fake IP range
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.range.contains(&v4),
            IpAddr::V6(_) => false,
        }
    }

    /// Get the number of allocated IPs
    pub fn allocated_count(&self) -> usize {
        self.domain_to_ip.len()
    }

    /// Get the pool capacity
    pub fn capacity(&self) -> u32 {
        self.end_ip - self.start_ip
    }

    /// Clear all mappings
    pub fn clear(&mut self) {
        self.domain_to_ip.clear();
        self.ip_to_domain.clear();
        self.counter.store(0, Ordering::SeqCst);
    }

    /// Reset the pool completely (clear mappings and reset counter)
    /// This should be called when VPN service restarts
    pub fn reset(&mut self) {
        self.domain_to_ip.clear();
        self.ip_to_domain.clear();
        self.counter.store(0, Ordering::SeqCst);
        info!("Fake-IP pool reset: counter=0, mappings cleared");
    }

    /// Get current counter value (for debugging)
    pub fn current_counter(&self) -> u32 {
        self.counter.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_allocation() {
        let mut pool = FakeIpPool::new("198.18.0.0/24").unwrap();

        let ip1 = pool.allocate("example.com").unwrap();
        let ip2 = pool.allocate("test.com").unwrap();
        let ip3 = pool.allocate("example.com").unwrap(); // Should return same IP

        assert_ne!(ip1, ip2);
        assert_eq!(ip1, ip3);
    }

    #[test]
    fn test_fake_ip_lookup() {
        let mut pool = FakeIpPool::new("198.18.0.0/24").unwrap();

        let ip = pool.allocate("example.com").unwrap();
        if let IpAddr::V4(v4) = ip {
            let domain = pool.lookup(v4);
            assert_eq!(domain, Some("example.com".to_string()));
        }
    }

    #[test]
    fn test_is_fake_ip() {
        let pool = FakeIpPool::new("198.18.0.0/16").unwrap();

        assert!(pool.is_fake_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(pool.is_fake_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 255, 254))));
        assert!(!pool.is_fake_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_fake_ip_starts_from_offset_3() {
        let mut pool = FakeIpPool::new("198.18.0.0/16").unwrap();
        
        // First allocation should be 198.18.0.3 (offset 3)
        let ip = pool.allocate("first.com").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 18, 0, 3)));
        
        // Second allocation should be 198.18.0.4
        let ip = pool.allocate("second.com").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 18, 0, 4)));
    }
}
