//! DNS resolver with caching and routing

use crate::bogon::contains_bogon;
use crate::cache::DnsCache;
use crate::client::{create_clients, DnsClient};
use crate::config::DnsConfig;
use crate::error::{DnsError, Result};
use crate::fake_ip::FakeIpPool;
use crate::hosts::HostsFile;
use crate::RecordType;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

/// DNS resolver with caching, Fake-IP, and routing support
pub struct DnsResolver {
    /// DNS cache
    cache: Arc<DnsCache>,
    /// Fake-IP pool
    fake_ip: Option<Arc<FakeIpPool>>,
    /// Hosts file
    hosts: Arc<RwLock<HostsFile>>,
    /// Primary DNS clients
    primary_clients: Vec<DnsClient>,
    /// Fallback DNS clients
    fallback_clients: Vec<DnsClient>,
    /// Configuration
    config: DnsConfig,
}

impl DnsResolver {
    /// Create a new DNS resolver
    pub fn new(config: DnsConfig) -> Result<Self> {
        let cache = Arc::new(DnsCache::new(
            config.cache_size,
            config.min_ttl as u32,
            config.max_ttl as u32,
        ));

        let fake_ip = if config.fake_ip {
            Some(Arc::new(FakeIpPool::new(
                &config.fake_ip_range,
                config.fake_ip_filter.clone(),
            )?))
        } else {
            None
        };

        let hosts = Arc::new(RwLock::new(HostsFile::from_map(config.hosts.clone())));

        let primary_clients = create_clients(&config.nameservers, config.timeout);
        let fallback_clients = create_clients(&config.fallback, config.timeout);

        if primary_clients.is_empty() {
            return Err(DnsError::NoServers);
        }

        info!(
            "DNS resolver initialized: {} primary servers, {} fallback servers, cache_size={}, fake_ip={}",
            primary_clients.len(),
            fallback_clients.len(),
            config.cache_size,
            config.fake_ip
        );

        Ok(Self {
            cache,
            fake_ip,
            hosts,
            primary_clients,
            fallback_clients,
            config,
        })
    }

    /// Resolve a domain name
    pub async fn resolve(&self, name: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let name = name.trim_end_matches('.');
        trace!("Resolving {} {:?}", name, record_type);

        // 1. Check hosts file
        if let Some(ips) = self.hosts.read().await.lookup(name) {
            debug!("Hosts hit: {} -> {:?}", name, ips);
            return Ok(ips.to_vec());
        }

        // 2. Check Fake-IP (for A records only)
        if record_type == RecordType::A {
            if let Some(ref fake_ip) = self.fake_ip {
                if !fake_ip.should_filter(name) {
                    let ip = fake_ip.allocate(name)?;
                    debug!("Fake-IP: {} -> {}", name, ip);
                    return Ok(vec![IpAddr::V4(ip)]);
                }
            }
        }

        // 3. Check cache
        if let Some(entry) = self.cache.get(name, record_type) {
            debug!("Cache hit: {} {:?} -> {:?}", name, record_type, entry.addresses);
            return Ok(entry.addresses);
        }

        // 4. Query upstream DNS
        let result = self.query_upstream(name, record_type).await?;

        // 5. Cache the result
        if !result.is_empty() {
            self.cache.insert(name, record_type, result.clone(), 300); // Default 5 min TTL
        }

        Ok(result)
    }

    /// Query upstream DNS servers
    async fn query_upstream(&self, name: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let hickory_type = hickory_proto::rr::RecordType::from(record_type);

        // Try primary servers first
        for client in &self.primary_clients {
            match client.query(name, hickory_type).await {
                Ok(response) => {
                    let ips = self.extract_ips(&response, record_type);

                    // Check if we need fallback (anti-spoofing)
                    if self.should_use_fallback(name, &ips) {
                        debug!("Using fallback DNS for {} (anti-spoofing)", name);
                        break; // Fall through to fallback
                    }

                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }
                Err(e) => {
                    warn!("Primary DNS {} failed: {}", client.address(), e);
                }
            }
        }

        // Try fallback servers
        for client in &self.fallback_clients {
            match client.query(name, hickory_type).await {
                Ok(response) => {
                    let ips = self.extract_ips(&response, record_type);
                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }
                Err(e) => {
                    warn!("Fallback DNS {} failed: {}", client.address(), e);
                }
            }
        }

        Err(DnsError::QueryFailed(format!(
            "All DNS servers failed for {}",
            name
        )))
    }

    /// Extract IP addresses from DNS response
    fn extract_ips(&self, response: &Message, record_type: RecordType) -> Vec<IpAddr> {
        let mut ips = Vec::new();

        for answer in response.answers() {
            match answer.data() {
                RData::A(a) => {
                    if record_type == RecordType::A {
                        ips.push(IpAddr::V4(a.0));
                    }
                }
                RData::AAAA(aaaa) => {
                    if record_type == RecordType::AAAA {
                        ips.push(IpAddr::V6(aaaa.0));
                    }
                }
                _ => {}
            }
        }

        // Sort: prefer IPv4 if configured
        if self.config.prefer_ipv4 {
            ips.sort_by_key(|ip| match ip {
                IpAddr::V4(_) => 0,
                IpAddr::V6(_) => 1,
            });
        }

        ips
    }

    /// Check if fallback DNS should be used (anti-spoofing)
    fn should_use_fallback(&self, name: &str, ips: &[IpAddr]) -> bool {
        let filter = &self.config.fallback_filter;

        // Check domain filter
        for pattern in &filter.domain {
            if let Some(suffix) = pattern.strip_prefix('+') {
                if name.ends_with(suffix) || name == &suffix[1..] {
                    return true;
                }
            } else if name == pattern {
                return true;
            }
        }

        // Check for bogon IPs using the bogon detection module
        if contains_bogon(ips) {
            debug!("Bogon IP detected in response for {}: {:?}", name, ips);
            return true;
        }

        // Check IP CIDR filter (additional custom ranges)
        for ip in ips {
            for cidr in &filter.ipcidr {
                if let Ok(network) = cidr.parse::<ipnet::IpNet>() {
                    if network.contains(ip) {
                        debug!("IP {} matches fallback CIDR filter {}", ip, cidr);
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Lookup domain from Fake-IP
    pub fn lookup_fake_ip(&self, ip: std::net::Ipv4Addr) -> Option<String> {
        self.fake_ip.as_ref().and_then(|pool| pool.lookup(ip))
    }

    /// Check if IP is a Fake-IP
    pub fn is_fake_ip(&self, ip: std::net::Ipv4Addr) -> bool {
        self.fake_ip
            .as_ref()
            .map(|pool| pool.is_fake_ip(ip))
            .unwrap_or(false)
    }

    /// Get cache reference
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    /// Get Fake-IP pool reference
    pub fn fake_ip_pool(&self) -> Option<&Arc<FakeIpPool>> {
        self.fake_ip.as_ref()
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) {
        self.cache.cleanup();
        if let Some(ref fake_ip) = self.fake_ip {
            fake_ip.cleanup_expired();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_resolver_basic() {
        let config = DnsConfig {
            nameservers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };

        let resolver = DnsResolver::new(config).unwrap();
        let result = resolver.resolve("google.com", RecordType::A).await;

        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }
}
