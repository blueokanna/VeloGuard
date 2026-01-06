//! Fake-IP pool for transparent proxying
//!
//! Fake-IP mode assigns virtual IP addresses to domain names,
//! allowing the proxy to intercept connections by IP and route
//! them based on the original domain name.

use crate::error::{DnsError, Result};
use dashmap::DashMap;
use ipnet::Ipv4Net;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace};

/// Fake-IP pool entry
#[derive(Debug, Clone)]
pub struct FakeIpEntry {
    /// The domain name
    pub domain: String,
    /// Time when this entry was created
    pub created_at: Instant,
    /// Last access time
    pub last_access: Instant,
}

impl FakeIpEntry {
    pub fn new(domain: String) -> Self {
        let now = Instant::now();
        Self {
            domain,
            created_at: now,
            last_access: now,
        }
    }
}

/// Fake-IP pool for domain-to-IP mapping
pub struct FakeIpPool {
    /// IP range for fake IPs
    range: Ipv4Net,
    /// Domain to IP mapping
    domain_to_ip: DashMap<String, Ipv4Addr>,
    /// IP to domain mapping (reverse lookup)
    ip_to_domain: DashMap<Ipv4Addr, FakeIpEntry>,
    /// Available IPs (recycled)
    available: RwLock<VecDeque<Ipv4Addr>>,
    /// Next IP to allocate
    next_ip: RwLock<u32>,
    /// Entry TTL
    ttl: Duration,
    /// Domains to exclude from Fake-IP
    filter: Vec<String>,
}

impl FakeIpPool {
    /// Create a new Fake-IP pool
    pub fn new(range: &str, filter: Vec<String>) -> Result<Self> {
        let range: Ipv4Net = range
            .parse()
            .map_err(|e| DnsError::Config(format!("Invalid Fake-IP range: {}", e)))?;

        let start_ip = u32::from(range.network()) + 2; // Skip network and gateway

        info!(
            "Fake-IP pool initialized: range={}, size={}",
            range,
            range.hosts().count()
        );

        Ok(Self {
            range,
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
            available: RwLock::new(VecDeque::new()),
            next_ip: RwLock::new(start_ip),
            ttl: Duration::from_secs(3600), // 1 hour default TTL
            filter,
        })
    }

    /// Check if a domain should be excluded from Fake-IP
    pub fn should_filter(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        for pattern in &self.filter {
            if let Some(rest) = pattern.strip_prefix("*.") {
                let suffix = &pattern[1..]; // ".example.com"
                if domain_lower.ends_with(suffix) || domain_lower == rest {
                    return true;
                }
            } else if let Some(suffix) = pattern.strip_prefix('+') {
                // ".example.com"
                if domain_lower.ends_with(suffix) || domain_lower == suffix.strip_prefix('.').unwrap_or(suffix) {
                    return true;
                }
            } else if domain_lower == pattern.to_lowercase() {
                return true;
            }
        }
        false
    }

    /// Allocate a Fake-IP for a domain
    pub fn allocate(&self, domain: &str) -> Result<Ipv4Addr> {
        let domain_lower = domain.to_lowercase();

        // Check if already allocated
        if let Some(ip) = self.domain_to_ip.get(&domain_lower) {
            // Update last access time
            if let Some(mut entry) = self.ip_to_domain.get_mut(&*ip) {
                entry.last_access = Instant::now();
            }
            trace!("Fake-IP cache hit: {} -> {}", domain, *ip);
            return Ok(*ip);
        }

        // Try to get a recycled IP first
        let ip = {
            let mut available = self.available.write();
            available.pop_front()
        };

        let ip = if let Some(ip) = ip {
            ip
        } else {
            // Allocate new IP
            let mut next = self.next_ip.write();
            let ip = Ipv4Addr::from(*next);

            // Check if we've exhausted the range
            let broadcast = u32::from(self.range.broadcast());
            if *next >= broadcast {
                // Try to recycle expired entries
                self.cleanup_expired();

                // Try again from available pool
                let mut available = self.available.write();
                if let Some(recycled) = available.pop_front() {
                    recycled
                } else {
                    return Err(DnsError::FakeIpExhausted);
                }
            } else {
                *next += 1;
                ip
            }
        };

        // Store mappings
        self.domain_to_ip.insert(domain_lower.clone(), ip);
        self.ip_to_domain.insert(ip, FakeIpEntry::new(domain_lower));

        debug!("Fake-IP allocated: {} -> {}", domain, ip);
        Ok(ip)
    }

    /// Lookup domain by Fake-IP
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(&ip).map(|entry| {
            // Update last access time
            // Note: This creates a mutable reference, so we need to be careful
            entry.domain.clone()
        })
    }

    /// Check if an IP is in the Fake-IP range
    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        self.range.contains(&ip)
    }

    /// Get the Fake-IP range
    pub fn range(&self) -> &Ipv4Net {
        &self.range
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.domain_to_ip.len()
    }

    /// Clear all mappings
    pub fn clear(&self) {
        self.domain_to_ip.clear();
        self.ip_to_domain.clear();
        self.available.write().clear();
        info!("Fake-IP pool cleared");
    }

    /// Cleanup expired entries
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut recycled = Vec::new();

        // Find expired entries
        self.ip_to_domain.retain(|ip, entry| {
            if now.duration_since(entry.last_access) > self.ttl {
                recycled.push(*ip);
                false
            } else {
                true
            }
        });

        // Remove from domain_to_ip
        for ip in &recycled {
            self.domain_to_ip.retain(|_, v| v != ip);
        }

        // Add to available pool
        if !recycled.is_empty() {
            let mut available = self.available.write();
            for ip in recycled {
                available.push_back(ip);
            }
            debug!("Fake-IP cleanup: recycled {} IPs", available.len());
        }
    }

    /// Set TTL for entries
    pub fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = ttl;
    }
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new("198.18.0.0/16", vec![
            "*.lan".to_string(),
            "*.local".to_string(),
            "localhost".to_string(),
        ])
        .expect("Default Fake-IP range should be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_allocation() {
        let pool = FakeIpPool::new("198.18.0.0/24", vec![]).unwrap();

        let ip1 = pool.allocate("example.com").unwrap();
        let ip2 = pool.allocate("google.com").unwrap();

        assert_ne!(ip1, ip2);
        assert!(pool.is_fake_ip(ip1));
        assert!(pool.is_fake_ip(ip2));

        // Same domain should return same IP
        let ip1_again = pool.allocate("example.com").unwrap();
        assert_eq!(ip1, ip1_again);
    }

    #[test]
    fn test_fake_ip_lookup() {
        let pool = FakeIpPool::new("198.18.0.0/24", vec![]).unwrap();

        let ip = pool.allocate("example.com").unwrap();
        let domain = pool.lookup(ip).unwrap();

        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_fake_ip_filter() {
        let pool = FakeIpPool::new(
            "198.18.0.0/24",
            vec!["*.local".to_string(), "localhost".to_string()],
        )
        .unwrap();

        assert!(pool.should_filter("test.local"));
        assert!(pool.should_filter("localhost"));
        assert!(!pool.should_filter("example.com"));
    }
}
