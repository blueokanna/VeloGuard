//! DNS cache implementation

use lru::LruCache;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// DNS cache implementation using LRU eviction
pub struct DnsCache {
    cache: Mutex<LruCache<String, Vec<IpAddr>>>,
}

impl DnsCache {
    /// Create a new DNS cache with the given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap()))),
        }
    }

    /// Get cached IPs for a domain
    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        self.cache.lock().unwrap().get(domain).cloned()
    }

    /// Put IPs into cache for a domain
    pub fn put(&self, domain: String, ips: Vec<IpAddr>) {
        self.cache.lock().unwrap().put(domain, ips);
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.lock().unwrap().is_empty()
    }
}
