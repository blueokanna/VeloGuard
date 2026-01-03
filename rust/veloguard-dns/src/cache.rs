//! DNS cache with TTL awareness

use crate::RecordType;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// DNS cache entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Resolved IP addresses
    pub addresses: Vec<IpAddr>,
    /// Original TTL from DNS response
    pub ttl: u32,
    /// Time when this entry was cached
    pub cached_at: Instant,
    /// Record type
    pub record_type: RecordType,
    /// CNAME chain (if any)
    pub cnames: Vec<String>,
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(addresses: Vec<IpAddr>, ttl: u32, record_type: RecordType) -> Self {
        Self {
            addresses,
            ttl,
            cached_at: Instant::now(),
            record_type,
            cnames: Vec::new(),
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > Duration::from_secs(self.ttl as u64)
    }

    /// Get remaining TTL in seconds
    pub fn remaining_ttl(&self) -> u32 {
        let elapsed = self.cached_at.elapsed().as_secs() as u32;
        self.ttl.saturating_sub(elapsed)
    }

    /// Check if this entry is stale (expired but still usable as fallback)
    pub fn is_stale(&self, stale_ttl: Duration) -> bool {
        self.cached_at.elapsed() > Duration::from_secs(self.ttl as u64) + stale_ttl
    }
}

/// DNS cache key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    /// Domain name (lowercase)
    pub name: String,
    /// Record type
    pub record_type: RecordType,
}

impl CacheKey {
    pub fn new(name: &str, record_type: RecordType) -> Self {
        Self {
            name: name.to_lowercase(),
            record_type,
        }
    }
}

/// DNS cache with LRU eviction
pub struct DnsCache {
    /// Cache entries
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    /// Maximum cache size
    max_size: usize,
    /// Minimum TTL (floor)
    min_ttl: u32,
    /// Maximum TTL (ceiling)
    max_ttl: u32,
    /// Stale TTL (how long to keep expired entries as fallback)
    stale_ttl: Duration,
    /// Cache statistics
    stats: Arc<CacheStats>,
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: std::sync::atomic::AtomicU64,
    pub misses: std::sync::atomic::AtomicU64,
    pub stale_hits: std::sync::atomic::AtomicU64,
    pub evictions: std::sync::atomic::AtomicU64,
}

impl CacheStats {
    pub fn hit(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn miss(&self) {
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn stale_hit(&self) {
        self.stale_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn eviction(&self) {
        self.evictions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

impl DnsCache {
    /// Create a new DNS cache
    pub fn new(max_size: usize, min_ttl: u32, max_ttl: u32) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(max_size)),
            max_size,
            min_ttl,
            max_ttl,
            stale_ttl: Duration::from_secs(3600), // 1 hour stale TTL
            stats: Arc::new(CacheStats::default()),
        }
    }

    /// Get a cache entry
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<CacheEntry> {
        let key = CacheKey::new(name, record_type);
        let entries = self.entries.read();

        if let Some(entry) = entries.get(&key) {
            if !entry.is_expired() {
                self.stats.hit();
                trace!("DNS cache hit: {} {:?}", name, record_type);
                return Some(entry.clone());
            } else if !entry.is_stale(self.stale_ttl) {
                // Return stale entry as fallback
                self.stats.stale_hit();
                debug!("DNS cache stale hit: {} {:?}", name, record_type);
                return Some(entry.clone());
            }
        }

        self.stats.miss();
        trace!("DNS cache miss: {} {:?}", name, record_type);
        None
    }

    /// Insert a cache entry
    pub fn insert(&self, name: &str, record_type: RecordType, addresses: Vec<IpAddr>, ttl: u32) {
        let key = CacheKey::new(name, record_type);

        // Apply TTL bounds
        let bounded_ttl = ttl.max(self.min_ttl).min(self.max_ttl);

        let entry = CacheEntry::new(addresses, bounded_ttl, record_type);

        let mut entries = self.entries.write();

        // Evict if at capacity
        if entries.len() >= self.max_size && !entries.contains_key(&key) {
            self.evict_one(&mut entries);
        }

        entries.insert(key, entry);
        trace!("DNS cache insert: {} {:?} TTL={}", name, record_type, bounded_ttl);
    }

    /// Insert a cache entry with CNAME chain
    pub fn insert_with_cnames(
        &self,
        name: &str,
        record_type: RecordType,
        addresses: Vec<IpAddr>,
        ttl: u32,
        cnames: Vec<String>,
    ) {
        let key = CacheKey::new(name, record_type);
        let bounded_ttl = ttl.max(self.min_ttl).min(self.max_ttl);

        let mut entry = CacheEntry::new(addresses, bounded_ttl, record_type);
        entry.cnames = cnames;

        let mut entries = self.entries.write();

        if entries.len() >= self.max_size && !entries.contains_key(&key) {
            self.evict_one(&mut entries);
        }

        entries.insert(key, entry);
    }

    /// Remove a cache entry
    pub fn remove(&self, name: &str, record_type: RecordType) {
        let key = CacheKey::new(name, record_type);
        self.entries.write().remove(&key);
    }

    /// Clear all cache entries
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Get cache statistics
    pub fn stats(&self) -> Arc<CacheStats> {
        self.stats.clone()
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) {
        let mut entries = self.entries.write();
        let before = entries.len();

        entries.retain(|_, entry| !entry.is_stale(self.stale_ttl));

        let removed = before - entries.len();
        if removed > 0 {
            debug!("DNS cache cleanup: removed {} stale entries", removed);
        }
    }

    /// Evict one entry (LRU-like: evict oldest or expired)
    fn evict_one(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        // First try to evict an expired entry
        let expired_key = entries
            .iter()
            .find(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone());

        if let Some(key) = expired_key {
            entries.remove(&key);
            self.stats.eviction();
            return;
        }

        // Otherwise evict the entry with lowest remaining TTL
        let oldest_key = entries
            .iter()
            .min_by_key(|(_, entry)| entry.remaining_ttl())
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest_key {
            entries.remove(&key);
            self.stats.eviction();
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(10000, 60, 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cache_basic() {
        let cache = DnsCache::new(100, 60, 3600);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("example.com", RecordType::A, vec![ip], 300);

        let entry = cache.get("example.com", RecordType::A).unwrap();
        assert_eq!(entry.addresses, vec![ip]);
        assert!(entry.remaining_ttl() <= 300);
    }

    #[test]
    fn test_cache_case_insensitive() {
        let cache = DnsCache::new(100, 60, 3600);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("Example.COM", RecordType::A, vec![ip], 300);

        // Should find with different case
        assert!(cache.get("example.com", RecordType::A).is_some());
        assert!(cache.get("EXAMPLE.COM", RecordType::A).is_some());
    }

    #[test]
    fn test_cache_ttl_bounds() {
        let cache = DnsCache::new(100, 60, 3600);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // TTL below minimum should be raised
        cache.insert("low.com", RecordType::A, vec![ip], 10);
        let entry = cache.get("low.com", RecordType::A).unwrap();
        assert!(entry.ttl >= 60);

        // TTL above maximum should be lowered
        cache.insert("high.com", RecordType::A, vec![ip], 100000);
        let entry = cache.get("high.com", RecordType::A).unwrap();
        assert!(entry.ttl <= 3600);
    }
}
