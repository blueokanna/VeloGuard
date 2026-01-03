//! Android TUN VPN implementation with socket protection
//!
//! This module provides socket protection for Android VPN to prevent
//! proxy connections from being routed back through TUN.

use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::collections::HashMap;
use tokio::sync::RwLock;
use parking_lot::RwLock as SyncRwLock;
use tracing::{debug, info, warn};

/// Global socket protect callback
/// Use RwLock to allow resetting on VPN restart
static PROTECT_CALLBACK: SyncRwLock<Option<Box<dyn Fn(RawFd) -> bool + Send + Sync>>> = SyncRwLock::new(None);

/// Set the socket protect callback
/// Called from JNI to register VpnService.protect()
pub fn set_protect_callback<F>(callback: F)
where
    F: Fn(RawFd) -> bool + Send + Sync + 'static,
{
    let mut guard = PROTECT_CALLBACK.write();
    *guard = Some(Box::new(callback));
    info!("Socket protect callback registered");
}

/// Clear the socket protect callback
pub fn clear_protect_callback() {
    let mut guard = PROTECT_CALLBACK.write();
    *guard = None;
    info!("Socket protect callback cleared");
}

/// Protect a socket from being routed through VPN
/// Returns true if protection was successful
pub fn protect_socket(fd: RawFd) -> bool {
    let guard = PROTECT_CALLBACK.read();
    if let Some(ref callback) = *guard {
        let result = callback(fd);
        if result {
            debug!("Socket fd={} protected successfully", fd);
        } else {
            warn!("Failed to protect socket fd={}", fd);
        }
        result
    } else {
        warn!("No protect callback set, socket fd={} not protected", fd);
        false
    }
}

/// Check if protect callback is set
pub fn has_protect_callback() -> bool {
    PROTECT_CALLBACK.read().is_some()
}

/// DNS Fake-IP pool for domain resolution
pub struct FakeIpPool {
    /// Domain to fake IP mapping
    domain_to_ip: RwLock<HashMap<String, Ipv4Addr>>,
    /// Fake IP to domain mapping
    ip_to_domain: RwLock<HashMap<Ipv4Addr, String>>,
    /// Next IP offset
    next_offset: AtomicU32,
    /// Pool start address (198.18.0.0)
    start_ip: u32,
    /// Pool size
    pool_size: u32,
}

impl FakeIpPool {
    pub fn new() -> Self {
        Self {
            domain_to_ip: RwLock::new(HashMap::new()),
            ip_to_domain: RwLock::new(HashMap::new()),
            next_offset: AtomicU32::new(1),
            start_ip: u32::from(Ipv4Addr::new(198, 18, 0, 0)),
            pool_size: 65536,
        }
    }

    /// Allocate a fake IP for a domain
    pub async fn allocate(&self, domain: &str) -> Ipv4Addr {
        let domain = domain.to_lowercase();
        
        // Check if already allocated
        if let Some(ip) = self.domain_to_ip.read().await.get(&domain) {
            return *ip;
        }

        // Allocate new IP
        let offset = self.next_offset.fetch_add(1, Ordering::Relaxed) % self.pool_size;
        let ip = Ipv4Addr::from(self.start_ip + offset);

        // Store mappings
        self.domain_to_ip.write().await.insert(domain.clone(), ip);
        self.ip_to_domain.write().await.insert(ip, domain);

        debug!("Allocated fake IP {} for domain", ip);
        ip
    }

    /// Lookup domain by fake IP
    pub async fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.ip_to_domain.read().await.get(&ip).cloned()
    }

    /// Check if IP is in fake IP range
    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        let val = u32::from(ip);
        val >= self.start_ip && val < self.start_ip + self.pool_size
    }
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Placeholder for AndroidTunProcessor - actual implementation uses SolidStack
pub struct AndroidTunProcessor;

impl AndroidTunProcessor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AndroidTunProcessor {
    fn default() -> Self {
        Self::new()
    }
}
