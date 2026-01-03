//! DNS module for VeloGuard Network Stack
//!
//! This module provides DNS resolution, caching, and Fake-IP support
//! for transparent proxying across all platforms.

pub mod cache;
pub mod doh;
pub mod dot;
pub mod error;
pub mod fake_ip;
pub mod resolver;
pub mod server;

pub use cache::*;
pub use doh::*;
pub use dot::*;
pub use error::*;
pub use fake_ip::*;
pub use resolver::*;
pub use server::*;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// DNS manager for VeloGuard
/// 
/// Provides unified DNS resolution with support for:
/// - Standard UDP/TCP DNS
/// - DNS over HTTPS (DoH)
/// - DNS over TLS (DoT)
/// - Fake-IP mode for transparent proxying
/// - DNS caching
pub struct DnsManager {
    resolver: Resolver,
    server: Option<DnsServer>,
    cache: Arc<DnsCache>,
    config: Arc<RwLock<DnsConfig>>,
}

impl DnsManager {
    /// Create a new DNS manager with default configuration
    pub async fn new() -> DnsResult<Self> {
        let resolver = Resolver::new().await?;
        let cache = Arc::new(DnsCache::new(1000));
        let config = Arc::new(RwLock::new(DnsConfig::default()));

        Ok(Self {
            resolver,
            server: None,
            cache,
            config,
        })
    }

    /// Create a new DNS manager with custom configuration
    pub async fn with_config(dns_config: DnsConfig) -> DnsResult<Self> {
        let resolver = Resolver::with_config(dns_config.clone()).await?;
        let cache = Arc::new(DnsCache::new(1000));
        let config = Arc::new(RwLock::new(dns_config));

        Ok(Self {
            resolver,
            server: None,
            cache,
            config,
        })
    }

    /// Resolve a domain name to IP addresses
    pub async fn resolve(&self, domain: &str) -> DnsResult<Vec<std::net::IpAddr>> {
        // Check cache first
        if let Some(ips) = self.cache.get(domain) {
            return Ok(ips);
        }

        // Resolve using resolver
        let ips = self.resolver.resolve(domain).await?;

        // Cache the result
        self.cache.put(domain.to_string(), ips.clone());

        Ok(ips)
    }

    /// Start DNS server
    pub async fn start_server(&mut self, listen_addr: &str) -> DnsResult<()> {
        let config = self.config.read().await;
        
        let server_config = DnsServerConfig {
            listen: listen_addr.parse()
                .map_err(|e| DnsError::ConfigError(format!("Invalid listen address: {}", e)))?,
            fake_ip_enabled: config.enhanced_mode.as_deref() == Some("fake-ip"),
            fake_ip_range: config.fake_ip_range.clone(),
            fake_ip_filter: config.fake_ip_filter.clone(),
            cache_size: 1000,
            cache_ttl: 600,
        };

        let server = DnsServer::with_config(server_config, self.resolver.clone()).await?;
        server.start().await?;
        self.server = Some(server);

        info!("DNS server started on {}", listen_addr);
        Ok(())
    }

    /// Stop DNS server
    pub async fn stop_server(&mut self) -> DnsResult<()> {
        if let Some(server) = self.server.take() {
            server.stop().await?;
            info!("DNS server stopped");
        }
        Ok(())
    }

    /// Get the resolver
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Check if DoH is enabled
    pub fn has_doh(&self) -> bool {
        self.resolver.has_doh()
    }

    /// Check if DoT is enabled
    pub fn has_dot(&self) -> bool {
        self.resolver.has_dot()
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.cache.len(), 1000)
    }

    /// Reset DNS manager state (clear cache, stop server if running)
    /// This should be called when VPN service restarts
    pub async fn reset(&mut self) -> DnsResult<()> {
        info!("Resetting DNS manager...");
        
        // Stop server if running
        if let Some(server) = self.server.take() {
            let _ = server.stop().await;
        }
        
        // Clear cache
        self.cache.clear();
        
        // Recreate resolver with current config
        let config = self.config.read().await.clone();
        self.resolver = Resolver::with_config(config).await?;
        
        info!("DNS manager reset complete");
        Ok(())
    }

    /// Clear DNS cache only
    pub fn clear_cache(&self) {
        self.cache.clear();
        info!("DNS cache cleared");
    }

    /// Check if DNS server is running
    pub fn is_server_running(&self) -> bool {
        self.server.is_some()
    }
}
