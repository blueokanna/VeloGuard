//! DNS resolver with support for multiple upstream types

use crate::dns::doh::DohResolver;
use crate::dns::dot::DotResolver;
use crate::dns::error::{DnsError, DnsResult};
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver as HickoryResolver;
use hickory_proto::xfer::Protocol;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// DNS upstream server type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DnsUpstreamType {
    /// Plain UDP DNS
    Udp,
    /// Plain TCP DNS
    Tcp,
    /// DNS over HTTPS
    Doh,
    /// DNS over TLS
    Dot,
}

/// DNS upstream server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsUpstream {
    /// Server address (IP or hostname)
    pub server: String,
    /// Server port (default: 53 for UDP/TCP, 443 for DoH, 853 for DoT)
    pub port: Option<u16>,
    /// Upstream type
    #[serde(rename = "type")]
    pub upstream_type: DnsUpstreamType,
    /// DoH URL (required for DoH type)
    pub url: Option<String>,
    /// TLS server name (for DoT)
    pub tls_name: Option<String>,
}

impl DnsUpstream {
    /// Get the effective port for this upstream
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(match self.upstream_type {
            DnsUpstreamType::Udp | DnsUpstreamType::Tcp => 53,
            DnsUpstreamType::Doh => 443,
            DnsUpstreamType::Dot => 853,
        })
    }
}

/// DNS resolver configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsConfig {
    /// Enable DNS resolution
    #[serde(default = "default_true")]
    pub enable: bool,
    /// Listen address for DNS server
    pub listen: Option<String>,
    /// Upstream DNS servers
    #[serde(default)]
    pub nameservers: Vec<DnsUpstream>,
    /// Fallback DNS servers (used when primary fails)
    #[serde(default)]
    pub fallback: Vec<DnsUpstream>,
    /// Enhanced mode (fake-ip or redir-host)
    pub enhanced_mode: Option<String>,
    /// Fake IP range
    pub fake_ip_range: Option<String>,
    /// Fake IP filter (domains that should not use fake IP)
    #[serde(default)]
    pub fake_ip_filter: Vec<String>,
    /// Default nameservers for bootstrap
    #[serde(default)]
    pub default_nameserver: Vec<String>,
    /// Nameserver policy (domain -> nameserver mapping)
    #[serde(default)]
    pub nameserver_policy: std::collections::HashMap<String, Vec<String>>,
}

fn default_true() -> bool {
    true
}

/// Unified DNS resolver supporting multiple upstream types
#[derive(Clone)]
pub struct Resolver {
    /// Standard DNS resolver (UDP/TCP)
    standard: Arc<HickoryResolver<TokioConnectionProvider>>,
    /// DoH resolver
    doh: Option<Arc<DohResolver>>,
    /// DoT resolver
    dot: Option<Arc<DotResolver>>,
    /// Configuration
    config: Arc<RwLock<DnsConfig>>,
}

impl Resolver {
    /// Create a new resolver with default configuration
    pub async fn new() -> DnsResult<Self> {
        let config = ResolverConfig::default();
        let opts = ResolverOpts::default();

        let resolver = HickoryResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();

        Ok(Self {
            standard: Arc::new(resolver),
            doh: None,
            dot: None,
            config: Arc::new(RwLock::new(DnsConfig::default())),
        })
    }

    /// Create a new resolver with custom configuration
    pub async fn with_config(dns_config: DnsConfig) -> DnsResult<Self> {
        // Build standard resolver config
        let mut resolver_config = ResolverConfig::new();
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;

        // Collect DoH and DoT servers
        let mut doh_urls = Vec::new();
        let mut dot_servers = Vec::new();

        for upstream in &dns_config.nameservers {
            match upstream.upstream_type {
                DnsUpstreamType::Udp => {
                    if let Ok(ip) = upstream.server.parse::<IpAddr>() {
                        let socket_addr = SocketAddr::new(ip, upstream.effective_port());
                        let ns_config = NameServerConfig::new(socket_addr, Protocol::Udp);
                        resolver_config.add_name_server(ns_config);
                    }
                }
                DnsUpstreamType::Tcp => {
                    if let Ok(ip) = upstream.server.parse::<IpAddr>() {
                        let socket_addr = SocketAddr::new(ip, upstream.effective_port());
                        let ns_config = NameServerConfig::new(socket_addr, Protocol::Tcp);
                        resolver_config.add_name_server(ns_config);
                    }
                }
                DnsUpstreamType::Doh => {
                    if let Some(url) = &upstream.url {
                        doh_urls.push(url.clone());
                    }
                }
                DnsUpstreamType::Dot => {
                    dot_servers.push((
                        upstream.server.clone(),
                        upstream.effective_port(),
                        upstream.tls_name.clone(),
                    ));
                }
            }
        }

        // If no standard servers configured, use defaults
        if resolver_config.name_servers().is_empty() {
            resolver_config = ResolverConfig::default();
        }

        let resolver = HickoryResolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();

        // Create DoH resolver if configured
        let doh = if !doh_urls.is_empty() {
            match DohResolver::new(&doh_urls) {
                Ok(r) => Some(Arc::new(r)),
                Err(e) => {
                    warn!("Failed to create DoH resolver: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Create DoT resolver if configured
        let dot = if !dot_servers.is_empty() {
            match DotResolver::new(&dot_servers) {
                Ok(r) => Some(Arc::new(r)),
                Err(e) => {
                    warn!("Failed to create DoT resolver: {}", e);
                    None
                }
            }
        } else {
            None
        };

        info!(
            "DNS resolver initialized: standard={}, doh={}, dot={}",
            true,
            doh.is_some(),
            dot.is_some()
        );

        Ok(Self {
            standard: Arc::new(resolver),
            doh,
            dot,
            config: Arc::new(RwLock::new(dns_config)),
        })
    }

    /// Resolve a domain name to IP addresses
    pub async fn resolve(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
        // Try DoH first if available
        if let Some(doh) = &self.doh {
            match doh.resolve(domain).await {
                Ok(ips) if !ips.is_empty() => {
                    debug!("DoH resolved {} to {:?}", domain, ips);
                    return Ok(ips);
                }
                Ok(_) => debug!("DoH returned empty result for {}", domain),
                Err(e) => debug!("DoH resolution failed for {}: {}", domain, e),
            }
        }

        // Try DoT if available
        if let Some(dot) = &self.dot {
            match dot.resolve(domain).await {
                Ok(ips) if !ips.is_empty() => {
                    debug!("DoT resolved {} to {:?}", domain, ips);
                    return Ok(ips);
                }
                Ok(_) => debug!("DoT returned empty result for {}", domain),
                Err(e) => debug!("DoT resolution failed for {}: {}", domain, e),
            }
        }

        // Fall back to standard resolver
        let response = self
            .standard
            .lookup_ip(domain)
            .await
            .map_err(|e| DnsError::ResolutionFailed(format!("DNS lookup failed for {}: {}", domain, e)))?;

        let ips: Vec<IpAddr> = response.iter().collect();
        debug!("Standard DNS resolved {} to {:?}", domain, ips);
        Ok(ips)
    }

    /// Resolve A records only
    pub async fn resolve_a(&self, domain: &str) -> DnsResult<Vec<std::net::Ipv4Addr>> {
        let response = self
            .standard
            .ipv4_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolutionFailed(format!("A lookup failed for {}: {}", domain, e)))?;

        let ips: Vec<std::net::Ipv4Addr> = response.into_iter().map(|r| r.0).collect();
        Ok(ips)
    }

    /// Resolve AAAA records only
    pub async fn resolve_aaaa(&self, domain: &str) -> DnsResult<Vec<std::net::Ipv6Addr>> {
        let response = self
            .standard
            .ipv6_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolutionFailed(format!("AAAA lookup failed for {}: {}", domain, e)))?;

        let ips: Vec<std::net::Ipv6Addr> = response.into_iter().map(|r| r.0).collect();
        Ok(ips)
    }

    /// Get the current DNS configuration
    pub async fn config(&self) -> DnsConfig {
        self.config.read().await.clone()
    }

    /// Check if DoH is enabled
    pub fn has_doh(&self) -> bool {
        self.doh.is_some()
    }

    /// Check if DoT is enabled
    pub fn has_dot(&self) -> bool {
        self.dot.is_some()
    }
}
