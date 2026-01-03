use crate::config::{Config, OutboundConfig, OutboundType};
use crate::error::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;

mod direct;
mod http;
mod hysteria2;
mod reject;
mod selector;
mod shadowsocks;
mod socks5;
mod trojan;
mod tuic;
mod vmess;
mod wireguard;

pub use direct::DirectOutbound;
pub use direct::relay_bidirectional_with_connection;
pub use http::HttpOutbound;
pub use hysteria2::Hysteria2Outbound;
pub use reject::RejectOutbound;
pub use selector::SelectorOutbound;
pub use shadowsocks::ShadowsocksOutbound;
pub use socks5::Socks5Outbound;
pub use trojan::TrojanOutbound;
pub use tuic::TuicOutbound;
pub use vmess::VmessOutbound;
pub use wireguard::WireguardOutbound;

/// Target address for outbound connections
#[derive(Debug, Clone)]
pub enum TargetAddr {
    /// Domain name with port
    Domain(String, u16),
    /// Socket address (IP:port)
    Ip(std::net::SocketAddr),
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddr::Domain(domain, port) => write!(f, "{}:{}", domain, port),
            TargetAddr::Ip(addr) => write!(f, "{}", addr),
        }
    }
}

impl TargetAddr {
    pub fn new_domain(domain: String, port: u16) -> Self {
        TargetAddr::Domain(domain, port)
    }
    
    pub fn new_ip(addr: std::net::SocketAddr) -> Self {
        TargetAddr::Ip(addr)
    }
    
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Domain(_, port) => *port,
            TargetAddr::Ip(addr) => addr.port(),
        }
    }
    
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Domain(domain, _) => domain.clone(),
            TargetAddr::Ip(addr) => addr.ip().to_string(),
        }
    }
}

/// Shared proxy registry for proxy groups to access other proxies
pub type ProxyRegistry = Arc<RwLock<HashMap<String, Arc<dyn OutboundProxy>>>>;

/// Outbound connection manager
pub struct OutboundManager {
    config: Arc<RwLock<Config>>,
    proxies: ProxyRegistry,
    proxy_list: Vec<Arc<dyn OutboundProxy>>,
}

#[async_trait::async_trait]
pub trait OutboundProxy: Send + Sync {
    /// Test the connection to the proxy server
    async fn connect(&self) -> Result<()>;
    
    /// Disconnect from the proxy server
    async fn disconnect(&self) -> Result<()>;
    
    /// Get the tag/name of this outbound
    fn tag(&self) -> &str;
    
    /// Get the server address and port (if applicable)
    fn server_addr(&self) -> Option<(String, u16)> {
        None
    }
    
    /// Connect to target through this outbound and relay data
    /// This is the main method for proxying traffic
    async fn relay_tcp(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
    ) -> Result<()>;
    
    /// Connect to target through this outbound and relay data with connection tracking
    /// Default implementation calls relay_tcp without connection tracking
    async fn relay_tcp_with_connection(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        // Default: ignore connection tracking and use regular relay
        let _ = connection;
        self.relay_tcp(inbound, target).await
    }
    
    /// Test HTTP latency through this outbound
    /// This sends an HTTP request through the proxy and measures the round-trip time
    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration>;
}

/// Trait alias for types that implement both AsyncRead and AsyncWrite
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

impl OutboundManager {
    pub async fn new(config: Arc<RwLock<Config>>) -> Result<Self> {
        let proxies: ProxyRegistry = Arc::new(RwLock::new(HashMap::new()));
        let mut proxy_list: Vec<Arc<dyn OutboundProxy>> = Vec::new();
        let mut proxy_group_configs: Vec<OutboundConfig> = Vec::new();

        {
            let config_read = config.read().await;
            
            // First pass: create all non-group proxies
            for outbound_config in &config_read.outbounds {
                let proxy: Option<Arc<dyn OutboundProxy>> = match outbound_config.outbound_type {
                    OutboundType::Direct => {
                        Some(Arc::new(DirectOutbound::new(outbound_config.clone())))
                    }
                    OutboundType::Reject => {
                        Some(Arc::new(RejectOutbound::new(outbound_config.clone())))
                    }
                    OutboundType::Socks5 => {
                        Some(Arc::new(Socks5Outbound::new(outbound_config.clone())?))
                    }
                    OutboundType::Http => {
                        Some(Arc::new(HttpOutbound::new(outbound_config.clone())?))
                    }
                    OutboundType::Shadowsocks => {
                        Some(Arc::new(ShadowsocksOutbound::new(outbound_config.clone())?))
                    }
                    OutboundType::Vmess => {
                        Some(Arc::new(VmessOutbound::new(outbound_config.clone())?))
                    }
                    OutboundType::Trojan => {
                        Some(Arc::new(TrojanOutbound::new(outbound_config.clone())?))
                    }
                    OutboundType::Wireguard => {
                        Some(Arc::new(WireguardOutbound::new(outbound_config.clone())?))
                    }
                    OutboundType::Tuic => {
                        Some(Arc::new(TuicOutbound::new(outbound_config.clone())?))
                    }
                    OutboundType::Hysteria2 => {
                        Some(Arc::new(Hysteria2Outbound::new(outbound_config.clone())?))
                    }
                    OutboundType::Quic => {
                        // TODO: Implement QUIC outbound proxy
                        tracing::warn!("QUIC outbound not yet implemented, using direct");
                        Some(Arc::new(DirectOutbound::new(outbound_config.clone())))
                    }
                    // Proxy groups - defer to second pass
                    OutboundType::Selector | OutboundType::Urltest | 
                    OutboundType::Fallback | OutboundType::Loadbalance | OutboundType::Relay => {
                        proxy_group_configs.push(outbound_config.clone());
                        None
                    }
                };
                
                if let Some(p) = proxy {
                    let tag = p.tag().to_string();
                    proxy_list.push(p.clone());
                    proxies.write().await.insert(tag, p);
                }
            }
        }
        
        // Second pass: create proxy groups with access to the registry
        for group_config in proxy_group_configs {
            let proxy: Arc<dyn OutboundProxy> = match group_config.outbound_type {
                OutboundType::Selector | OutboundType::Urltest | 
                OutboundType::Fallback | OutboundType::Loadbalance | OutboundType::Relay => {
                    Arc::new(SelectorOutbound::new(group_config.clone(), proxies.clone())?)
                }
                _ => unreachable!(),
            };
            
            let tag = proxy.tag().to_string();
            proxy_list.push(proxy.clone());
            proxies.write().await.insert(tag, proxy);
        }

        Ok(Self { config, proxies, proxy_list })
    }

    pub async fn start(&self) -> Result<()> {
        // Don't pre-connect outbounds on startup - this makes startup much faster
        // Connections will be established on-demand when traffic flows through
        tracing::info!(
            "OutboundManager started with {} proxies (lazy connection mode)",
            self.proxy_list.len()
        );
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        for proxy in &self.proxy_list {
            proxy.disconnect().await?;
        }
        Ok(())
    }

    pub async fn reload(&self) -> Result<()> {
        // TODO: Implement outbound reload logic
        Ok(())
    }

    /// Get a proxy by tag
    pub fn get_proxy(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        // Use blocking read since this is called from sync context
        // In production, consider using try_read or making this async
        if let Ok(proxies) = self.proxies.try_read() {
            proxies.get(tag).cloned()
        } else {
            None
        }
    }
    
    /// Get a proxy by tag (async version)
    pub async fn get_proxy_async(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        self.proxies.read().await.get(tag).cloned()
    }
    
    /// Get all proxy tags
    pub fn get_all_tags(&self) -> Vec<String> {
        self.proxy_list.iter().map(|p| p.tag().to_string()).collect()
    }
    
    /// Get config
    pub fn config(&self) -> Arc<RwLock<Config>> {
        self.config.clone()
    }
    
    /// Get proxy registry (for proxy groups)
    pub fn registry(&self) -> ProxyRegistry {
        self.proxies.clone()
    }
}
