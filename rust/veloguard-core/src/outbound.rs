use crate::config::{Config, OutboundConfig, OutboundType};
use crate::error::{Error, Result};
use parking_lot::RwLock as ParkingRwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
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
mod vless;
mod vmess;
mod wireguard;

pub use direct::relay_bidirectional_with_connection;
pub use direct::DirectOutbound;
pub use http::HttpOutbound;
pub use hysteria2::Hysteria2Outbound;
pub use reject::RejectOutbound;
pub use selector::SelectorOutbound;
pub use shadowsocks::ShadowsocksOutbound;
pub use socks5::Socks5Outbound;
pub use trojan::TrojanOutbound;
pub use tuic::TuicOutbound;
pub use vless::VlessOutbound;
pub use vmess::VmessOutbound;
pub use wireguard::WireguardOutbound;

static GLOBAL_SELECTOR_SELECTIONS: OnceLock<ParkingRwLock<HashMap<String, String>>> =
    OnceLock::new();

pub fn get_global_selector_selections() -> &'static ParkingRwLock<HashMap<String, String>> {
    GLOBAL_SELECTOR_SELECTIONS.get_or_init(|| ParkingRwLock::new(HashMap::new()))
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Domain(String, u16),
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

impl From<TargetAddr> for veloguard_protocol::Address {
    fn from(target: TargetAddr) -> Self {
        match target {
            TargetAddr::Domain(domain, port) => veloguard_protocol::Address::Domain(domain, port),
            TargetAddr::Ip(addr) => veloguard_protocol::Address::from_socket_addr(addr),
        }
    }
}

impl From<&TargetAddr> for veloguard_protocol::Address {
    fn from(target: &TargetAddr) -> Self {
        match target {
            TargetAddr::Domain(domain, port) => {
                veloguard_protocol::Address::Domain(domain.clone(), *port)
            }
            TargetAddr::Ip(addr) => veloguard_protocol::Address::from_socket_addr(*addr),
        }
    }
}

impl From<veloguard_protocol::Address> for TargetAddr {
    fn from(addr: veloguard_protocol::Address) -> Self {
        match addr {
            veloguard_protocol::Address::Domain(domain, port) => TargetAddr::Domain(domain, port),
            veloguard_protocol::Address::Ipv4(ip, port) => TargetAddr::Ip(
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)),
            ),
            veloguard_protocol::Address::Ipv6(ip, port) => TargetAddr::Ip(
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)),
            ),
        }
    }
}

pub type ProxyRegistry = Arc<RwLock<HashMap<String, Arc<dyn OutboundProxy>>>>;

pub struct OutboundManager {
    config: Arc<RwLock<Config>>,
    proxies: ProxyRegistry,
    proxy_list: Vec<Arc<dyn OutboundProxy>>,
}

#[async_trait::async_trait]
pub trait OutboundProxy: Send + Sync {
    async fn connect(&self) -> Result<()>;

    async fn disconnect(&self) -> Result<()>;

    fn tag(&self) -> &str;

    fn server_addr(&self) -> Option<(String, u16)> {
        None
    }

    fn supports_udp(&self) -> bool {
        false
    }

    async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: TargetAddr) -> Result<()>;

    async fn relay_tcp_with_connection(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        let _ = connection;
        self.relay_tcp(inbound, target).await
    }

    async fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let _ = (target, data);
        Err(Error::protocol(format!(
            "UDP relay not supported by outbound '{}'",
            self.tag()
        )))
    }

    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration>;
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

impl OutboundManager {
    pub async fn new(config: Arc<RwLock<Config>>) -> Result<Self> {
        let proxies: ProxyRegistry = Arc::new(RwLock::new(HashMap::new()));
        let mut proxy_list: Vec<Arc<dyn OutboundProxy>> = Vec::new();
        let mut proxy_group_configs: Vec<OutboundConfig> = Vec::new();

        {
            let config_read = config.read().await;
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
                    OutboundType::Vless => {
                        Some(Arc::new(VlessOutbound::new(outbound_config.clone())?))
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
                        tracing::warn!("QUIC outbound not yet implemented, using direct");
                        Some(Arc::new(DirectOutbound::new(outbound_config.clone())))
                    }
                    OutboundType::Selector
                    | OutboundType::Urltest
                    | OutboundType::Fallback
                    | OutboundType::Loadbalance
                    | OutboundType::Relay => {
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
                OutboundType::Selector
                | OutboundType::Urltest
                | OutboundType::Fallback
                | OutboundType::Loadbalance
                | OutboundType::Relay => Arc::new(SelectorOutbound::new(
                    group_config.clone(),
                    proxies.clone(),
                )?),
                _ => unreachable!(),
            };

            let tag = proxy.tag().to_string();
            proxy_list.push(proxy.clone());
            proxies.write().await.insert(tag, proxy);
        }

        Ok(Self {
            config,
            proxies,
            proxy_list,
        })
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
        Ok(())
    }

    /// Get a proxy by tag (case-insensitive)
    pub fn get_proxy(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        // Use blocking read since this is called from sync context
        // In production, consider using try_read or making this async
        if let Ok(proxies) = self.proxies.try_read() {
            // First try exact match
            if let Some(proxy) = proxies.get(tag) {
                return Some(proxy.clone());
            }
            // Then try case-insensitive match
            let tag_lower = tag.to_lowercase();
            for (key, proxy) in proxies.iter() {
                if key.to_lowercase() == tag_lower {
                    return Some(proxy.clone());
                }
            }
            None
        } else {
            None
        }
    }

    /// Get a proxy by tag (async version, case-insensitive)
    pub async fn get_proxy_async(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        let proxies = self.proxies.read().await;
        // First try exact match
        if let Some(proxy) = proxies.get(tag) {
            return Some(proxy.clone());
        }
        // Then try case-insensitive match
        let tag_lower = tag.to_lowercase();
        for (key, proxy) in proxies.iter() {
            if key.to_lowercase() == tag_lower {
                return Some(proxy.clone());
            }
        }
        None
    }

    /// Get all proxy tags
    pub fn get_all_tags(&self) -> Vec<String> {
        self.proxy_list
            .iter()
            .map(|p| p.tag().to_string())
            .collect()
    }

    /// Get config
    pub fn config(&self) -> Arc<RwLock<Config>> {
        self.config.clone()
    }

    /// Get proxy registry (for proxy groups)
    pub fn registry(&self) -> ProxyRegistry {
        self.proxies.clone()
    }

    /// Set the selected proxy in a selector group
    pub async fn set_selector_proxy(&self, group_tag: &str, proxy_tag: &str) -> Result<()> {
        let proxies = self.proxies.read().await;

        if proxies.get(group_tag).is_some() {
            // Use the shared global selections map
            let selections = get_global_selector_selections();
            selections
                .write()
                .insert(group_tag.to_string(), proxy_tag.to_string());

            tracing::info!("Selector '{}' selection set to '{}'", group_tag, proxy_tag);
            Ok(())
        } else {
            Err(Error::config(format!(
                "Proxy group '{}' not found",
                group_tag
            )))
        }
    }

    /// Get the selected proxy in a selector group
    pub fn get_selector_proxy(&self, group_tag: &str) -> Option<String> {
        let selections = get_global_selector_selections();
        selections.read().get(group_tag).cloned()
    }
}
