use crate::config::{Config, InboundType};
use crate::error::{Error, Result};
use crate::outbound::OutboundManager;
use crate::routing::Router;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

mod http;
mod mixed;
mod socks5;

use http::HttpInbound;
use mixed::MixedInbound;
use socks5::Socks5Inbound;

fn parse_listen_addr(listen: &str, port: u16) -> Result<SocketAddr> {
    let listen = listen.trim();
    let host = listen
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(listen);
    let ip = host.parse::<IpAddr>().map_err(|error| {
        Error::config_with_source(format!("Invalid inbound listen address '{listen}'"), error)
    })?;
    Ok(SocketAddr::new(ip, port))
}

fn bind_tcp_listener(listen: &str, port: u16, name: &str) -> Result<(TcpListener, SocketAddr)> {
    let addr = parse_listen_addr(listen, port)?;
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .map_err(|error| Error::network(format!("Failed to create {name} socket: {error}")))?;

    socket
        .set_reuse_address(true)
        .map_err(|error| Error::network(format!("Failed to set SO_REUSEADDR: {error}")))?;

    // A wildcard IPv6 listener must also accept the IPv4 loopback traffic used
    // by system-proxy and TUN clients. Explicitly request a dual-stack socket.
    if addr.ip().is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false).map_err(|error| {
            Error::network(format!(
                "Failed to enable dual-stack {name} listener: {error}"
            ))
        })?;
    }

    socket
        .set_nonblocking(true)
        .map_err(|error| Error::network(format!("Failed to set non-blocking: {error}")))?;
    socket.bind(&addr.into()).map_err(|error| {
        Error::network(format!("Failed to bind {name} listener to {addr}: {error}"))
    })?;
    socket
        .listen(1024)
        .map_err(|error| Error::network(format!("Failed to listen on {addr}: {error}")))?;

    let listener = TcpListener::from_std(socket.into())
        .map_err(|error| Error::network(format!("Failed to create {name} TcpListener: {error}")))?;
    Ok((listener, addr))
}

/// Inbound connection manager
pub struct InboundManager {
    _config: Arc<RwLock<Config>>,
    _router: Arc<Router>,
    listeners: Vec<Box<dyn InboundListener>>,
}

#[async_trait::async_trait]
pub trait InboundListener: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn tag(&self) -> &str;
}

impl InboundManager {
    pub async fn new(
        config: Arc<RwLock<Config>>,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Self> {
        let mut listeners: Vec<Box<dyn InboundListener>> = Vec::new();

        {
            let config_read = config.read().await;
            for inbound_config in &config_read.inbounds {
                let listener: Box<dyn InboundListener> = match inbound_config.inbound_type {
                    InboundType::Http => Box::new(HttpInbound::new(
                        inbound_config.clone(),
                        Arc::clone(&router),
                        Arc::clone(&outbound_manager),
                    )),
                    InboundType::Socks5 => Box::new(Socks5Inbound::new(
                        inbound_config.clone(),
                        Arc::clone(&router),
                        Arc::clone(&outbound_manager),
                    )),
                    InboundType::Mixed => {
                        // Mixed supports both HTTP and SOCKS5 with auto-detection
                        Box::new(MixedInbound::new(
                            inbound_config.clone(),
                            Arc::clone(&router),
                            Arc::clone(&outbound_manager),
                        ))
                    }
                    _ => {
                        tracing::warn!(
                            "Unsupported inbound type: {:?}",
                            inbound_config.inbound_type
                        );
                        continue;
                    }
                };
                listeners.push(listener);
            }
        } // config_read is dropped here

        Ok(Self {
            _config: config,
            _router: router,
            listeners,
        })
    }

    pub async fn start(&self) -> Result<()> {
        for listener in &self.listeners {
            listener.start().await?;
        }
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        for listener in &self.listeners {
            listener.stop().await?;
        }
        Ok(())
    }

    pub async fn reload(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_listen_addr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn parses_ipv4_listen_address() {
        assert_eq!(
            parse_listen_addr("127.0.0.1", 7890).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890)
        );
    }

    #[test]
    fn parses_bracketed_and_unbracketed_ipv6_listen_addresses() {
        let expected = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 7890);
        assert_eq!(parse_listen_addr("::1", 7890).unwrap(), expected);
        assert_eq!(parse_listen_addr("[::1]", 7890).unwrap(), expected);
    }

    #[test]
    fn rejects_non_ip_listen_address() {
        assert!(parse_listen_addr("localhost", 7890).is_err());
    }
}
