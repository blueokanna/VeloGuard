use crate::config::InboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

pub struct DokodemoInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
    target_address: String,
    target_port: u16,
    network: String,
}

#[async_trait::async_trait]
impl InboundListener for DokodemoInbound {
    async fn start(&self) -> Result<()> {
        self.start_listener().await
    }
    async fn stop(&self) -> Result<()> {
        self.stop_listener().await
    }
    fn tag(&self) -> &str {
        &self.config.tag
    }
}

impl DokodemoInbound {
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        let target_address = config.options.get("address")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1")
            .to_string();
        let target_port = config.options.get("port")
            .and_then(|v| v.as_i64())
            .unwrap_or(80) as u16;
        let network = config.options.get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp")
            .to_string();
        Self {
            config,
            router,
            outbound_manager,
            cancel_token: CancellationToken::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            target_address,
            target_port,
            network,
        }
    }

    async fn start_listener(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        let addr: SocketAddr = format!("{}:{}", self.config.listen, self.config.port)
            .parse()
            .map_err(|e| Error::config(format!("Invalid listen address: {}", e)))?;
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);
        if self.network.contains("tcp") {
            self.start_tcp_listener(addr).await?;
        }
        if self.network.contains("udp") {
            self.start_udp_listener(addr).await?;
        }
        tracing::info!("Dokodemo-door inbound listening on {} (network: {})", addr, self.network);
        Ok(())
    }

    async fn start_tcp_listener(&self, addr: SocketAddr) -> Result<()> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ).map_err(|e| Error::network(format!("Failed to create socket: {}", e)))?;
        socket.set_reuse_address(true).ok();
        socket.set_nonblocking(true).ok();
        socket.bind(&addr.into())
            .map_err(|e| Error::network(format!("Failed to bind: {}", e)))?;
        socket.listen(1024)
            .map_err(|e| Error::network(format!("Failed to listen: {}", e)))?;
        let listener: TcpListener = TcpListener::from_std(socket.into())
            .map_err(|e| Error::network(format!("Failed to create listener: {}", e)))?;
        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let cancel_token = self.cancel_token.clone();
        let running = Arc::clone(&self.running);
        let target_address = self.target_address.clone();
        let target_port = self.target_port;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                let router = Arc::clone(&router);
                                let outbound_manager = Arc::clone(&outbound_manager);
                                let target_address = target_address.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_tcp_connection(
                                        stream, peer_addr, router, outbound_manager,
                                        target_address, target_port
                                    ).await {
                                        tracing::debug!("Dokodemo TCP error from {}: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => tracing::error!("Dokodemo TCP accept error: {}", e),
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
        });
        Ok(())
    }

    async fn start_udp_listener(&self, addr: SocketAddr) -> Result<()> {
        let socket = UdpSocket::bind(addr).await
            .map_err(|e| Error::network(format!("Failed to bind UDP: {}", e)))?;
        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let cancel_token = self.cancel_token.clone();
        let target_address = self.target_address.clone();
        let target_port = self.target_port;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((n, src_addr)) => {
                                let data = buf[..n].to_vec();
                                let router = Arc::clone(&router);
                                let outbound_manager = Arc::clone(&outbound_manager);
                                let target_address = target_address.clone();
                                let _socket_clone = socket.local_addr().ok();
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_udp_packet(
                                        data, src_addr, router, outbound_manager,
                                        target_address, target_port
                                    ).await {
                                        tracing::debug!("Dokodemo UDP error from {}: {}", src_addr, e);
                                    }
                                });
                            }
                            Err(e) => tracing::error!("Dokodemo UDP recv error: {}", e),
                        }
                    }
                }
            }
        });
        Ok(())
    }

    async fn stop_listener(&self) -> Result<()> {
        self.cancel_token.cancel();
        let mut attempts = 0;
        while self.running.load(std::sync::atomic::Ordering::Relaxed) && attempts < 50 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            attempts += 1;
        }
        Ok(())
    }

    async fn handle_tcp_connection(
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        target_address: String,
        target_port: u16,
    ) -> Result<()> {
        let target = if target_address.parse::<std::net::IpAddr>().is_ok() {
            let ip: std::net::IpAddr = target_address.parse().unwrap();
            TargetAddr::Ip(SocketAddr::new(ip, target_port))
        } else {
            TargetAddr::Domain(target_address.clone(), target_port)
        };
        let outbound_tag = router.match_outbound(
            Some(&target.host()), None, Some(target.port()), None
        ).await;
        tracing::info!("Dokodemo {} -> {} from {}", target, outbound_tag, peer_addr);
        let outbound = outbound_manager.get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;
        let tracked_conn = TrackedConnection::new_with_ip(
            "dokodemo".to_string(), outbound_tag.clone(), target.host(), None,
            target.port(), "Dokodemo".to_string(), "tcp".to_string(),
            "Dokodemo".to_string(), target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);
        if let Err(e) = outbound.relay_tcp_with_connection(
            Box::new(stream), target.clone(), Some(conn_arc)
        ).await {
            tracing::debug!("Dokodemo relay error: {}", e);
        }
        tracker.untrack(&tracked.id);
        Ok(())
    }

    async fn handle_udp_packet(
        data: Vec<u8>,
        src_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        target_address: String,
        target_port: u16,
    ) -> Result<()> {
        let target = if target_address.parse::<std::net::IpAddr>().is_ok() {
            let ip: std::net::IpAddr = target_address.parse().unwrap();
            TargetAddr::Ip(SocketAddr::new(ip, target_port))
        } else {
            TargetAddr::Domain(target_address.clone(), target_port)
        };
        let outbound_tag = router.match_outbound(
            Some(&target.host()), None, Some(target.port()), None
        ).await;
        tracing::debug!("Dokodemo UDP {} -> {} from {}", target, outbound_tag, src_addr);
        let outbound = outbound_manager.get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;
        if outbound.supports_udp() {
            match outbound.relay_udp_packet(&target, &data).await {
                Ok(_response) => {}
                Err(e) => tracing::debug!("Dokodemo UDP relay error: {}", e),
            }
        }
        Ok(())
    }
}
