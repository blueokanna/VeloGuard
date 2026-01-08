use crate::config::InboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use sha2::{Digest, Sha224};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[allow(dead_code)]
const TROJAN_CMD_CONNECT: u8 = 0x01;
#[allow(dead_code)]
const TROJAN_CMD_UDP: u8 = 0x03;

pub struct TrojanInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
    passwords: Arc<RwLock<HashSet<String>>>,
}

#[async_trait::async_trait]
impl InboundListener for TrojanInbound {
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

impl TrojanInbound {
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        let mut passwords_set = HashSet::new();
        if let Some(users) = config.options.get("users") {
            if let Some(users_arr) = users.as_sequence() {
                for user in users_arr {
                    if let Some(password) = user.get("password").and_then(|v| v.as_str()) {
                        let hash = hex::encode(Sha224::digest(password.as_bytes()));
                        passwords_set.insert(hash);
                    }
                }
            }
        }
        Self {
            config,
            router,
            outbound_manager,
            cancel_token: CancellationToken::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            passwords: Arc::new(RwLock::new(passwords_set)),
        }
    }

    async fn start_listener(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        let addr: SocketAddr = format!("{}:{}", self.config.listen, self.config.port)
            .parse()
            .map_err(|e| Error::config(format!("Invalid listen address: {}", e)))?;
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
        let passwords = Arc::clone(&self.passwords);
        running.store(true, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                let router = Arc::clone(&router);
                                let outbound_manager = Arc::clone(&outbound_manager);
                                let passwords = Arc::clone(&passwords);
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(
                                        stream, peer_addr, router, outbound_manager, passwords
                                    ).await {
                                        tracing::debug!("Trojan inbound error from {}: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => tracing::error!("Trojan accept error: {}", e),
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
        });
        tracing::info!("Trojan inbound listening on {}", addr);
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

    async fn handle_connection(
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        passwords: Arc<RwLock<HashSet<String>>>,
    ) -> Result<()> {
        let mut password_hash = [0u8; 56];
        stream.read_exact(&mut password_hash).await
            .map_err(|e| Error::network(format!("Failed to read password hash: {}", e)))?;
        let password_hex = String::from_utf8(password_hash.to_vec())
            .map_err(|_| Error::protocol("Invalid password encoding"))?;
        let passwords_read = passwords.read().await;
        if !passwords_read.contains(&password_hex) {
            return Err(Error::protocol("Invalid Trojan password"));
        }
        drop(passwords_read);
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await
            .map_err(|e| Error::network(format!("Failed to read CRLF: {}", e)))?;
        if crlf != [0x0D, 0x0A] {
            return Err(Error::protocol("Invalid CRLF after password"));
        }
        let mut cmd_buf = [0u8; 1];
        stream.read_exact(&mut cmd_buf).await
            .map_err(|e| Error::network(format!("Failed to read command: {}", e)))?;
        let _command = cmd_buf[0];
        let mut addr_type_buf = [0u8; 1];
        stream.read_exact(&mut addr_type_buf).await
            .map_err(|e| Error::network(format!("Failed to read address type: {}", e)))?;
        let addr_type = addr_type_buf[0];
        let target = match addr_type {
            0x01 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port))
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await?;
                let domain = String::from_utf8(domain)
                    .map_err(|_| Error::protocol("Invalid domain encoding"))?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                TargetAddr::Domain(domain, port)
            }
            0x04 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                let ip = Ipv6Addr::from(addr);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => return Err(Error::protocol(format!("Unknown address type: {}", addr_type))),
        };
        let mut crlf2 = [0u8; 2];
        stream.read_exact(&mut crlf2).await
            .map_err(|e| Error::network(format!("Failed to read CRLF: {}", e)))?;
        let outbound_tag = router.match_outbound(
            Some(&target.host()), None, Some(target.port()), None
        ).await;
        tracing::info!("Trojan {} -> {} from {}", target, outbound_tag, peer_addr);
        let outbound = outbound_manager.get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;
        let tracked_conn = TrackedConnection::new_with_ip(
            "trojan".to_string(), outbound_tag.clone(), target.host(), None,
            target.port(), "Trojan".to_string(), "tcp".to_string(),
            "Trojan".to_string(), target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);
        if let Err(e) = outbound.relay_tcp_with_connection(
            Box::new(stream), target.clone(), Some(conn_arc)
        ).await {
            tracing::debug!("Trojan relay error: {}", e);
        }
        tracker.untrack(&tracked.id);
        Ok(())
    }
}
