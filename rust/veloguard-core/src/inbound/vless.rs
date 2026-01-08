use crate::config::InboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const VLESS_VERSION: u8 = 0;

pub struct VlessInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
    users: Arc<RwLock<HashSet<Uuid>>>,
}

#[async_trait::async_trait]
impl InboundListener for VlessInbound {
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

impl VlessInbound {
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        let mut users_set = HashSet::new();
        if let Some(users) = config.options.get("users") {
            if let Some(users_arr) = users.as_sequence() {
                for user in users_arr {
                    if let Some(uuid_str) = user.get("uuid").and_then(|v| v.as_str()) {
                        if let Ok(uuid) = Uuid::parse_str(uuid_str) {
                            users_set.insert(uuid);
                        }
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
            users: Arc::new(RwLock::new(users_set)),
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
        let users = Arc::clone(&self.users);
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
                                let users = Arc::clone(&users);
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(
                                        stream, peer_addr, router, outbound_manager, users
                                    ).await {
                                        tracing::debug!("VLESS inbound error from {}: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => tracing::error!("VLESS accept error: {}", e),
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
        });
        tracing::info!("VLESS inbound listening on {}", addr);
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
        users: Arc<RwLock<HashSet<Uuid>>>,
    ) -> Result<()> {
        let mut header = [0u8; 1 + 16 + 1];
        stream.read_exact(&mut header).await
            .map_err(|e| Error::network(format!("Failed to read VLESS header: {}", e)))?;
        let version = header[0];
        if version != VLESS_VERSION {
            return Err(Error::protocol(format!("Invalid VLESS version: {}", version)));
        }
        let uuid_bytes: [u8; 16] = header[1..17].try_into().unwrap();
        let uuid = Uuid::from_bytes(uuid_bytes);
        let users_read = users.read().await;
        if !users_read.contains(&uuid) {
            return Err(Error::protocol("Unknown VLESS user"));
        }
        drop(users_read);
        let addon_len = header[17] as usize;
        if addon_len > 0 {
            let mut addon = vec![0u8; addon_len];
            stream.read_exact(&mut addon).await
                .map_err(|e| Error::network(format!("Failed to read addon: {}", e)))?;
        }
        let mut cmd_buf = [0u8; 1];
        stream.read_exact(&mut cmd_buf).await
            .map_err(|e| Error::network(format!("Failed to read command: {}", e)))?;
        let _command = cmd_buf[0];
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await
            .map_err(|e| Error::network(format!("Failed to read port: {}", e)))?;
        let port = u16::from_be_bytes(port_buf);
        let mut addr_type_buf = [0u8; 1];
        stream.read_exact(&mut addr_type_buf).await
            .map_err(|e| Error::network(format!("Failed to read address type: {}", e)))?;
        let addr_type = addr_type_buf[0];
        let target = match addr_type {
            0x01 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port))
            }
            0x02 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await?;
                let domain = String::from_utf8(domain)
                    .map_err(|_| Error::protocol("Invalid domain encoding"))?;
                TargetAddr::Domain(domain, port)
            }
            0x03 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                let ip = Ipv6Addr::from(addr);
                TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => return Err(Error::protocol(format!("Unknown address type: {}", addr_type))),
        };
        let outbound_tag = router.match_outbound(
            Some(&target.host()), None, Some(target.port()), None
        ).await;
        tracing::info!("VLESS {} -> {} from {}", target, outbound_tag, peer_addr);
        let outbound = outbound_manager.get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;
        stream.write_all(&[VLESS_VERSION, 0]).await
            .map_err(|e| Error::network(format!("Failed to write response: {}", e)))?;
        let tracked_conn = TrackedConnection::new_with_ip(
            "vless".to_string(), outbound_tag.clone(), target.host(), None,
            target.port(), "VLESS".to_string(), "tcp".to_string(),
            "VLESS".to_string(), target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);
        if let Err(e) = outbound.relay_tcp_with_connection(
            Box::new(stream), target.clone(), Some(conn_arc)
        ).await {
            tracing::debug!("VLESS relay error: {}", e);
        }
        tracker.untrack(&tracked.id);
        Ok(())
    }
}
