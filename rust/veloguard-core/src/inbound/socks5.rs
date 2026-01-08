use crate::config::InboundConfig;
use crate::connection_tracker::{TrackedConnection, global_tracker};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use dashmap::DashMap;
use std::time::{Duration, Instant};

/// UDP session timeout for QUIC/gRPC long-lived connections
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

/// UDP session for tracking UDP ASSOCIATE connections
#[allow(dead_code)]
struct UdpSession {
    client_addr: SocketAddr,
    last_activity: Instant,
}

/// SOCKS5 proxy inbound listener with UDP ASSOCIATE support
pub struct Socks5Inbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
    /// UDP sessions for UDP ASSOCIATE
    #[allow(dead_code)]
    udp_sessions: Arc<DashMap<u16, UdpSession>>,
}

#[async_trait::async_trait]
impl InboundListener for Socks5Inbound {
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

impl Socks5Inbound {
    pub fn new(config: InboundConfig, router: Arc<Router>, outbound_manager: Arc<OutboundManager>) -> Self {
        Self { 
            config, 
            router,
            outbound_manager,
            cancel_token: CancellationToken::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            udp_sessions: Arc::new(DashMap::new()),
        }
    }

    async fn start_listener(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!("SOCKS5 inbound already running on {}:{}", self.config.listen, self.config.port);
            return Ok(());
        }

        let addr: SocketAddr = format!("{}:{}", self.config.listen, self.config.port)
            .parse()
            .map_err(|e| Error::config_with_source("Invalid listen address", e))?;

        // Try to bind with SO_REUSEADDR to avoid "address already in use" errors
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ).map_err(|e| Error::network(format!("Failed to create socket: {}", e)))?;
        
        socket.set_reuse_address(true)
            .map_err(|e| Error::network(format!("Failed to set SO_REUSEADDR: {}", e)))?;
        
        socket.set_nonblocking(true)
            .map_err(|e| Error::network(format!("Failed to set non-blocking: {}", e)))?;
        
        socket.bind(&addr.into())
            .map_err(|e| Error::network(format!("Failed to bind SOCKS5 listener to {}: {}", addr, e)))?;
        
        socket.listen(1024)
            .map_err(|e| Error::network(format!("Failed to listen on {}: {}", addr, e)))?;

        let listener: TcpListener = TcpListener::from_std(socket.into())
            .map_err(|e| Error::network(format!("Failed to create TcpListener: {}", e)))?;

        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let cancel_token = self.cancel_token.clone();
        let running = Arc::clone(&self.running);

        running.store(true, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("SOCKS5 inbound on {} shutting down", addr);
                        break;
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                let router = Arc::clone(&router);
                                let outbound_manager = Arc::clone(&outbound_manager);
                                tokio::spawn(async move {
                                    if let Err(err) = Self::handle_connection(stream, peer_addr, router, outbound_manager).await {
                                        tracing::debug!("SOCKS5 connection error from {}: {}", peer_addr, err);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("SOCKS5 accept error: {}", e);
                            }
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("SOCKS5 inbound on {} stopped", addr);
        });

        tracing::info!("SOCKS5 inbound listening on {}", addr);
        Ok(())
    }

    async fn stop_listener(&self) -> Result<()> {
        tracing::info!("Stopping SOCKS5 inbound on {}:{}", self.config.listen, self.config.port);
        self.cancel_token.cancel();
        
        // Wait for graceful shutdown
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
    ) -> Result<()> {
        // SOCKS5 handshake
        if !Self::perform_handshake(&mut stream).await? {
            return Err(Error::protocol_with_info("SOCKS5 handshake failed", "SOCKS5"));
        }

        // Read request
        let (target_addr, target_port, command) = Self::read_request(&mut stream).await?;

        // Handle different SOCKS5 commands
        match command {
            0x01 => {
                // CONNECT command - TCP proxy
                Self::handle_connect(stream, peer_addr, target_addr, target_port, router, outbound_manager).await
            }
            0x03 => {
                // UDP ASSOCIATE command - UDP proxy for QUIC/gRPC
                Self::handle_udp_associate(stream, peer_addr, router, outbound_manager).await
            }
            _ => {
                Self::send_reply(&mut stream, 0x07).await?; // Command not supported
                Err(Error::protocol_with_info("Unsupported SOCKS5 command", "SOCKS5"))
            }
        }
    }

    /// Handle SOCKS5 CONNECT command (TCP proxy)
    async fn handle_connect(
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        target_addr: Socks5Addr,
        target_port: u16,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {

        // Extract domain/IP and port for routing
        let (domain, ip) = match &target_addr {
            Socks5Addr::Domain(domain) => (Some(domain.clone()), None),
            Socks5Addr::Ipv4(ip) => (None, Some(IpAddr::V4(*ip))),
            Socks5Addr::Ipv6(ip) => (None, Some(IpAddr::V6(*ip))),
        };

        // Match outbound using router
        let outbound_tag = router.match_outbound(
            domain.as_deref(),
            ip,
            Some(target_port),
            None,
        ).await;

        // Build target address
        let target = match &target_addr {
            Socks5Addr::Domain(d) => TargetAddr::new_domain(d.clone(), target_port),
            Socks5Addr::Ipv4(ip) => TargetAddr::new_ip(SocketAddr::new(IpAddr::V4(*ip), target_port)),
            Socks5Addr::Ipv6(ip) => TargetAddr::new_ip(SocketAddr::new(IpAddr::V6(*ip), target_port)),
        };

        tracing::info!("SOCKS5 CONNECT {} -> {} from {}", target, outbound_tag, peer_addr);

        // Get the outbound proxy
        let outbound = match outbound_manager.get_proxy(&outbound_tag) {
            Some(proxy) => proxy,
            None => {
                tracing::error!("Outbound '{}' not found", outbound_tag);
                Self::send_reply(&mut stream, 0x01).await?; // General failure
                return Err(Error::config(format!("Outbound '{}' not found", outbound_tag)));
            }
        };

        // Send success reply with dummy bound address (we don't know the actual bind address)
        let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        Self::send_reply_with_addr(&mut stream, 0x00, dummy_addr).await?;

        // Try to resolve the destination IP for display
        let destination_ip = match &target {
            TargetAddr::Ip(addr) => Some(addr.ip().to_string()),
            TargetAddr::Domain(domain, _) => {
                // Try to resolve the domain to get the IP
                tokio::net::lookup_host(format!("{}:{}", domain, target.port()))
                    .await
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .map(|addr| addr.ip().to_string())
            }
        };

        // Track the connection with IP address
        let tracked_conn = TrackedConnection::new_with_ip(
            "socks5".to_string(),
            outbound_tag.clone(),
            target.host(),
            destination_ip,
            target.port(),
            "SOCKS5".to_string(),
            "tcp".to_string(),
            "SOCKS5".to_string(),
            target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);

        // Relay data through the outbound proxy with connection tracking
        if let Err(e) = outbound.relay_tcp_with_connection(Box::new(stream), target.clone(), Some(conn_arc)).await {
            tracing::debug!("SOCKS5 relay error via '{}' to {}: {}", outbound.tag(), target, e);
        }

        // Untrack the connection
        tracker.untrack(&tracked.id);

        Ok(())
    }

    /// Handle SOCKS5 UDP ASSOCIATE command for QUIC/gRPC protocols
    async fn handle_udp_associate(
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        tracing::info!("SOCKS5 UDP ASSOCIATE request from {}", peer_addr);

        // Bind a UDP socket for the client
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;
        
        let local_addr = udp_socket.local_addr()
            .map_err(|e| Error::network(format!("Failed to get UDP socket address: {}", e)))?;

        tracing::info!("UDP relay socket bound to {} for client {}", local_addr, peer_addr);

        // Send success reply with the UDP relay address
        Self::send_reply_with_addr(&mut stream, 0x00, local_addr).await?;

        // Start UDP relay task
        let udp_socket = Arc::new(udp_socket);
        let udp_socket_clone = Arc::clone(&udp_socket);
        let router_clone = Arc::clone(&router);
        let outbound_manager_clone = Arc::clone(&outbound_manager);

        // Spawn UDP relay handler
        tokio::spawn(async move {
            if let Err(e) = Self::run_udp_relay(
                udp_socket_clone,
                peer_addr,
                router_clone,
                outbound_manager_clone,
            ).await {
                tracing::debug!("UDP relay error for {}: {}", peer_addr, e);
            }
        });

        // Keep TCP connection alive - UDP ASSOCIATE is valid while TCP connection is open
        // Read from TCP stream to detect when client disconnects
        let mut buf = [0u8; 1];
        loop {
            match tokio::time::timeout(Duration::from_secs(60), stream.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    // Client disconnected
                    tracing::info!("UDP ASSOCIATE client {} disconnected", peer_addr);
                    break;
                }
                Ok(Ok(_)) => {
                    // Unexpected data, ignore
                }
                Ok(Err(e)) => {
                    tracing::debug!("UDP ASSOCIATE TCP error for {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    // Timeout, check if still connected
                    continue;
                }
            }
        }

        Ok(())
    }

    /// Run UDP relay for SOCKS5 UDP ASSOCIATE
    async fn run_udp_relay(
        udp_socket: Arc<UdpSocket>,
        _client_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        // Cache for UDP sessions to maintain connection state for QUIC
        let session_cache: Arc<DashMap<String, Arc<UdpSocket>>> = Arc::new(DashMap::new());
        
        loop {
            let (n, src_addr) = match tokio::time::timeout(
                UDP_SESSION_TIMEOUT,
                udp_socket.recv_from(&mut buf)
            ).await {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    tracing::debug!("UDP recv error: {}", e);
                    continue;
                }
                Err(_) => {
                    // Timeout, cleanup old sessions and continue
                    session_cache.retain(|_, _| true); // Keep all for now
                    continue;
                }
            };

            if n < 10 {
                continue; // Too short for SOCKS5 UDP header
            }

            // Parse SOCKS5 UDP request header
            // +----+------+------+----------+----------+----------+
            // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +----+------+------+----------+----------+----------+
            // | 2  |  1   |  1   | Variable |    2     | Variable |
            // +----+------+------+----------+----------+----------+

            let frag = buf[2];
            if frag != 0 {
                // Fragmentation not supported
                tracing::debug!("UDP fragmentation not supported");
                continue;
            }

            let atyp = buf[3];
            let (target_addr, target_port, header_len) = match atyp {
                0x01 => {
                    // IPv4
                    if n < 10 {
                        continue;
                    }
                    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                    let port = u16::from_be_bytes([buf[8], buf[9]]);
                    (TargetAddr::new_ip(SocketAddr::new(IpAddr::V4(ip), port)), port, 10)
                }
                0x03 => {
                    // Domain
                    let domain_len = buf[4] as usize;
                    if n < 7 + domain_len {
                        continue;
                    }
                    let domain = match String::from_utf8(buf[5..5 + domain_len].to_vec()) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };
                    let port = u16::from_be_bytes([buf[5 + domain_len], buf[6 + domain_len]]);
                    (TargetAddr::new_domain(domain, port), port, 7 + domain_len)
                }
                0x04 => {
                    // IPv6
                    if n < 22 {
                        continue;
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[4..20]);
                    let ip = Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([buf[20], buf[21]]);
                    (TargetAddr::new_ip(SocketAddr::new(IpAddr::V6(ip), port)), port, 22)
                }
                _ => continue,
            };

            let payload = &buf[header_len..n];
            if payload.is_empty() {
                continue;
            }

            // Route the UDP packet
            let (domain, ip) = match &target_addr {
                TargetAddr::Domain(d, _) => (Some(d.clone()), None),
                TargetAddr::Ip(addr) => (None, Some(addr.ip())),
            };

            let outbound_tag = router.match_outbound(
                domain.as_deref(),
                ip,
                Some(target_port),
                None,
            ).await;

            tracing::debug!(
                "UDP relay: {} -> {} via {} ({} bytes)",
                src_addr, target_addr, outbound_tag, payload.len()
            );

            // For direct outbound, use a more efficient approach
            if outbound_tag == "direct" {
                // Resolve target address
                let resolved_addr = match &target_addr {
                    TargetAddr::Ip(addr) => *addr,
                    TargetAddr::Domain(domain, port) => {
                        match tokio::net::lookup_host(format!("{}:{}", domain, port)).await {
                            Ok(mut addrs) => match addrs.next() {
                                Some(addr) => addr,
                                None => continue,
                            },
                            Err(_) => continue,
                        }
                    }
                };

                // Get or create session socket for this target
                let session_key = resolved_addr.to_string();
                let session_socket = if let Some(socket) = session_cache.get(&session_key) {
                    socket.clone()
                } else {
                    let new_socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => Arc::new(s),
                        Err(_) => continue,
                    };
                    session_cache.insert(session_key.clone(), new_socket.clone());
                    
                    // Start a receiver task for this session
                    let recv_socket = new_socket.clone();
                    let reply_socket = Arc::clone(&udp_socket);
                    let reply_addr = src_addr;
                    let target_for_reply = target_addr.clone();
                    
                    tokio::spawn(async move {
                        let mut recv_buf = vec![0u8; 65535];
                        loop {
                            match tokio::time::timeout(
                                Duration::from_secs(60),
                                recv_socket.recv_from(&mut recv_buf)
                            ).await {
                                Ok(Ok((recv_n, _from_addr))) => {
                                    if recv_n == 0 {
                                        continue;
                                    }
                                    
                                    // Build SOCKS5 UDP response
                                    let mut response_packet = Vec::with_capacity(recv_n + 22);
                                    response_packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG
                                    
                                    match &target_for_reply {
                                        TargetAddr::Ip(addr) => {
                                            match addr.ip() {
                                                IpAddr::V4(ip) => {
                                                    response_packet.push(0x01);
                                                    response_packet.extend_from_slice(&ip.octets());
                                                }
                                                IpAddr::V6(ip) => {
                                                    response_packet.push(0x04);
                                                    response_packet.extend_from_slice(&ip.octets());
                                                }
                                            }
                                            response_packet.extend_from_slice(&addr.port().to_be_bytes());
                                        }
                                        TargetAddr::Domain(domain, port) => {
                                            response_packet.push(0x03);
                                            response_packet.push(domain.len() as u8);
                                            response_packet.extend_from_slice(domain.as_bytes());
                                            response_packet.extend_from_slice(&port.to_be_bytes());
                                        }
                                    }
                                    response_packet.extend_from_slice(&recv_buf[..recv_n]);

                                    if let Err(e) = reply_socket.send_to(&response_packet, reply_addr).await {
                                        tracing::debug!("Failed to send UDP response: {}", e);
                                    }
                                }
                                Ok(Err(e)) => {
                                    tracing::debug!("UDP session recv error: {}", e);
                                    break;
                                }
                                Err(_) => {
                                    // Timeout - session expired
                                    break;
                                }
                            }
                        }
                    });
                    
                    new_socket
                };

                // Send the packet directly
                if let Err(e) = session_socket.send_to(payload, resolved_addr).await {
                    tracing::debug!("Failed to send UDP packet: {}", e);
                }
                continue;
            }

            // Get the outbound proxy for non-direct
            let outbound = match outbound_manager.get_proxy(&outbound_tag) {
                Some(proxy) => proxy,
                None => {
                    tracing::warn!("Outbound '{}' not found for UDP", outbound_tag);
                    continue;
                }
            };

            // Check if outbound supports UDP
            if !outbound.supports_udp() {
                tracing::debug!("Outbound '{}' does not support UDP, skipping", outbound_tag);
                continue;
            }

            // Forward UDP packet through outbound
            let udp_socket_clone = Arc::clone(&udp_socket);
            let target_addr_clone = target_addr.clone();
            let payload_vec = payload.to_vec();
            
            tokio::spawn(async move {
                match outbound.relay_udp_packet(&target_addr_clone, &payload_vec).await {
                    Ok(response) => {
                        if !response.is_empty() {
                            // Build SOCKS5 UDP response
                            let mut response_packet = Vec::with_capacity(response.len() + 22);
                            response_packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG
                            
                            match &target_addr_clone {
                                TargetAddr::Ip(addr) => {
                                    match addr.ip() {
                                        IpAddr::V4(ip) => {
                                            response_packet.push(0x01);
                                            response_packet.extend_from_slice(&ip.octets());
                                        }
                                        IpAddr::V6(ip) => {
                                            response_packet.push(0x04);
                                            response_packet.extend_from_slice(&ip.octets());
                                        }
                                    }
                                    response_packet.extend_from_slice(&addr.port().to_be_bytes());
                                }
                                TargetAddr::Domain(domain, port) => {
                                    response_packet.push(0x03);
                                    response_packet.push(domain.len() as u8);
                                    response_packet.extend_from_slice(domain.as_bytes());
                                    response_packet.extend_from_slice(&port.to_be_bytes());
                                }
                            }
                            response_packet.extend_from_slice(&response);

                            if let Err(e) = udp_socket_clone.send_to(&response_packet, src_addr).await {
                                tracing::debug!("Failed to send UDP response: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("UDP relay error via '{}': {}", outbound.tag(), e);
                    }
                }
            });
        }
    }

    async fn perform_handshake(stream: &mut tokio::net::TcpStream) -> Result<bool> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 handshake: {}", e)))?;

        if buf[0] != 0x05 {
            return Ok(false); // Not SOCKS5
        }

        let num_methods = buf[1] as usize;
        let mut methods = vec![0u8; num_methods];
        stream.read_exact(&mut methods).await
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 methods: {}", e)))?;

        // Check if no authentication is supported
        let supports_no_auth = methods.contains(&0x00);
        if !supports_no_auth {
            // Send "no acceptable methods" reply
            stream.write_all(&[0x05, 0xFF]).await
                .map_err(|e| Error::network(format!("Failed to write SOCKS5 response: {}", e)))?;
            return Ok(false);
        }

        // Send response: version 5, no authentication
        stream.write_all(&[0x05, 0x00]).await
            .map_err(|e| Error::network(format!("Failed to write SOCKS5 response: {}", e)))?;

        Ok(true)
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Result<(Socks5Addr, u16, u8)> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 request: {}", e)))?;

        if buf[0] != 0x05 {
            return Err(Error::protocol("Invalid SOCKS5 version"));
        }

        let command = buf[1];
        let addr_type = buf[3];

        let (addr, port) = match addr_type {
            0x01 => { // IPv4
                let mut addr_buf = [0u8; 4];
                stream.read_exact(&mut addr_buf).await?;
                let ipv4 = Ipv4Addr::from(addr_buf);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                (Socks5Addr::Ipv4(ipv4), port)
            }
            0x03 => { // Domain
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; len];
                stream.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8(domain_buf)
                    .map_err(|_| Error::protocol("Invalid domain encoding"))?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                (Socks5Addr::Domain(domain), port)
            }
            0x04 => { // IPv6
                let mut addr_buf = [0u8; 16];
                stream.read_exact(&mut addr_buf).await?;
                let ipv6 = Ipv6Addr::from(addr_buf);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                (Socks5Addr::Ipv6(ipv6), port)
            }
            _ => return Err(Error::protocol("Unsupported address type")),
        };

        Ok((addr, port, command))
    }

    async fn send_reply(stream: &mut tokio::net::TcpStream, reply: u8) -> Result<()> {
        let reply_packet = [
            0x05, // Version
            reply, // Reply code
            0x00, // Reserved
            0x01, // IPv4 address type
            0x00, 0x00, 0x00, 0x00, // IPv4 address (0.0.0.0)
            0x00, 0x00, // Port (0)
        ];

        stream.write_all(&reply_packet).await
            .map_err(|e| Error::network(format!("Failed to write SOCKS5 reply: {}", e)))?;

        Ok(())
    }

    async fn send_reply_with_addr(stream: &mut tokio::net::TcpStream, reply: u8, addr: SocketAddr) -> Result<()> {
        let mut reply_packet = Vec::with_capacity(22);
        reply_packet.push(0x05); // Version
        reply_packet.push(reply); // Reply code
        reply_packet.push(0x00); // Reserved

        match addr.ip() {
            IpAddr::V4(ipv4) => {
                reply_packet.push(0x01); // IPv4
                reply_packet.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                reply_packet.push(0x04); // IPv6
                reply_packet.extend_from_slice(&ipv6.octets());
            }
        }
        
        reply_packet.extend_from_slice(&addr.port().to_be_bytes());

        stream.write_all(&reply_packet).await
            .map_err(|e| Error::network(format!("Failed to write SOCKS5 reply: {}", e)))?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn relay<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);

        let a_to_b = tokio::io::copy(&mut ar, &mut bw);
        let b_to_a = tokio::io::copy(&mut br, &mut aw);

        tokio::select! {
            result = a_to_b => {
                if let Err(e) = result {
                    tracing::debug!("Relay A->B error: {}", e);
                }
            }
            result = b_to_a => {
                if let Err(e) = result {
                    tracing::debug!("Relay B->A error: {}", e);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
enum Socks5Addr {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}
