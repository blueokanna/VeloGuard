use crate::config::InboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

pub struct MixedInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
}

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ADDR_IPV4: u8 = 0x01;
const SOCKS5_ADDR_DOMAIN: u8 = 0x03;
const SOCKS5_ADDR_IPV6: u8 = 0x04;

#[async_trait::async_trait]
impl InboundListener for MixedInbound {
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

impl MixedInbound {
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        Self {
            config,
            router,
            outbound_manager,
            cancel_token: CancellationToken::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    async fn start_listener(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                "Mixed inbound already running on {}:{}",
                self.config.listen,
                self.config.port
            );
            return Ok(());
        }

        let addr: SocketAddr = format!("{}:{}", self.config.listen, self.config.port)
            .parse()
            .map_err(|e| Error::config(format!("Invalid listen address: {}", e)))?;

        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|e| Error::network(format!("Failed to create socket: {}", e)))?;

        socket
            .set_reuse_address(true)
            .map_err(|e| Error::network(format!("Failed to set SO_REUSEADDR: {}", e)))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| Error::network(format!("Failed to set non-blocking: {}", e)))?;

        socket.bind(&addr.into()).map_err(|e| {
            Error::network(format!("Failed to bind Mixed listener to {}: {}", addr, e))
        })?;

        socket
            .listen(1024)
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
                        tracing::info!("Mixed inbound on {} shutting down", addr);
                        break;
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                let router = Arc::clone(&router);
                                let outbound_manager = Arc::clone(&outbound_manager);
                                tokio::spawn(async move {
                                    if let Err(err) = Self::handle_connection(stream, peer_addr, router, outbound_manager).await {
                                        tracing::debug!("Mixed connection error from {}: {}", peer_addr, err);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("Mixed accept error: {}", e);
                            }
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("Mixed inbound on {} stopped", addr);
        });

        tracing::info!("Mixed inbound (HTTP/SOCKS5) listening on {}", addr);
        Ok(())
    }

    async fn stop_listener(&self) -> Result<()> {
        tracing::info!(
            "Stopping Mixed inbound on {}:{}",
            self.config.listen,
            self.config.port
        );
        self.cancel_token.cancel();

        let mut attempts = 0;
        while self.running.load(std::sync::atomic::Ordering::Relaxed) && attempts < 50 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            attempts += 1;
        }

        Ok(())
    }

    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        let mut peek_buf = [0u8; 1];
        stream.peek(&mut peek_buf).await.map_err(|e| {
            Error::network(format!(
                "Failed to peek connection from {}: {}",
                peer_addr, e
            ))
        })?;

        let first_byte = peek_buf[0];

        if first_byte == SOCKS5_VERSION {
            tracing::debug!("Detected SOCKS5 protocol from {}", peer_addr);
            Self::handle_socks5(stream, peer_addr, router, outbound_manager).await
        } else {
            tracing::debug!("Detected HTTP protocol from {}", peer_addr);
            Self::handle_http(stream, peer_addr, router, outbound_manager).await
        }
    }

    // ============== HTTP Handling ==============

    async fn handle_http(
        stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        let io = TokioIo::new(stream);

        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let router = Arc::clone(&router);
            let outbound_manager = Arc::clone(&outbound_manager);
            async move { Self::handle_http_request(req, peer_addr, router, outbound_manager).await }
        });

        if let Err(err) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
        {
            // Filter out common non-error conditions
            let err_str = err.to_string();
            if !err_str.contains("connection closed")
                && !err_str.contains("connection reset")
                && !err_str.contains("broken pipe")
            {
                tracing::debug!("HTTP serve error from {}: {}", peer_addr, err);
            }
        }

        Ok(())
    }

    async fn handle_http_request(
        req: Request<hyper::body::Incoming>,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> std::result::Result<Response<BoxBody<Bytes, std::io::Error>>, std::convert::Infallible>
    {
        let method = req.method().clone();
        let uri = req.uri().clone();

        tracing::debug!("HTTP {} {} from {}", method, uri, peer_addr);
        if method == Method::CONNECT {
            return Ok(Self::handle_http_connect(req, router, outbound_manager).await);
        }

        match Self::handle_http_proxy(req, router, outbound_manager).await {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::error!("HTTP proxy error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(
                        Full::new(Bytes::from(format!("Proxy error: {}", e)))
                            .map_err(|_| std::io::Error::other("body error"))
                            .boxed(),
                    )
                    .unwrap())
            }
        }
    }

    async fn handle_http_connect(
        req: Request<hyper::body::Incoming>,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Response<BoxBody<Bytes, std::io::Error>> {
        let uri = req.uri().clone();

        let (host, port) = match Self::parse_connect_uri(&uri) {
            Some(hp) => hp,
            None => {
                tracing::warn!("Invalid CONNECT URI: {}", uri);
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(
                        Full::new(Bytes::from("Invalid CONNECT request"))
                            .map_err(|_| std::io::Error::other("body error"))
                            .boxed(),
                    )
                    .unwrap();
            }
        };

        let outbound_tag = router
            .match_outbound(Some(&host), None, Some(port), None)
            .await;

        tracing::info!("CONNECT {}:{} -> {}", host, port, outbound_tag);
        let outbound = match outbound_manager.get_proxy(&outbound_tag) {
            Some(proxy) => proxy,
            None => {
                tracing::error!("Outbound '{}' not found", outbound_tag);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(
                        Full::new(Bytes::from(format!(
                            "Outbound '{}' not found",
                            outbound_tag
                        )))
                        .map_err(|_| std::io::Error::other("body error"))
                        .boxed(),
                    )
                    .unwrap();
            }
        };

        let target = TargetAddr::new_domain(host.clone(), port);
        let outbound_tag_clone = outbound_tag.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let upgraded = TokioIo::new(upgraded);

                    let destination_ip = tokio::net::lookup_host(format!("{}:{}", host, port))
                        .await
                        .ok()
                        .and_then(|mut addrs| addrs.next())
                        .map(|addr| addr.ip().to_string());

                    let tracked_conn = TrackedConnection::new_with_ip(
                        "mixed".to_string(),
                        outbound_tag_clone.clone(),
                        host.clone(),
                        destination_ip,
                        port,
                        "HTTPS".to_string(),
                        "tcp".to_string(),
                        "HTTP-CONNECT".to_string(),
                        format!("{}:{}", host, port),
                    );
                    let tracker = global_tracker();
                    let tracked = tracker.track(tracked_conn);
                    let conn_arc = Arc::clone(&tracked);

                    // Use the outbound proxy to relay traffic with connection tracking
                    if let Err(e) = outbound
                        .relay_tcp_with_connection(Box::new(upgraded), target, Some(conn_arc))
                        .await
                    {
                        tracing::debug!("CONNECT relay error via '{}': {}", outbound.tag(), e);
                    }
                    tracker.untrack(&tracked.id);
                }
                Err(e) => {
                    tracing::debug!("HTTP upgrade failed: {}", e);
                }
            }
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(
                Empty::new()
                    .map_err(|_| std::io::Error::other("empty"))
                    .boxed(),
            )
            .unwrap()
    }

    async fn handle_http_proxy(
        req: Request<hyper::body::Incoming>,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
        let uri = req.uri().clone();

        let (host, port) = Self::parse_http_uri(&uri, req.headers())
            .ok_or_else(|| Error::protocol("Invalid HTTP proxy request: missing host"))?;

        let outbound_tag = router
            .match_outbound(Some(&host), None, Some(port), None)
            .await;

        tracing::info!("HTTP {} -> {}", uri, outbound_tag);

        let outbound = outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        let method = req.method().clone();
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let mut request_bytes = Vec::new();
        request_bytes.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());
        for (key, value) in req.headers() {
            let key_str = key.as_str().to_lowercase();
            if key_str != "proxy-connection" && key_str != "proxy-authorization" {
                request_bytes.extend_from_slice(
                    format!("{}: {}\r\n", key, value.to_str().unwrap_or("")).as_bytes(),
                );
            }
        }
        request_bytes.extend_from_slice(b"\r\n");

        let body = req.into_body();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| Error::network(format!("Failed to read request body: {}", e)))?
            .to_bytes();
        if !body_bytes.is_empty() {
            request_bytes.extend_from_slice(&body_bytes);
        }

        let target = TargetAddr::new_domain(host.clone(), port);
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);

        let relay_handle =
            tokio::spawn(async move { outbound.relay_tcp(Box::new(server_side), target).await });

        let (mut read_half, mut write_half) = tokio::io::split(client_side);
        write_half
            .write_all(&request_bytes)
            .await
            .map_err(|e| Error::network(format!("Failed to write request: {}", e)))?;

        write_half
            .shutdown()
            .await
            .map_err(|e| Error::network(format!("Failed to shutdown write: {}", e)))?;

        let mut response_buf = Vec::new();
        let mut temp_buf = [0u8; 8192];
        let mut headers_complete = false;
        let mut content_length: Option<usize> = None;
        let mut body_read = 0usize;

        let read_timeout = tokio::time::Duration::from_secs(30);
        let start = tokio::time::Instant::now();

        loop {
            if start.elapsed() > read_timeout {
                break;
            }

            let read_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                read_half.read(&mut temp_buf),
            )
            .await;

            match read_result {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response_buf.extend_from_slice(&temp_buf[..n]);

                    if !headers_complete {
                        if let Some(header_end) = find_header_end(&response_buf) {
                            headers_complete = true;
                            let headers_str = String::from_utf8_lossy(&response_buf[..header_end]);
                            for line in headers_str.lines() {
                                if line.to_lowercase().starts_with("content-length:") {
                                    if let Some(len_str) = line.split(':').nth(1) {
                                        content_length = len_str.trim().parse().ok();
                                    }
                                }
                            }
                            body_read = response_buf.len() - header_end - 4;
                        }
                    } else {
                        body_read += n;
                    }

                    if headers_complete {
                        if let Some(cl) = content_length {
                            if body_read >= cl {
                                break;
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!("Read error: {}", e);
                    break;
                }
                Err(_) => {
                    if headers_complete && !response_buf.is_empty() {
                        break;
                    }
                }
            }
        }

        let _ = relay_handle.await;
        if response_buf.is_empty() {
            return Err(Error::network("No response received from server"));
        }

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(
                Full::new(Bytes::from(response_buf))
                    .map_err(|_| std::io::Error::other("body error"))
                    .boxed(),
            )
            .unwrap())
    }

    fn parse_connect_uri(uri: &Uri) -> Option<(String, u16)> {
        if let Some(authority) = uri.authority() {
            let host = authority.host().to_string();
            let port = authority.port_u16().unwrap_or(443);
            return Some((host, port));
        }

        let path = uri.path().trim_start_matches('/');
        if let Some((host, port_str)) = path.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }

        let uri_str = uri.to_string();
        if let Some((host, port_str)) = uri_str.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }

        None
    }

    fn parse_http_uri(uri: &Uri, headers: &hyper::HeaderMap) -> Option<(String, u16)> {
        if let Some(host) = uri.host() {
            let port = uri.port_u16().unwrap_or(80);
            return Some((host.to_string(), port));
        }

        if let Some(host_header) = headers.get("host") {
            if let Ok(host_str) = host_header.to_str() {
                if let Some((host, port_str)) = host_str.rsplit_once(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        return Some((host.to_string(), port));
                    }
                }
                return Some((host_str.to_string(), 80));
            }
        }

        None
    }

    // ============== SOCKS5 Handling ==============

    async fn handle_socks5(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.map_err(|e| {
            Error::protocol(format!(
                "Failed to read SOCKS5 header from {}: {}",
                peer_addr, e
            ))
        })?;

        let version = header[0];
        let nmethods = header[1] as usize;

        if version != SOCKS5_VERSION {
            return Err(Error::protocol(format!(
                "Invalid SOCKS version: {} (expected {})",
                version, SOCKS5_VERSION
            )));
        }

        let mut methods = vec![0u8; nmethods];
        stream
            .read_exact(&mut methods)
            .await
            .map_err(|e| Error::protocol(format!("Failed to read SOCKS5 methods: {}", e)))?;

        if !methods.contains(&SOCKS5_AUTH_NONE) {
            stream.write_all(&[SOCKS5_VERSION, 0xFF]).await.ok();
            return Err(Error::protocol("No acceptable SOCKS5 auth methods"));
        }

        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])
            .await
            .map_err(|e| Error::network(format!("Failed to send auth response: {}", e)))?;

        // Read connection request
        let mut request = [0u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .map_err(|e| Error::protocol(format!("Failed to read SOCKS5 request: {}", e)))?;

        let version = request[0];
        let cmd = request[1];
        let atyp = request[3];

        if version != SOCKS5_VERSION {
            return Err(Error::protocol("Invalid SOCKS5 version in request"));
        }

        match cmd {
            SOCKS5_CMD_CONNECT => {}
            0x03 => {
                // UDP ASSOCIATE - Full implementation for QUIC/gRPC support
                tracing::info!("SOCKS5 UDP ASSOCIATE request from {}", peer_addr);
                return Self::handle_udp_associate(stream, peer_addr, router, outbound_manager)
                    .await;
            }
            _ => {
                // 不支持的命令
                Self::send_socks5_error(&mut stream, 0x07).await; // Command not supported
                return Err(Error::protocol(format!(
                    "Unsupported SOCKS5 command: {}",
                    cmd
                )));
            }
        }

        // Parse destination address
        let target =
            match atyp {
                SOCKS5_ADDR_IPV4 => {
                    let mut addr = [0u8; 4];
                    stream.read_exact(&mut addr).await.map_err(|e| {
                        Error::protocol(format!("Failed to read IPv4 address: {}", e))
                    })?;
                    let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                    let mut port_buf = [0u8; 2];
                    stream
                        .read_exact(&mut port_buf)
                        .await
                        .map_err(|e| Error::protocol(format!("Failed to read port: {}", e)))?;
                    let port = u16::from_be_bytes(port_buf);
                    TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port))
                }
                SOCKS5_ADDR_DOMAIN => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await.map_err(|e| {
                        Error::protocol(format!("Failed to read domain length: {}", e))
                    })?;
                    let mut domain = vec![0u8; len[0] as usize];
                    stream
                        .read_exact(&mut domain)
                        .await
                        .map_err(|e| Error::protocol(format!("Failed to read domain: {}", e)))?;
                    let domain = String::from_utf8(domain)
                        .map_err(|_| Error::protocol("Invalid domain encoding"))?;
                    let mut port_buf = [0u8; 2];
                    stream
                        .read_exact(&mut port_buf)
                        .await
                        .map_err(|e| Error::protocol(format!("Failed to read port: {}", e)))?;
                    let port = u16::from_be_bytes(port_buf);
                    TargetAddr::Domain(domain, port)
                }
                SOCKS5_ADDR_IPV6 => {
                    let mut addr = [0u8; 16];
                    stream.read_exact(&mut addr).await.map_err(|e| {
                        Error::protocol(format!("Failed to read IPv6 address: {}", e))
                    })?;
                    let ip = Ipv6Addr::from(addr);
                    let mut port_buf = [0u8; 2];
                    stream
                        .read_exact(&mut port_buf)
                        .await
                        .map_err(|e| Error::protocol(format!("Failed to read port: {}", e)))?;
                    let port = u16::from_be_bytes(port_buf);
                    TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port))
                }
                _ => {
                    Self::send_socks5_error(&mut stream, 0x08).await; // Address type not supported
                    return Err(Error::protocol(format!(
                        "Unsupported address type: {}",
                        atyp
                    )));
                }
            };

        // Route the connection - properly handle IP vs Domain targets
        let (domain_for_routing, ip_for_routing) = match &target {
            TargetAddr::Ip(addr) => (None, Some(addr.ip())),
            TargetAddr::Domain(domain, _) => (Some(domain.as_str()), None),
        };

        let outbound_tag = router
            .match_outbound(
                domain_for_routing,
                ip_for_routing,
                Some(target.port()),
                None,
            )
            .await;

        tracing::info!("SOCKS5 {} -> {} (from {})", target, outbound_tag, peer_addr);

        // Get the outbound proxy
        let outbound = match outbound_manager.get_proxy(&outbound_tag) {
            Some(proxy) => proxy,
            None => {
                tracing::error!("Outbound '{}' not found", outbound_tag);
                Self::send_socks5_error(&mut stream, 0x01).await; // General failure
                return Err(Error::config(format!(
                    "Outbound '{}' not found",
                    outbound_tag
                )));
            }
        };

        let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        Self::send_socks5_success(&mut stream, dummy_addr).await?;

        // Try to resolve the destination IP for display
        let destination_ip = match &target {
            TargetAddr::Ip(addr) => Some(addr.ip().to_string()),
            TargetAddr::Domain(domain, _) => {
                tokio::net::lookup_host(format!("{}:{}", domain, target.port()))
                    .await
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .map(|addr| addr.ip().to_string())
            }
        };

        // Track the connection with IP address
        let tracked_conn = TrackedConnection::new_with_ip(
            "mixed".to_string(),
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

        if let Err(e) = outbound
            .relay_tcp_with_connection(Box::new(stream), target.clone(), Some(conn_arc))
            .await
        {
            let is_private = if let TargetAddr::Ip(addr) = &target {
                crate::routing::Router::is_private_ip(addr.ip())
            } else {
                false
            };
            let is_probe_port = matches!(target.port(), 7 | 9 | 13 | 17 | 19 | 37);

            if is_private && is_probe_port {
                // Completely silent for probe ports on private addresses
                tracing::trace!("SOCKS5 relay to private probe port {}: {}", target, e);
            } else if is_private {
                // Trace level for other private address failures
                tracing::trace!(
                    "SOCKS5 relay error via '{}' to {}: {}",
                    outbound.tag(),
                    target,
                    e
                );
            } else {
                // Debug level for public address failures
                tracing::debug!(
                    "SOCKS5 relay error via '{}' to {}: {}",
                    outbound.tag(),
                    target,
                    e
                );
            }
        }

        // Untrack the connection
        tracker.untrack(&tracked.id);

        Ok(())
    }

    async fn send_socks5_error(stream: &mut TcpStream, error_code: u8) {
        let response = [
            SOCKS5_VERSION,
            error_code,
            0x00, // Reserved
            SOCKS5_ADDR_IPV4,
            0,
            0,
            0,
            0, // Bind address
            0,
            0, // Bind port
        ];
        let _ = stream.write_all(&response).await;
    }

    async fn send_socks5_success(stream: &mut TcpStream, addr: SocketAddr) -> Result<()> {
        let mut response = vec![SOCKS5_VERSION, 0x00, 0x00]; // Success

        match addr.ip() {
            IpAddr::V4(ip) => {
                response.push(SOCKS5_ADDR_IPV4);
                response.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                response.push(SOCKS5_ADDR_IPV6);
                response.extend_from_slice(&ip.octets());
            }
        }

        response.extend_from_slice(&addr.port().to_be_bytes());

        stream
            .write_all(&response)
            .await
            .map_err(|e| Error::network(format!("Failed to send SOCKS5 response: {}", e)))?;

        Ok(())
    }

    // ============== UDP ASSOCIATE Handling ==============

    /// Handle SOCKS5 UDP ASSOCIATE command for QUIC/gRPC protocols
    async fn handle_udp_associate(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        // Bind a UDP socket for the client
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;

        let local_addr = udp_socket
            .local_addr()
            .map_err(|e| Error::network(format!("Failed to get UDP socket address: {}", e)))?;

        tracing::info!(
            "UDP relay socket bound to {} for client {}",
            local_addr,
            peer_addr
        );

        // Send success reply with the UDP relay address
        Self::send_socks5_success(&mut stream, local_addr).await?;

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
            )
            .await
            {
                tracing::debug!("UDP relay error for {}: {}", peer_addr, e);
            }
        });

        // Keep TCP connection alive - UDP ASSOCIATE is valid while TCP connection is open
        let mut buf = [0u8; 1];
        loop {
            match tokio::time::timeout(Duration::from_secs(60), stream.read(&mut buf)).await {
                Ok(Ok(0)) => {
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
            let (n, src_addr) =
                match tokio::time::timeout(UDP_SESSION_TIMEOUT, udp_socket.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => {
                        tracing::debug!("UDP recv error: {}", e);
                        continue;
                    }
                    Err(_) => {
                        // Timeout, cleanup old sessions and continue
                        session_cache.retain(|_, _| true);
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
                tracing::debug!("UDP fragmentation not supported");
                continue;
            }

            let atyp = buf[3];
            let (target_addr, target_port, header_len) = match atyp {
                SOCKS5_ADDR_IPV4 => {
                    if n < 10 {
                        continue;
                    }
                    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                    let port = u16::from_be_bytes([buf[8], buf[9]]);
                    (
                        TargetAddr::new_ip(SocketAddr::new(IpAddr::V4(ip), port)),
                        port,
                        10,
                    )
                }
                SOCKS5_ADDR_DOMAIN => {
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
                SOCKS5_ADDR_IPV6 => {
                    if n < 22 {
                        continue;
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[4..20]);
                    let ip = Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([buf[20], buf[21]]);
                    (
                        TargetAddr::new_ip(SocketAddr::new(IpAddr::V6(ip), port)),
                        port,
                        22,
                    )
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

            let outbound_tag = router
                .match_outbound(domain.as_deref(), ip, Some(target_port), None)
                .await;

            tracing::debug!(
                "UDP relay: {} -> {} via {} ({} bytes)",
                src_addr,
                target_addr,
                outbound_tag,
                payload.len()
            );

            // For direct outbound, use a more efficient approach
            if outbound_tag == "direct" {
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
                                recv_socket.recv_from(&mut recv_buf),
                            )
                            .await
                            {
                                Ok(Ok((recv_n, _from_addr))) => {
                                    if recv_n == 0 {
                                        continue;
                                    }

                                    // Build SOCKS5 UDP response
                                    let response_packet = Self::build_udp_response(
                                        &target_for_reply,
                                        &recv_buf[..recv_n],
                                    );
                                    if let Err(e) =
                                        reply_socket.send_to(&response_packet, reply_addr).await
                                    {
                                        tracing::debug!("Failed to send UDP response: {}", e);
                                    }
                                }
                                Ok(Err(e)) => {
                                    tracing::debug!("UDP session recv error: {}", e);
                                    break;
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                    });

                    new_socket
                };

                if let Err(e) = session_socket.send_to(payload, resolved_addr).await {
                    tracing::debug!("Failed to send UDP packet: {}", e);
                }
                continue;
            }

            let outbound = match outbound_manager.get_proxy(&outbound_tag) {
                Some(proxy) => proxy,
                None => {
                    tracing::warn!("Outbound '{}' not found for UDP", outbound_tag);
                    continue;
                }
            };

            if !outbound.supports_udp() {
                tracing::debug!("Outbound '{}' does not support UDP, skipping", outbound_tag);
                continue;
            }

            let udp_socket_clone = Arc::clone(&udp_socket);
            let target_addr_clone = target_addr.clone();
            let payload_vec = payload.to_vec();

            tokio::spawn(async move {
                match outbound
                    .relay_udp_packet(&target_addr_clone, &payload_vec)
                    .await
                {
                    Ok(response) => {
                        if !response.is_empty() {
                            let response_packet =
                                Self::build_udp_response(&target_addr_clone, &response);
                            if let Err(e) =
                                udp_socket_clone.send_to(&response_packet, src_addr).await
                            {
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

    fn build_udp_response(target: &TargetAddr, data: &[u8]) -> Vec<u8> {
        let mut response_packet = Vec::with_capacity(data.len() + 22);
        response_packet.extend_from_slice(&[0x00, 0x00, 0x00]);

        match target {
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    IpAddr::V4(ip) => {
                        response_packet.push(SOCKS5_ADDR_IPV4);
                        response_packet.extend_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        response_packet.push(SOCKS5_ADDR_IPV6);
                        response_packet.extend_from_slice(&ip.octets());
                    }
                }
                response_packet.extend_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Domain(domain, port) => {
                response_packet.push(SOCKS5_ADDR_DOMAIN);
                response_packet.push(domain.len() as u8);
                response_packet.extend_from_slice(domain.as_bytes());
                response_packet.extend_from_slice(&port.to_be_bytes());
            }
        }
        response_packet.extend_from_slice(data);
        response_packet
    }

    // ============== Common Relay ==============

    #[allow(dead_code)]
    async fn relay<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);

        // Use tokio::select with biased to handle both directions properly
        let result = tokio::select! {
            biased;

            result = tokio::io::copy(&mut ar, &mut bw) => {
                let _ = bw.shutdown().await;
                result.map(|_| ())
            }
            result = tokio::io::copy(&mut br, &mut aw) => {
                let _ = aw.shutdown().await;
                result.map(|_| ())
            }
        };

        if let Err(ref e) = result {
            if e.kind() != std::io::ErrorKind::ConnectionReset
                && e.kind() != std::io::ErrorKind::BrokenPipe
                && !e.to_string().contains("connection")
            {
                tracing::debug!("Relay error: {}", e);
            }
        }

        Ok(())
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    (0..data.len().saturating_sub(3)).find(|&i| &data[i..i + 4] == b"\r\n\r\n")
}
