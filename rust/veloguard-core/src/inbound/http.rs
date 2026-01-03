use crate::config::InboundConfig;
use crate::connection_tracker::{TrackedConnection, global_tracker};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// HTTP proxy inbound listener
pub struct HttpInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl InboundListener for HttpInbound {
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

impl HttpInbound {
    pub fn new(config: InboundConfig, router: Arc<Router>, outbound_manager: Arc<OutboundManager>) -> Self {
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
            tracing::warn!("HTTP inbound already running on {}:{}", self.config.listen, self.config.port);
            return Ok(());
        }

        let addr: SocketAddr = format!("{}:{}", self.config.listen, self.config.port)
            .parse()
            .map_err(|e| Error::config(format!("Invalid listen address: {}", e)))?;

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
            .map_err(|e| Error::network(format!("Failed to bind HTTP listener to {}: {}", addr, e)))?;
        
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
                        tracing::info!("HTTP inbound on {} shutting down", addr);
                        break;
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                let router = Arc::clone(&router);
                                let outbound_manager = Arc::clone(&outbound_manager);
                                tokio::spawn(async move {
                                    if let Err(err) = Self::handle_connection(stream, peer_addr, router, outbound_manager).await {
                                        tracing::debug!("HTTP connection error from {}: {}", peer_addr, err);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("HTTP accept error: {}", e);
                            }
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("HTTP inbound on {} stopped", addr);
        });

        tracing::info!("HTTP inbound listening on {}", addr);
        Ok(())
    }

    async fn stop_listener(&self) -> Result<()> {
        tracing::info!("Stopping HTTP inbound on {}:{}", self.config.listen, self.config.port);
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
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        let io = TokioIo::new(stream);

        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let router = Arc::clone(&router);
            let outbound_manager = Arc::clone(&outbound_manager);
            async move {
                Self::handle_request(req, peer_addr, router, outbound_manager).await
            }
        });

        if let Err(err) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
        {
            if !err.to_string().contains("connection closed") {
                tracing::debug!("HTTP serve error: {}", err);
            }
        }

        Ok(())
    }

    async fn handle_request(
        req: Request<hyper::body::Incoming>,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> std::result::Result<Response<BoxBody<Bytes, std::io::Error>>, std::convert::Infallible> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        
        tracing::debug!("HTTP {} {} from {}", method, uri, peer_addr);

        // Handle CONNECT method for HTTPS tunneling
        if method == Method::CONNECT {
            return Ok(Self::handle_connect(req, router, outbound_manager).await);
        }

        // Handle regular HTTP proxy request
        match Self::handle_http_proxy(req, router, outbound_manager).await {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::error!("HTTP proxy error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("Proxy error: {}", e)))
                        .map_err(|_| std::io::Error::other("body error"))
                        .boxed())
                    .unwrap())
            }
        }
    }

    async fn handle_connect(
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
                    .body(Full::new(Bytes::from("Invalid CONNECT request"))
                        .map_err(|_| std::io::Error::other("body error"))
                        .boxed())
                    .unwrap();
            }
        };

        let outbound_tag = router.match_outbound(
            Some(&host),
            None,
            Some(port),
            None,
        ).await;

        tracing::info!("CONNECT {}:{} -> {}", host, port, outbound_tag);

        // Get the outbound proxy
        let outbound = match outbound_manager.get_proxy(&outbound_tag) {
            Some(proxy) => proxy,
            None => {
                tracing::error!("Outbound '{}' not found", outbound_tag);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("Outbound '{}' not found", outbound_tag)))
                        .map_err(|_| std::io::Error::other("body error"))
                        .boxed())
                    .unwrap();
            }
        };

        // Spawn the relay task using the outbound proxy
        let target = TargetAddr::new_domain(host.clone(), port);
        let outbound_tag_clone = outbound_tag.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let upgraded = TokioIo::new(upgraded);
                    
                    // Track the connection
                    let tracked_conn = TrackedConnection::new(
                        "http".to_string(),
                        outbound_tag_clone.clone(),
                        host.clone(),
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
                    if let Err(e) = outbound.relay_tcp_with_connection(Box::new(upgraded), target, Some(conn_arc)).await {
                        // Only log if it's not a normal connection close
                        if !e.to_string().contains("connection") {
                            tracing::debug!("CONNECT relay error via '{}': {}", outbound.tag(), e);
                        }
                    }
                    // Untrack the connection
                    tracker.untrack(&tracked.id);
                }
                Err(e) => {
                    // Upgrade failures are common when clients disconnect
                    tracing::debug!("HTTP upgrade failed: {}", e);
                }
            }
        });

        // Return 200 OK to indicate tunnel is established
        Response::builder()
            .status(StatusCode::OK)
            .body(Empty::new().map_err(|_| std::io::Error::other("empty")).boxed())
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

        let outbound_tag = router.match_outbound(
            Some(&host),
            None,
            Some(port),
            None,
        ).await;

        tracing::info!("HTTP {} -> {}", uri, outbound_tag);

        // Get the outbound proxy
        let outbound = outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        // Build the HTTP request to send to the target
        let method = req.method().clone();
        let path = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        
        let mut request_bytes = Vec::new();
        request_bytes.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());

        // Forward headers, excluding proxy-specific ones
        for (key, value) in req.headers() {
            let key_lower = key.as_str().to_lowercase();
            if key_lower != "proxy-connection" && key_lower != "proxy-authorization" {
                request_bytes.extend_from_slice(format!("{}: {}\r\n", key, value.to_str().unwrap_or("")).as_bytes());
            }
        }
        request_bytes.extend_from_slice(b"\r\n");

        let body = req.into_body();
        let body_bytes = body.collect().await
            .map_err(|e| Error::network(format!("Failed to read request body: {}", e)))?
            .to_bytes();
        
        if !body_bytes.is_empty() {
            request_bytes.extend_from_slice(&body_bytes);
        }

        // For plain HTTP proxy, we use a duplex stream but handle it differently
        // The key is to shutdown the write side AFTER writing the request
        // This signals EOF to relay_tcp's client_to_remote, allowing it to send the request
        let target = TargetAddr::new_domain(host.clone(), port);
        
        // Create duplex stream for bidirectional communication
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        
        // Spawn the outbound relay task
        let relay_handle = tokio::spawn(async move {
            outbound.relay_tcp(Box::new(server_side), target).await
        });
        
        // Use the client side to send request and receive response
        let (mut read_half, mut write_half) = tokio::io::split(client_side);
        
        // Write the HTTP request and then shutdown write side to signal end of request
        write_half.write_all(&request_bytes).await
            .map_err(|e| Error::network(format!("Failed to write request: {}", e)))?;
        
        // Shutdown write side to signal EOF to relay_tcp
        // This allows client_to_remote to complete and send the request to remote server
        write_half.shutdown().await
            .map_err(|e| Error::network(format!("Failed to shutdown write: {}", e)))?;
        
        // Read the response with a timeout
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
                read_half.read(&mut temp_buf)
            ).await;
            
            match read_result {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => {
                    response_buf.extend_from_slice(&temp_buf[..n]);
                    
                    // Check if we've received complete headers
                    if !headers_complete {
                        if let Some(header_end) = find_header_end(&response_buf) {
                            headers_complete = true;
                            // Parse Content-Length if present
                            let headers_str = String::from_utf8_lossy(&response_buf[..header_end]);
                            for line in headers_str.lines() {
                                if line.to_lowercase().starts_with("content-length:") {
                                    if let Some(len_str) = line.split(':').nth(1) {
                                        content_length = len_str.trim().parse().ok();
                                    }
                                }
                            }
                            body_read = response_buf.len() - header_end - 4; // 4 for \r\n\r\n
                        }
                    } else {
                        body_read += n;
                    }
                    
                    // Check if we've received the complete response
                    if headers_complete {
                        if let Some(cl) = content_length {
                            if body_read >= cl {
                                break;
                            }
                        } else {
                            // No Content-Length, check for Connection: close or chunked encoding
                            // For simplicity, continue reading until timeout or EOF
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!("Read error: {}", e);
                    break;
                }
                Err(_) => {
                    // Timeout - if we have headers, we might have the complete response
                    if headers_complete && !response_buf.is_empty() {
                        break;
                    }
                }
            }
        }
        
        // Cleanup - relay_handle should complete when remote closes connection
        let _ = relay_handle.await;

        if response_buf.is_empty() {
            return Err(Error::network("No response received from server"));
        }

        // Parse the response status from the raw data
        let response_str = String::from_utf8_lossy(&response_buf);
        let status_code = if let Some(first_line) = response_str.lines().next() {
            // Parse "HTTP/1.1 200 OK" format
            first_line.split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200)
        } else {
            200
        };

        Ok(Response::builder()
            .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK))
            .body(Full::new(Bytes::from(response_buf))
                .map_err(|_| std::io::Error::other("body error"))
                .boxed())
            .unwrap())
    }

    fn parse_connect_uri(uri: &Uri) -> Option<(String, u16)> {
        if let Some(authority) = uri.authority() {
            let host = authority.host().to_string();
            let port = authority.port_u16().unwrap_or(443);
            return Some((host, port));
        }
        
        // Some clients send path as host:port
        let path = uri.path().trim_start_matches('/');
        if let Some((host, port_str)) = path.rsplit_once(':') {
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

    #[allow(dead_code)]
    async fn relay<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);

        // Use tokio::select with biased to handle both directions properly
        // When one direction finishes, we need to properly shutdown the other
        let result = tokio::select! {
            biased;
            
            result = tokio::io::copy(&mut ar, &mut bw) => {
                // Client to server finished, shutdown server write side
                let _ = bw.shutdown().await;
                result.map(|_| ())
            }
            result = tokio::io::copy(&mut br, &mut aw) => {
                // Server to client finished, shutdown client write side
                let _ = aw.shutdown().await;
                result.map(|_| ())
            }
        };

        // Log any relay errors at debug level (connection closures are normal)
        if let Err(ref e) = result {
            if e.kind() != std::io::ErrorKind::ConnectionReset 
               && e.kind() != std::io::ErrorKind::BrokenPipe
               && !e.to_string().contains("connection") {
                tracing::debug!("Relay error: {}", e);
            }
        }

        Ok(())
    }
}

/// Find the end of HTTP headers (position of \r\n\r\n)
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i+4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}
