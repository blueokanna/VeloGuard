use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use tokio::io::AsyncWriteExt;

pub struct DirectOutbound {
    config: OutboundConfig,
}

#[async_trait::async_trait]
impl OutboundProxy for DirectOutbound {
    async fn connect(&self) -> Result<()> {
        // Direct outbound doesn't need to maintain persistent connections
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        // Nothing to disconnect
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
    
    fn server_addr(&self) -> Option<(String, u16)> {
        // Direct outbound has no server
        None
    }
    
    fn supports_udp(&self) -> bool {
        true
    }
    
    async fn relay_udp_packet(
        &self,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        use tokio::net::UdpSocket;
        use std::time::Duration;
        
        // Resolve target address
        let target_addr = match target {
            TargetAddr::Ip(addr) => *addr,
            TargetAddr::Domain(domain, port) => {
                let addr_str = format!("{}:{}", domain, port);
                let resolved = tokio::net::lookup_host(&addr_str)
                    .await
                    .map_err(|e| Error::network(format!("Failed to resolve {}: {}", domain, e)))?
                    .next()
                    .ok_or_else(|| Error::network(format!("No address found for {}", domain)))?;
                resolved
            }
        };
        
        // Create UDP socket and connect to target for better performance
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;
        
        // Connect the socket to the target for connected UDP semantics
        socket.connect(target_addr).await
            .map_err(|e| Error::network(format!("Failed to connect UDP socket: {}", e)))?;
        
        // Send data using connected socket
        socket.send(data).await
            .map_err(|e| Error::network(format!("Failed to send UDP packet: {}", e)))?;
        
        // Receive response with timeout - use shorter timeout for QUIC compatibility
        let mut buf = vec![0u8; 65535];
        let timeout = Duration::from_secs(5);
        
        match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => Ok(buf[..n].to_vec()),
            Ok(Err(e)) => {
                // For QUIC, some packets may not have immediate responses
                tracing::debug!("UDP recv error (may be normal for QUIC): {}", e);
                Ok(Vec::new())
            },
            Err(_) => {
                // Timeout is normal for QUIC - not all packets expect responses
                tracing::debug!("UDP response timeout (normal for QUIC one-way packets)");
                Ok(Vec::new())
            },
        }
    }
    
    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;
        use tokio::io::{AsyncBufReadExt, BufReader};
        
        // Parse the test URL
        let url = url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;
        
        let host = url.host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() { "/" } else { url.path() };
        
        let start = Instant::now();
        
        // Direct connection to target with protection
        let addr = format!("{}:{}", host, url_port);
        let mut stream = crate::socket_protect::connect_protected_timeout(&addr, timeout)
            .await
            .map_err(|e| Error::network(format!("Failed to connect: {}", e)))?;
        
        // Send HTTP request
        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
            path, host, crate::USER_AGENT
        );
        stream.write_all(http_request.as_bytes()).await
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {}", e)))?;
        
        // Read HTTP response
        let result = tokio::time::timeout(timeout, async {
            let mut reader = BufReader::new(stream);
            let mut response_line = String::new();
            reader.read_line(&mut response_line).await
                .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?;
            
            if response_line.starts_with("HTTP/") {
                Ok(())
            } else {
                Err(Error::network("Invalid HTTP response"))
            }
        }).await;
        
        match result {
            Ok(Ok(())) => Ok(start.elapsed()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::network("Response timeout")),
        }
    }
    
    async fn relay_tcp(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
    ) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None).await
    }
    
    async fn relay_tcp_with_connection(
        &self,
        mut inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        use crate::connection_tracker::global_tracker;
        
        // Connect directly to target
        let target_str = target.to_string();
        
        // Use protected connection on Android to prevent routing loop
        let mut outbound = crate::socket_protect::connect_protected(&target_str)
            .await
            .map_err(|e| Error::network(format!("Direct connect to {} failed: {}", target_str, e)))?;
        
        // Disable Nagle's algorithm
        outbound.set_nodelay(true).ok();
        
        tracing::debug!("Direct connection to {} established", target_str);
        
        // Relay data bidirectionally with traffic tracking
        let tracker = global_tracker();
        let result = relay_bidirectional_with_connection(&mut inbound, &mut outbound, tracker, connection).await;
        
        // Cleanup
        let _ = outbound.shutdown().await;
        
        result
    }
}

impl DirectOutbound {
    pub fn new(config: OutboundConfig) -> Self {
        Self { config }
    }
}

/// Bidirectional relay between two streams with traffic statistics and optional connection tracking
pub async fn relay_bidirectional_with_connection<A, B>(
    a: &mut A, 
    b: &mut B,
    tracker: std::sync::Arc<crate::connection_tracker::ConnectionTracker>,
    connection: Option<std::sync::Arc<crate::connection_tracker::TrackedConnection>>,
) -> Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    
    let tracker_upload = tracker.clone();
    let tracker_download = tracker.clone();
    let conn_upload = connection.clone();
    let conn_download = connection.clone();

    let a_to_b = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match ar.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if is_connection_closed(&e) => break,
                Err(e) => return Err(e),
            };
            if let Err(e) = bw.write_all(&buf[..n]).await {
                if is_connection_closed(&e) { break; }
                return Err(e);
            }
            tracker_upload.add_global_upload(n as u64);
            if let Some(ref conn) = conn_upload {
                conn.add_upload(n as u64);
            }
        }
        let _ = bw.shutdown().await;
        Ok::<(), std::io::Error>(())
    };
    
    let b_to_a = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match br.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if is_connection_closed(&e) => break,
                Err(e) => return Err(e),
            };
            if let Err(e) = aw.write_all(&buf[..n]).await {
                if is_connection_closed(&e) { break; }
                return Err(e);
            }
            tracker_download.add_global_download(n as u64);
            if let Some(ref conn) = conn_download {
                conn.add_download(n as u64);
            }
        }
        let _ = aw.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    // Run both directions concurrently and wait for both to complete
    let (result_a, result_b) = tokio::join!(a_to_b, b_to_a);

    // Connection close errors are normal - don't propagate them
    match (result_a, result_b) {
        (Ok(_), Ok(_)) => Ok(()),
        (Ok(_), Err(e)) | (Err(e), Ok(_)) => {
            if is_connection_closed(&e) {
                Ok(())
            } else {
                tracing::debug!("Relay error (one direction): {}", e);
                Ok(())
            }
        }
        (Err(e1), Err(e2)) => {
            if is_connection_closed(&e1) && is_connection_closed(&e2) {
                Ok(())
            } else {
                tracing::debug!("Relay errors: {} / {}", e1, e2);
                Ok(())
            }
        }
    }
}

/// Check if an error indicates a normal connection close
fn is_connection_closed(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
    )
}

/// Bidirectional relay between two streams (without stats)
#[allow(dead_code)]
pub async fn relay_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let result = tokio::select! {
        biased;
        
        result = tokio::io::copy(&mut ar, &mut bw) => {
            let _ = bw.shutdown().await;
            result.map(|bytes| {
                tracing::trace!("Relay A->B completed: {} bytes", bytes);
                
            })
        }
        result = tokio::io::copy(&mut br, &mut aw) => {
            let _ = aw.shutdown().await;
            result.map(|bytes| {
                tracing::trace!("Relay B->A completed: {} bytes", bytes);
                
            })
        }
    };

    match result {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) if e.to_string().contains("connection") => Ok(()),
        Err(e) => Err(Error::network(format!("Relay error: {}", e))),
    }
}
