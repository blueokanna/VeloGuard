use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use crate::outbound::direct::relay_bidirectional_with_connection;
use crate::connection_tracker::global_tracker;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// HTTP outbound proxy (HTTP CONNECT tunnel)
pub struct HttpOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

#[async_trait::async_trait]
impl OutboundProxy for HttpOutbound {
    async fn connect(&self) -> Result<()> {
        // Test connection to HTTP proxy server
        let addr = format!("{}:{}", self.server, self.port);
        let _stream = TcpStream::connect(&addr).await
            .map_err(|e| Error::network(format!("Failed to connect to HTTP proxy {}: {}", addr, e)))?;
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
    
    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
    
    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;
        
        // Parse the test URL to get host and port
        let url = url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;
        
        let host = url.host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() { "/" } else { url.path() };
        
        let start = Instant::now();
        
        // Connect to HTTP proxy with protection
        let server_addr = format!("{}:{}", self.server, self.port);
        let mut stream = crate::socket_protect::connect_protected_timeout(&server_addr, timeout)
            .await
            .map_err(|e| Error::network(format!("Failed to connect: {}", e)))?;
        
        // Send CONNECT request to establish tunnel
        let target_str = format!("{}:{}", host, url_port);
        let mut connect_request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            target_str, target_str
        );
        
        // Add proxy auth if configured
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            use base64::Engine;
            let credentials = format!("{}:{}", user, pass);
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
            connect_request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        connect_request.push_str("\r\n");
        
        stream.write_all(connect_request.as_bytes()).await
            .map_err(|e| Error::network(format!("Failed to send CONNECT: {}", e)))?;
        
        // Read CONNECT response
        let mut reader = BufReader::new(&mut stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await
            .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?;
        
        if !response_line.contains("200") {
            return Err(Error::network(format!("CONNECT failed: {}", response_line.trim())));
        }
        
        // Skip headers
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await
                .map_err(|e| Error::network(format!("Failed to read headers: {}", e)))?;
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        
        // Now send HTTP request through the tunnel
        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: VeloGuard/1.0\r\n\r\n",
            path, host
        );
        
        // Get the underlying stream back
        let stream = reader.into_inner();
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
        // Connect to HTTP proxy
        let server_addr = format!("{}:{}", self.server, self.port);
        
        // Use protected connection on Android to prevent routing loop
        let outbound = crate::socket_protect::connect_protected(&server_addr)
            .await
            .map_err(|e| Error::network(format!("Failed to connect to HTTP proxy {}: {}", server_addr, e)))?;
        
        tracing::debug!("HTTP proxy: connected to {} for target {}", server_addr, target);
        
        // Send CONNECT request
        let target_str = target.to_string();
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            target_str, target_str
        );
        
        // Add proxy auth if configured
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            use base64::Engine;
            let credentials = format!("{}:{}", user, pass);
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        
        request.push_str("\r\n");
        
        let mut outbound = outbound;
        outbound.write_all(request.as_bytes()).await.map_err(|e| {
            Error::network(format!("Failed to send CONNECT request: {}", e))
        })?;
        
        // Read response
        let mut reader = BufReader::new(&mut outbound);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.map_err(|e| {
            Error::network(format!("Failed to read proxy response: {}", e))
        })?;
        
        // Parse response status
        let parts: Vec<&str> = response_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::protocol("Invalid HTTP proxy response"));
        }
        
        let status_code: u16 = parts[1].parse().map_err(|_| {
            Error::protocol(format!("Invalid status code: {}", parts[1]))
        })?;
        
        if status_code != 200 {
            return Err(Error::network(format!(
                "HTTP CONNECT failed with status {}: {}",
                status_code,
                parts.get(2..).map(|p| p.join(" ")).unwrap_or_default()
            )));
        }
        
        // Skip remaining headers (read until empty line)
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }
        
        // Get the stream back from the reader
        let outbound = reader.into_inner();
        let mut outbound = outbound;
        
        tracing::debug!("HTTP proxy: tunnel established to {}", target);
        
        // Relay data with traffic tracking
        let tracker = global_tracker();
        let result = relay_bidirectional_with_connection(&mut inbound, &mut outbound, tracker, connection).await;
        
        let _ = outbound.shutdown().await;
        
        result
    }
}

impl HttpOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config.server.as_ref()
            .ok_or_else(|| Error::config("Missing server address"))?
            .clone();

        let port = config.port
            .ok_or_else(|| Error::config("Missing port"))?;
        
        let username = config.options.get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
            
        let password = config.options.get("password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(Self {
            config,
            server,
            port,
            username,
            password,
        })
    }
}
