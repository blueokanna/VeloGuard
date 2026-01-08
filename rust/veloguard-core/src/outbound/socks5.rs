use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use crate::outbound::direct::relay_bidirectional_with_connection;
use crate::connection_tracker::global_tracker;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SOCKS5 outbound proxy
pub struct Socks5Outbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

#[async_trait::async_trait]
impl OutboundProxy for Socks5Outbound {
    async fn connect(&self) -> Result<()> {
        // Test connection to SOCKS5 server (DNS resolution happens here)
        let addr = format!("{}:{}", self.server, self.port);
        let _stream = TcpStream::connect(&addr).await
            .map_err(|e| Error::network(format!("Failed to connect to SOCKS5 server {}: {}", addr, e)))?;
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        // SOCKS5 outbound doesn't maintain persistent connections
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
        use tokio::io::{AsyncBufReadExt, BufReader};
        
        // Parse the test URL to get host and port
        let url = url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;
        
        let host = url.host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() { "/" } else { url.path() };
        
        let start = Instant::now();
        
        // Connect to SOCKS5 server with protection
        let server_addr = format!("{}:{}", self.server, self.port);
        let mut stream = crate::socket_protect::connect_protected_timeout(&server_addr, timeout)
            .await
            .map_err(|e| Error::network(format!("Failed to connect: {}", e)))?;
        
        // Perform SOCKS5 handshake
        self.perform_handshake(&mut stream).await?;
        
        // Send CONNECT request
        let target = TargetAddr::Domain(host.clone(), url_port);
        self.send_connect_request_target(&mut stream, &target).await?;
        
        // Read response
        self.read_connect_response(&mut stream).await?;
        
        // Send HTTP request
        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: VeloGuard/1.0\r\n\r\n",
            path, host
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
        // Connect to SOCKS5 server
        let server_addr = format!("{}:{}", self.server, self.port);
        
        // Use protected connection on Android to prevent routing loop
        let mut outbound = crate::socket_protect::connect_protected(&server_addr)
            .await
            .map_err(|e| Error::network(format!("Failed to connect to SOCKS5 server {}: {}", server_addr, e)))?;
        
        tracing::debug!("SOCKS5: connected to {} for target {}", server_addr, target);
        
        // Perform SOCKS5 handshake
        self.perform_handshake(&mut outbound).await?;
        
        // Send CONNECT request with domain support
        self.send_connect_request_target(&mut outbound, &target).await?;
        
        // Read response
        self.read_connect_response(&mut outbound).await?;
        
        tracing::debug!("SOCKS5: tunnel established to {}", target);
        
        // Relay data with traffic tracking
        let tracker = global_tracker();
        let result = relay_bidirectional_with_connection(&mut inbound, &mut outbound, tracker, connection).await;
        
        let _ = outbound.shutdown().await;
        
        result
    }
}

impl Socks5Outbound {
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

    async fn perform_handshake(&self, stream: &mut TcpStream) -> Result<()> {
        // SOCKS5 initial handshake
        let handshake = if self.username.is_some() {
            // Support username/password auth
            vec![0x05, 0x02, 0x00, 0x02] // No auth and username/password
        } else {
            vec![0x05, 0x01, 0x00] // No auth only
        };
        
        stream.write_all(&handshake).await
            .map_err(|e| Error::network(format!("Failed to send SOCKS5 handshake: {}", e)))?;

        // Read response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 handshake response: {}", e)))?;

        if response[0] != 0x05 {
            return Err(Error::protocol("Invalid SOCKS5 version in response"));
        }

        match response[1] {
            0x00 => Ok(()), // No auth required
            0x02 => {
                // Username/password auth required
                if let (Some(user), Some(pass)) = (&self.username, &self.password) {
                    self.perform_auth(stream, user, pass).await
                } else {
                    Err(Error::protocol("SOCKS5 server requires auth but no credentials provided"))
                }
            }
            0xFF => Err(Error::protocol("SOCKS5 no acceptable auth method")),
            _ => Err(Error::protocol(format!("Unsupported SOCKS5 auth method: {}", response[1]))),
        }
    }
    
    async fn perform_auth(&self, stream: &mut TcpStream, username: &str, password: &str) -> Result<()> {
        // Username/password auth (RFC 1929)
        let mut auth = vec![0x01]; // Version
        auth.push(username.len() as u8);
        auth.extend_from_slice(username.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());
        
        stream.write_all(&auth).await
            .map_err(|e| Error::network(format!("Failed to send auth: {}", e)))?;
        
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await
            .map_err(|e| Error::network(format!("Failed to read auth response: {}", e)))?;
        
        if response[1] != 0x00 {
            return Err(Error::protocol("SOCKS5 authentication failed"));
        }
        
        Ok(())
    }
    
    async fn send_connect_request_target(&self, stream: &mut TcpStream, target: &TargetAddr) -> Result<()> {
        let mut request = vec![
            0x05, // Version
            0x01, // CONNECT command
            0x00, // Reserved
        ];

        match target {
            TargetAddr::Domain(domain, port) => {
                request.push(0x03); // Domain address type
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
                request.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    IpAddr::V4(ipv4) => {
                        request.push(0x01); // IPv4
                        request.extend_from_slice(&ipv4.octets());
                    }
                    IpAddr::V6(ipv6) => {
                        request.push(0x04); // IPv6
                        request.extend_from_slice(&ipv6.octets());
                    }
                }
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        stream.write_all(&request).await
            .map_err(|e| Error::network(format!("Failed to send SOCKS5 CONNECT: {}", e)))?;

        Ok(())
    }

    async fn read_connect_response(&self, stream: &mut TcpStream) -> Result<()> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 response: {}", e)))?;

        if header[0] != 0x05 {
            return Err(Error::protocol("Invalid SOCKS5 version in response"));
        }

        let status = header[1];
        if status != 0x00 {
            let error_msg = match status {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown error",
            };
            return Err(Error::network(format!("SOCKS5 CONNECT failed: {}", error_msg)));
        }

        // Skip bound address in response
        match header[3] {
            0x01 => { // IPv4
                let mut addr_port = [0u8; 6];
                stream.read_exact(&mut addr_port).await?;
            }
            0x04 => { // IPv6
                let mut addr_port = [0u8; 18];
                stream.read_exact(&mut addr_port).await?;
            }
            0x03 => { // Domain
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut addr_port = vec![0u8; len + 2];
                stream.read_exact(&mut addr_port).await?;
            }
            _ => return Err(Error::protocol("Unsupported address type in SOCKS5 response")),
        }

        Ok(())
    }
}
