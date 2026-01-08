//! WebSocket Transport - WebSocket-based transport layer
//! 
//! Provides WebSocket encapsulation for proxy traffic, useful for
//! bypassing HTTP-based firewalls and proxies.

use crate::error::{Error, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// WebSocket transport configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// WebSocket path (e.g., "/ws")
    pub path: String,
    /// Host header value
    pub host: Option<String>,
    /// Custom headers
    pub headers: std::collections::HashMap<String, String>,
    /// Enable TLS
    pub tls: bool,
    /// Max early data size for 0-RTT
    pub max_early_data: Option<usize>,
    /// Early data header name
    pub early_data_header: Option<String>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            headers: std::collections::HashMap::new(),
            tls: false,
            max_early_data: None,
            early_data_header: None,
        }
    }
}

/// WebSocket transport stream
pub struct WebSocketStream<S> {
    inner: S,
    read_buffer: Vec<u8>,
    read_pos: usize,
    #[allow(dead_code)]
    write_buffer: Vec<u8>,
    handshake_done: bool,
}

impl<S> WebSocketStream<S> {
    /// Create a new WebSocket stream wrapper
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buffer: Vec::new(),
            read_pos: 0,
            write_buffer: Vec::new(),
            handshake_done: false,
        }
    }

    /// Check if handshake is complete
    pub fn is_handshake_done(&self) -> bool {
        self.handshake_done
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketStream<S> {
    /// Perform WebSocket client handshake
    pub async fn client_handshake(&mut self, config: &WebSocketConfig) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Generate WebSocket key
        let key = generate_ws_key();
        
        // Build HTTP upgrade request
        let host = config.host.as_deref().unwrap_or("localhost");
        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n",
            config.path, host, key
        );

        // Add custom headers
        for (name, value) in &config.headers {
            request.push_str(&format!("{}: {}\r\n", name, value));
        }
        request.push_str("\r\n");

        // Send request
        self.inner.write_all(request.as_bytes()).await
            .map_err(|e| Error::network(format!("WebSocket handshake write failed: {}", e)))?;
        self.inner.flush().await
            .map_err(|e| Error::network(format!("WebSocket handshake flush failed: {}", e)))?;

        // Read response
        let mut response = vec![0u8; 1024];
        let mut total_read = 0;
        
        loop {
            let n = self.inner.read(&mut response[total_read..]).await
                .map_err(|e| Error::network(format!("WebSocket handshake read failed: {}", e)))?;
            
            if n == 0 {
                return Err(Error::network("WebSocket handshake: connection closed"));
            }
            
            total_read += n;
            
            // Check for end of HTTP headers
            if let Some(pos) = find_header_end(&response[..total_read]) {
                let response_str = String::from_utf8_lossy(&response[..pos]);
                
                // Verify response
                if !response_str.contains("101") || !response_str.to_lowercase().contains("upgrade") {
                    return Err(Error::protocol(format!(
                        "WebSocket handshake failed: {}",
                        response_str.lines().next().unwrap_or("unknown")
                    )));
                }
                
                // Store any remaining data after headers
                if total_read > pos + 4 {
                    self.read_buffer = response[pos + 4..total_read].to_vec();
                }
                
                break;
            }
            
            if total_read >= response.len() {
                return Err(Error::protocol("WebSocket handshake response too large"));
            }
        }

        self.handshake_done = true;
        Ok(())
    }

    /// Perform WebSocket server handshake
    pub async fn server_handshake(&mut self) -> Result<WebSocketConfig> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Read HTTP upgrade request
        let mut request = vec![0u8; 4096];
        let mut total_read = 0;
        
        loop {
            let n = self.inner.read(&mut request[total_read..]).await
                .map_err(|e| Error::network(format!("WebSocket server read failed: {}", e)))?;
            
            if n == 0 {
                return Err(Error::network("WebSocket server: connection closed"));
            }
            
            total_read += n;
            
            if let Some(pos) = find_header_end(&request[..total_read]) {
                let request_str = String::from_utf8_lossy(&request[..pos]);
                
                // Parse request
                let mut path = "/".to_string();
                let mut ws_key = String::new();
                let mut host = None;
                
                for line in request_str.lines() {
                    if line.starts_with("GET ") {
                        if let Some(p) = line.split_whitespace().nth(1) {
                            path = p.to_string();
                        }
                    } else if line.to_lowercase().starts_with("sec-websocket-key:") {
                        ws_key = line.split(':').nth(1).unwrap_or("").trim().to_string();
                    } else if line.to_lowercase().starts_with("host:") {
                        host = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                    }
                }
                
                if ws_key.is_empty() {
                    return Err(Error::protocol("Missing Sec-WebSocket-Key header"));
                }
                
                // Generate accept key
                let accept_key = generate_accept_key(&ws_key);
                
                // Send response
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {}\r\n\r\n",
                    accept_key
                );
                
                self.inner.write_all(response.as_bytes()).await
                    .map_err(|e| Error::network(format!("WebSocket server write failed: {}", e)))?;
                
                // Store any remaining data
                if total_read > pos + 4 {
                    self.read_buffer = request[pos + 4..total_read].to_vec();
                }
                
                self.handshake_done = true;
                
                return Ok(WebSocketConfig {
                    path,
                    host,
                    ..Default::default()
                });
            }
            
            if total_read >= request.len() {
                return Err(Error::protocol("WebSocket request too large"));
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First, drain any buffered data
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }
            
            return Poll::Ready(Ok(()));
        }

        // Read WebSocket frame header (simplified - binary frames only)
        let mut header = [0u8; 2];
        let mut header_buf = ReadBuf::new(&mut header);
        
        match Pin::new(&mut self.inner).poll_read(cx, &mut header_buf) {
            Poll::Ready(Ok(())) => {
                if header_buf.filled().len() < 2 {
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let payload_len = (header[1] & 0x7F) as usize;
        let masked = (header[1] & 0x80) != 0;

        // Handle extended payload length
        let actual_len = if payload_len == 126 {
            // Read 2 more bytes for length
            let mut ext_len = [0u8; 2];
            let mut ext_buf = ReadBuf::new(&mut ext_len);
            match Pin::new(&mut self.inner).poll_read(cx, &mut ext_buf) {
                Poll::Ready(Ok(())) => u16::from_be_bytes(ext_len) as usize,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        } else if payload_len == 127 {
            // Read 8 more bytes for length
            let mut ext_len = [0u8; 8];
            let mut ext_buf = ReadBuf::new(&mut ext_len);
            match Pin::new(&mut self.inner).poll_read(cx, &mut ext_buf) {
                Poll::Ready(Ok(())) => u64::from_be_bytes(ext_len) as usize,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        } else {
            payload_len
        };

        // Read mask if present
        let mask = if masked {
            let mut mask_bytes = [0u8; 4];
            let mut mask_buf = ReadBuf::new(&mut mask_bytes);
            match Pin::new(&mut self.inner).poll_read(cx, &mut mask_buf) {
                Poll::Ready(Ok(())) => Some(mask_bytes),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        } else {
            None
        };

        // Read payload
        let this = self.get_mut();
        let mut payload = vec![0u8; actual_len];
        let mut payload_buf = ReadBuf::new(&mut payload);
        
        match Pin::new(&mut this.inner).poll_read(cx, &mut payload_buf) {
            Poll::Ready(Ok(())) => {
                // Unmask if needed
                if let Some(mask) = mask {
                    for (i, byte) in payload.iter_mut().enumerate() {
                        *byte ^= mask[i % 4];
                    }
                }

                let to_copy = std::cmp::min(payload.len(), buf.remaining());
                buf.put_slice(&payload[..to_copy]);
                
                if to_copy < payload.len() {
                    this.read_buffer = payload[to_copy..].to_vec();
                    this.read_pos = 0;
                }
                
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Build WebSocket frame (binary, no mask for server->client)
        let mut frame = Vec::new();
        
        // FIN + Binary opcode
        frame.push(0x82);
        
        // Payload length
        if buf.len() < 126 {
            frame.push(buf.len() as u8);
        } else if buf.len() < 65536 {
            frame.push(126);
            frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(buf.len() as u64).to_be_bytes());
        }
        
        // Payload
        frame.extend_from_slice(buf);
        
        match Pin::new(&mut self.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Generate a random WebSocket key
fn generate_ws_key() -> String {
    use base64::Engine;
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).ok();
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Generate WebSocket accept key from client key
fn generate_accept_key(key: &str) -> String {
    use base64::Engine;
    use sha1::{Sha1, Digest};
    
    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let result = hasher.finalize();
    
    base64::engine::general_purpose::STANDARD.encode(result)
}

/// Find the end of HTTP headers (\r\n\r\n)
fn find_header_end(data: &[u8]) -> Option<usize> {
    (0..data.len().saturating_sub(3)).find(|&i| &data[i..i + 4] == b"\r\n\r\n")
}
