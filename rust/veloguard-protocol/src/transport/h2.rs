use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::client::{self, SendRequest};
use http::{Method, Request, Uri};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Result, TransportError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2Config {
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default = "default_method")]
    pub method: String,
}

fn default_path() -> String {
    "/".to_string()
}

fn default_method() -> String {
    "POST".to_string()
}

impl Default for H2Config {
    fn default() -> Self {
        Self {
            path: default_path(),
            host: None,
            headers: HashMap::new(),
            method: default_method(),
        }
    }
}

pub struct H2Transport {
    config: H2Config,
    server: String,
    port: u16,
}

impl H2Transport {
    pub fn new(config: H2Config, server: &str, port: u16) -> Self {
        Self {
            config,
            server: server.to_string(),
            port,
        }
    }

    pub async fn connect<S>(&self, stream: S) -> Result<H2Stream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send_request, connection) = client::handshake(stream).await
            .map_err(|e| TransportError::Handshake(format!("H2 handshake failed: {}", e)))?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("H2 connection error: {}", e);
            }
        });

        let host = self.config.host.as_deref().unwrap_or(&self.server);
        let uri_str = format!("https://{}:{}{}", host, self.port, self.config.path);
        let uri: Uri = uri_str.parse()
            .map_err(|e| TransportError::InvalidConfig(format!("Invalid H2 URI: {}", e)))?;

        let method = self.config.method.parse::<Method>()
            .map_err(|e| TransportError::InvalidConfig(format!("Invalid HTTP method: {}", e)))?;

        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", host);

        for (key, value) in &self.config.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let request = request.body(())
            .map_err(|e| TransportError::InvalidConfig(format!("Failed to build request: {}", e)))?;

        Ok(H2Stream::new(send_request, request))
    }

    pub fn config(&self) -> &H2Config {
        &self.config
    }
}

pub struct H2Stream {
    send_request: SendRequest<Bytes>,
    request_template: Request<()>,
    send_stream: Option<h2::SendStream<Bytes>>,
    recv_stream: Option<h2::RecvStream>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    initialized: bool,
}

impl H2Stream {
    pub fn new(send_request: SendRequest<Bytes>, request_template: Request<()>) -> Self {
        Self {
            send_request,
            request_template,
            send_stream: None,
            recv_stream: None,
            read_buffer: Vec::new(),
            read_pos: 0,
            initialized: false,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        self.send_request.clone().ready().await
            .map_err(|e| TransportError::H2(format!("H2 not ready: {}", e)))?;

        let request = Request::builder()
            .method(self.request_template.method().clone())
            .uri(self.request_template.uri().clone())
            .body(())
            .map_err(|e| TransportError::InvalidConfig(format!("Failed to build request: {}", e)))?;

        let (response, send_stream) = self.send_request.clone().send_request(request, false)
            .map_err(|e| TransportError::H2(format!("Failed to send H2 request: {}", e)))?;

        self.send_stream = Some(send_stream);

        let response = response.await
            .map_err(|e| TransportError::H2(format!("Failed to get H2 response: {}", e)))?;

        let (_, recv_stream) = response.into_parts();
        self.recv_stream = Some(recv_stream);
        self.initialized = true;

        Ok(())
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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

        let recv_stream = match self.recv_stream.as_mut() {
            Some(s) => s,
            None => return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2 stream not initialized"
            ))),
        };

        match Pin::new(recv_stream).poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                
                if to_copy < data.len() {
                    self.read_buffer = data[to_copy..].to_vec();
                    self.read_pos = 0;
                }
                
                if let Some(ref mut recv) = self.recv_stream {
                    let _ = recv.flow_control().release_capacity(data.len());
                }
                
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(e.to_string())))
            }
            Poll::Ready(None) => {
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let send_stream = match self.send_stream.as_mut() {
            Some(s) => s,
            None => return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2 stream not initialized"
            ))),
        };

        let data = Bytes::copy_from_slice(buf);
        match send_stream.send_data(data, false) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(io::Error::other(e.to_string()))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(ref mut send_stream) = self.send_stream {
            let _ = send_stream.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2_config_default() {
        let config = H2Config::default();
        assert_eq!(config.path, "/");
        assert!(config.host.is_none());
        assert!(config.headers.is_empty());
        assert_eq!(config.method, "POST");
    }

    #[test]
    fn test_h2_transport_new() {
        let config = H2Config::default();
        let transport = H2Transport::new(config, "example.com", 443);
        assert_eq!(transport.server, "example.com");
        assert_eq!(transport.port, 443);
    }

    #[test]
    fn test_h2_config_with_headers() {
        let mut headers = HashMap::new();
        headers.insert("X-Custom-Header".to_string(), "value".to_string());
        headers.insert("Authorization".to_string(), "Bearer token".to_string());
        
        let config = H2Config {
            path: "/api/stream".to_string(),
            host: Some("api.example.com".to_string()),
            headers,
            method: "PUT".to_string(),
        };
        
        assert_eq!(config.path, "/api/stream");
        assert_eq!(config.host, Some("api.example.com".to_string()));
        assert_eq!(config.headers.len(), 2);
        assert_eq!(config.method, "PUT");
    }

    #[test]
    fn test_h2_config_serialization() {
        let config = H2Config {
            path: "/test".to_string(),
            host: Some("test.com".to_string()),
            headers: HashMap::new(),
            method: "POST".to_string(),
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: H2Config = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.path, config.path);
        assert_eq!(deserialized.host, config.host);
        assert_eq!(deserialized.method, config.method);
    }
}
