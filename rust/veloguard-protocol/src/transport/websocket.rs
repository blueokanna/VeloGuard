use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use futures::{Sink, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;

use super::{Result, TransportError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub max_early_data: usize,
    #[serde(default)]
    pub early_data_header: Option<String>,
}

fn default_path() -> String {
    "/".to_string()
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: default_path(),
            host: None,
            headers: HashMap::new(),
            max_early_data: 0,
            early_data_header: None,
        }
    }
}

pub struct WebSocketTransport {
    config: WebSocketConfig,
    server: String,
    port: u16,
    use_tls: bool,
}

impl WebSocketTransport {
    pub fn new(config: WebSocketConfig, server: &str, port: u16, use_tls: bool) -> Self {
        Self {
            config,
            server: server.to_string(),
            port,
            use_tls,
        }
    }

    pub async fn connect<S>(&self, stream: S) -> Result<WsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let scheme = if self.use_tls { "wss" } else { "ws" };
        let host = self.config.host.as_deref().unwrap_or(&self.server);
        let uri_str = format!("{}://{}:{}{}", scheme, host, self.port, self.config.path);
        
        let uri: Uri = uri_str.parse()
            .map_err(|e| TransportError::InvalidConfig(format!("Invalid WebSocket URI: {}", e)))?;

        let mut request = Request::builder()
            .uri(uri)
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_ws_key());

        for (key, value) in &self.config.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let request = request.body(())
            .map_err(|e| TransportError::InvalidConfig(format!("Failed to build request: {}", e)))?;

        let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream).await
            .map_err(|e| TransportError::Handshake(format!("WebSocket handshake failed: {}", e)))?;

        Ok(WsStream::new(ws_stream))
    }

    pub async fn connect_with_early_data<S>(&self, stream: S, early_data: &[u8]) -> Result<WsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if early_data.is_empty() || self.config.max_early_data == 0 {
            return self.connect(stream).await;
        }

        let scheme = if self.use_tls { "wss" } else { "ws" };
        let host = self.config.host.as_deref().unwrap_or(&self.server);
        
        let early_data_encoded = if early_data.len() <= self.config.max_early_data {
            base64::engine::general_purpose::STANDARD.encode(early_data)
        } else {
            base64::engine::general_purpose::STANDARD.encode(&early_data[..self.config.max_early_data])
        };

        let path_with_early_data = if let Some(ref header_name) = self.config.early_data_header {
            format!("{}?{}={}", self.config.path, header_name, early_data_encoded)
        } else {
            format!("{}?ed={}", self.config.path, early_data_encoded)
        };

        let uri_str = format!("{}://{}:{}{}", scheme, host, self.port, path_with_early_data);
        let uri: Uri = uri_str.parse()
            .map_err(|e| TransportError::InvalidConfig(format!("Invalid WebSocket URI: {}", e)))?;

        let mut request = Request::builder()
            .uri(uri)
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_ws_key());

        for (key, value) in &self.config.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let request = request.body(())
            .map_err(|e| TransportError::InvalidConfig(format!("Failed to build request: {}", e)))?;

        let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream).await
            .map_err(|e| TransportError::Handshake(format!("WebSocket handshake failed: {}", e)))?;

        Ok(WsStream::new(ws_stream))
    }

    pub fn config(&self) -> &WebSocketConfig {
        &self.config
    }
}

fn generate_ws_key() -> String {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).ok();
    base64::engine::general_purpose::STANDARD.encode(key)
}

pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

impl<S> WsStream<S> {
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }

    pub fn into_inner(self) -> WebSocketStream<S> {
        self.inner
    }
}

impl<S> WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn split(self) -> (WsSink<S>, WsReader<S>) {
        let (sink, stream) = self.inner.split();
        (WsSink::new(sink), WsReader::new(stream))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
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

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                match msg {
                    Message::Binary(data) => {
                        let to_copy = std::cmp::min(data.len(), buf.remaining());
                        buf.put_slice(&data[..to_copy]);
                        
                        if to_copy < data.len() {
                            self.read_buffer = data[to_copy..].to_vec();
                            self.read_pos = 0;
                        }
                        
                        Poll::Ready(Ok(()))
                    }
                    Message::Text(text) => {
                        let data = text.as_bytes();
                        let to_copy = std::cmp::min(data.len(), buf.remaining());
                        buf.put_slice(&data[..to_copy]);
                        
                        if to_copy < data.len() {
                            self.read_buffer = data[to_copy..].to_vec();
                            self.read_pos = 0;
                        }
                        
                        Poll::Ready(Ok(()))
                    }
                    Message::Ping(_) | Message::Pong(_) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Message::Close(_) => {
                        Poll::Ready(Ok(()))
                    }
                    Message::Frame(_) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Message::Binary(Bytes::copy_from_slice(buf));
                match Pin::new(&mut self.inner).start_send(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::other(e.to_string()))),
                }
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::other(e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct WsSink<S> {
    inner: SplitSink<WebSocketStream<S>, Message>,
}

impl<S> WsSink<S> {
    pub fn new(inner: SplitSink<WebSocketStream<S>, Message>) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsSink<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Message::Binary(Bytes::copy_from_slice(buf));
                match Pin::new(&mut self.inner).start_send(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::other(e.to_string()))),
                }
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::other(e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct WsReader<S> {
    inner: SplitStream<WebSocketStream<S>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

impl<S> WsReader<S> {
    pub fn new(inner: SplitStream<WebSocketStream<S>>) -> Self {
        Self {
            inner,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsReader<S> {
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

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                match msg {
                    Message::Binary(data) => {
                        let to_copy = std::cmp::min(data.len(), buf.remaining());
                        buf.put_slice(&data[..to_copy]);
                        
                        if to_copy < data.len() {
                            self.read_buffer = data[to_copy..].to_vec();
                            self.read_pos = 0;
                        }
                        
                        Poll::Ready(Ok(()))
                    }
                    Message::Text(text) => {
                        let data = text.as_bytes();
                        let to_copy = std::cmp::min(data.len(), buf.remaining());
                        buf.put_slice(&data[..to_copy]);
                        
                        if to_copy < data.len() {
                            self.read_buffer = data[to_copy..].to_vec();
                            self.read_pos = 0;
                        }
                        
                        Poll::Ready(Ok(()))
                    }
                    Message::Ping(_) | Message::Pong(_) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Message::Close(_) => {
                        Poll::Ready(Ok(()))
                    }
                    Message::Frame(_) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_config_default() {
        let config = WebSocketConfig::default();
        assert_eq!(config.path, "/");
        assert!(config.host.is_none());
        assert!(config.headers.is_empty());
        assert_eq!(config.max_early_data, 0);
        assert!(config.early_data_header.is_none());
    }

    #[test]
    fn test_websocket_transport_new() {
        let config = WebSocketConfig::default();
        let transport = WebSocketTransport::new(config, "example.com", 443, true);
        assert_eq!(transport.server, "example.com");
        assert_eq!(transport.port, 443);
        assert!(transport.use_tls);
    }

    #[test]
    fn test_websocket_config_with_headers() {
        let mut headers = HashMap::new();
        headers.insert("X-Custom-Header".to_string(), "value".to_string());
        
        let config = WebSocketConfig {
            path: "/ws".to_string(),
            host: Some("custom.host.com".to_string()),
            headers,
            max_early_data: 2048,
            early_data_header: Some("Sec-WebSocket-Protocol".to_string()),
        };
        
        assert_eq!(config.path, "/ws");
        assert_eq!(config.host, Some("custom.host.com".to_string()));
        assert_eq!(config.headers.get("X-Custom-Header"), Some(&"value".to_string()));
        assert_eq!(config.max_early_data, 2048);
    }

    #[test]
    fn test_websocket_config_serialization() {
        let config = WebSocketConfig {
            path: "/test".to_string(),
            host: Some("test.com".to_string()),
            headers: HashMap::new(),
            max_early_data: 1024,
            early_data_header: None,
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: WebSocketConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.path, config.path);
        assert_eq!(deserialized.host, config.host);
        assert_eq!(deserialized.max_early_data, config.max_early_data);
    }

    #[test]
    fn test_generate_ws_key() {
        let key1 = generate_ws_key();
        let key2 = generate_ws_key();
        
        assert_ne!(key1, key2);
        assert!(!key1.is_empty());
        
        let decoded = base64::engine::general_purpose::STANDARD.decode(&key1).unwrap();
        assert_eq!(decoded.len(), 16);
    }
}
