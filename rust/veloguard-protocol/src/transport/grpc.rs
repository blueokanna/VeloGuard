use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::client::{self, SendRequest};
use http::{Method, Request, Uri};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Result, TransportError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GrpcMode {
    #[default]
    Gun,
    Multi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    #[serde(default = "default_service_name")]
    pub service_name: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub mode: GrpcMode,
}

fn default_service_name() -> String {
    "GunService".to_string()
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            host: None,
            headers: HashMap::new(),
            mode: GrpcMode::Gun,
        }
    }
}

pub struct GrpcTransport {
    config: GrpcConfig,
    server: String,
    port: u16,
}

impl GrpcTransport {
    pub fn new(config: GrpcConfig, server: &str, port: u16) -> Self {
        Self {
            config,
            server: server.to_string(),
            port,
        }
    }

    pub async fn connect<S>(&self, stream: S) -> Result<GrpcStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send_request, connection) = client::handshake(stream).await
            .map_err(|e| TransportError::Handshake(format!("gRPC handshake failed: {}", e)))?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("gRPC connection error: {}", e);
            }
        });

        let host = self.config.host.as_deref().unwrap_or(&self.server);
        
        let path = match self.config.mode {
            GrpcMode::Gun => format!("/{}/Tun", self.config.service_name),
            GrpcMode::Multi => format!("/{}/TunMulti", self.config.service_name),
        };
        
        let uri_str = format!("https://{}:{}{}", host, self.port, path);
        let uri: Uri = uri_str.parse()
            .map_err(|e| TransportError::InvalidConfig(format!("Invalid gRPC URI: {}", e)))?;

        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("host", host)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("grpc-accept-encoding", "identity")
            .header("accept-encoding", "identity");

        for (key, value) in &self.config.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let request = request.body(())
            .map_err(|e| TransportError::InvalidConfig(format!("Failed to build request: {}", e)))?;

        Ok(GrpcStream::new(send_request, request, self.config.mode))
    }

    pub fn config(&self) -> &GrpcConfig {
        &self.config
    }
}

pub struct GrpcStream {
    send_request: SendRequest<Bytes>,
    request_template: Request<()>,
    #[allow(dead_code)]
    mode: GrpcMode,
    send_stream: Option<h2::SendStream<Bytes>>,
    recv_stream: Option<h2::RecvStream>,
    read_buffer: BytesMut,
    initialized: bool,
}

impl GrpcStream {
    pub fn new(send_request: SendRequest<Bytes>, request_template: Request<()>, mode: GrpcMode) -> Self {
        Self {
            send_request,
            request_template,
            mode,
            send_stream: None,
            recv_stream: None,
            read_buffer: BytesMut::new(),
            initialized: false,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        self.send_request.clone().ready().await
            .map_err(|e| TransportError::Grpc(format!("gRPC not ready: {}", e)))?;

        let request = Request::builder()
            .method(self.request_template.method().clone())
            .uri(self.request_template.uri().clone())
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .map_err(|e| TransportError::InvalidConfig(format!("Failed to build request: {}", e)))?;

        let (response, send_stream) = self.send_request.clone().send_request(request, false)
            .map_err(|e| TransportError::Grpc(format!("Failed to send gRPC request: {}", e)))?;

        self.send_stream = Some(send_stream);

        let response = response.await
            .map_err(|e| TransportError::Grpc(format!("Failed to get gRPC response: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(TransportError::Grpc(format!("gRPC response status: {}", status)));
        }

        let (_, recv_stream) = response.into_parts();
        self.recv_stream = Some(recv_stream);
        self.initialized = true;

        Ok(())
    }

    fn encode_grpc_frame(data: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + data.len());
        buf.put_u8(0);
        buf.put_u32(data.len() as u32);
        buf.put_slice(data);
        buf.freeze()
    }

    fn try_decode_grpc_frame(buf: &mut BytesMut) -> Option<Bytes> {
        if buf.len() < 5 {
            return None;
        }

        let _compressed = buf[0];
        let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

        if buf.len() < 5 + length {
            return None;
        }

        buf.advance(5);
        Some(buf.split_to(length).freeze())
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(data) = Self::try_decode_grpc_frame(&mut self.read_buffer) {
            let to_copy = std::cmp::min(data.len(), buf.remaining());
            buf.put_slice(&data[..to_copy]);
            
            if to_copy < data.len() {
                let remaining = &data[to_copy..];
                let mut new_buf = BytesMut::with_capacity(5 + remaining.len());
                new_buf.put_u8(0);
                new_buf.put_u32(remaining.len() as u32);
                new_buf.put_slice(remaining);
                new_buf.unsplit(self.read_buffer.split());
                self.read_buffer = new_buf;
            }
            
            return Poll::Ready(Ok(()));
        }

        let recv_stream = match self.recv_stream.as_mut() {
            Some(s) => s,
            None => return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "gRPC stream not initialized"
            ))),
        };

        match Pin::new(recv_stream).poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                self.read_buffer.extend_from_slice(&data);
                
                if let Some(ref mut recv) = self.recv_stream {
                    let _ = recv.flow_control().release_capacity(data.len());
                }

                if let Some(frame_data) = Self::try_decode_grpc_frame(&mut self.read_buffer) {
                    let to_copy = std::cmp::min(frame_data.len(), buf.remaining());
                    buf.put_slice(&frame_data[..to_copy]);
                    
                    if to_copy < frame_data.len() {
                        let remaining = &frame_data[to_copy..];
                        let mut new_buf = BytesMut::with_capacity(5 + remaining.len());
                        new_buf.put_u8(0);
                        new_buf.put_u32(remaining.len() as u32);
                        new_buf.put_slice(remaining);
                        new_buf.unsplit(self.read_buffer.split());
                        self.read_buffer = new_buf;
                    }
                    
                    Poll::Ready(Ok(()))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(e.to_string())))
            }
            Poll::Ready(None) => {
                if !self.read_buffer.is_empty() {
                    if let Some(frame_data) = Self::try_decode_grpc_frame(&mut self.read_buffer) {
                        let to_copy = std::cmp::min(frame_data.len(), buf.remaining());
                        buf.put_slice(&frame_data[..to_copy]);
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let send_stream = match self.send_stream.as_mut() {
            Some(s) => s,
            None => return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "gRPC stream not initialized"
            ))),
        };

        let frame = Self::encode_grpc_frame(buf);
        match send_stream.send_data(frame, false) {
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
    fn test_grpc_config_default() {
        let config = GrpcConfig::default();
        assert_eq!(config.service_name, "GunService");
        assert!(config.host.is_none());
        assert!(config.headers.is_empty());
        assert_eq!(config.mode, GrpcMode::Gun);
    }

    #[test]
    fn test_grpc_transport_new() {
        let config = GrpcConfig::default();
        let transport = GrpcTransport::new(config, "example.com", 443);
        assert_eq!(transport.server, "example.com");
        assert_eq!(transport.port, 443);
    }

    #[test]
    fn test_grpc_config_with_multi_mode() {
        let config = GrpcConfig {
            service_name: "CustomService".to_string(),
            host: Some("grpc.example.com".to_string()),
            headers: HashMap::new(),
            mode: GrpcMode::Multi,
        };
        
        assert_eq!(config.service_name, "CustomService");
        assert_eq!(config.mode, GrpcMode::Multi);
    }

    #[test]
    fn test_grpc_config_serialization() {
        let config = GrpcConfig {
            service_name: "TestService".to_string(),
            host: Some("test.com".to_string()),
            headers: HashMap::new(),
            mode: GrpcMode::Gun,
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: GrpcConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.service_name, config.service_name);
        assert_eq!(deserialized.host, config.host);
        assert_eq!(deserialized.mode, config.mode);
    }

    #[test]
    fn test_encode_grpc_frame() {
        let data = b"hello";
        let frame = GrpcStream::encode_grpc_frame(data);
        
        assert_eq!(frame[0], 0);
        assert_eq!(u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]), 5);
        assert_eq!(&frame[5..], b"hello");
    }

    #[test]
    fn test_decode_grpc_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u32(5);
        buf.put_slice(b"hello");
        
        let data = GrpcStream::try_decode_grpc_frame(&mut buf).unwrap();
        assert_eq!(&data[..], b"hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_grpc_frame_incomplete() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u32(10);
        buf.put_slice(b"hello");
        
        let result = GrpcStream::try_decode_grpc_frame(&mut buf);
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_grpc_frame_too_short() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0, 0, 0]);
        
        let result = GrpcStream::try_decode_grpc_frame(&mut buf);
        assert!(result.is_none());
    }

    #[test]
    fn test_grpc_mode_serialization() {
        let gun = GrpcMode::Gun;
        let multi = GrpcMode::Multi;
        
        let gun_json = serde_json::to_string(&gun).unwrap();
        let multi_json = serde_json::to_string(&multi).unwrap();
        
        assert_eq!(gun_json, "\"gun\"");
        assert_eq!(multi_json, "\"multi\"");
        
        let gun_de: GrpcMode = serde_json::from_str(&gun_json).unwrap();
        let multi_de: GrpcMode = serde_json::from_str(&multi_json).unwrap();
        
        assert_eq!(gun_de, GrpcMode::Gun);
        assert_eq!(multi_de, GrpcMode::Multi);
    }
}
