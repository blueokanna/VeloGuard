//! Transport Layer - Provides various transport protocols
//! 
//! Supported transports:
//! - TCP: Raw TCP connections (default)
//! - WebSocket: WebSocket-based transport for HTTP proxy bypass
//! - mKCP: KCP-based UDP transport for lossy networks
//! - Mux: Connection multiplexing

pub mod mkcp;
pub mod mux;
pub mod tcp;
pub mod websocket;

pub use mkcp::{MkcpConfig, MkcpStream, MkcpTransport};
pub use mux::{MuxConfig, MuxConnection, MuxStream};
pub use tcp::{TcpConfig, TcpTransportStream};
pub use websocket::{WebSocketConfig, WebSocketStream};

use tokio::io::{AsyncRead, AsyncWrite};

/// Transport type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportType {
    #[default]
    Tcp,
    WebSocket,
    Mkcp,
    Grpc,
    Http2,
    Quic,
}

impl TransportType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" | "" => Some(TransportType::Tcp),
            "ws" | "websocket" => Some(TransportType::WebSocket),
            "mkcp" | "kcp" => Some(TransportType::Mkcp),
            "grpc" => Some(TransportType::Grpc),
            "h2" | "http2" => Some(TransportType::Http2),
            "quic" => Some(TransportType::Quic),
            _ => None,
        }
    }
}

/// Stream settings for transport configuration
#[derive(Debug, Clone, Default)]
pub struct StreamSettings {
    pub transport: TransportType,
    pub security: SecurityType,
    pub tcp_settings: Option<TcpConfig>,
    pub ws_settings: Option<WebSocketConfig>,
    pub mkcp_settings: Option<MkcpConfig>,
}

/// Security type for transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityType {
    #[default]
    None,
    Tls,
    Reality,
}

impl SecurityType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" | "" => Some(SecurityType::None),
            "tls" => Some(SecurityType::Tls),
            "reality" => Some(SecurityType::Reality),
            _ => None,
        }
    }
}

/// Trait for transport streams
pub trait TransportStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransportStream for T {}

