use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("QUIC error: {0}")]
    Quic(String),
    
    #[error("TLS error: {0}")]
    Tls(String),
    
    #[error("WireGuard error: {0}")]
    WireGuard(String),
    
    #[error("TUIC error: {0}")]
    Tuic(String),
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Handshake error: {0}")]
    Handshake(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Authentication failed")]
    AuthFailed,
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Connection closed")]
    ConnectionClosed,
    
    #[error("Timeout")]
    Timeout,
    
    #[error("Address parse error: {0}")]
    AddressParse(String),
    
    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(u8),
    
    #[error("Buffer too small")]
    BufferTooSmall,
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

impl From<quinn::ConnectionError> for ProtocolError {
    fn from(e: quinn::ConnectionError) -> Self {
        ProtocolError::Quic(e.to_string())
    }
}

impl From<quinn::ConnectError> for ProtocolError {
    fn from(e: quinn::ConnectError) -> Self {
        ProtocolError::Quic(e.to_string())
    }
}

impl From<quinn::WriteError> for ProtocolError {
    fn from(e: quinn::WriteError) -> Self {
        ProtocolError::Quic(e.to_string())
    }
}

impl From<quinn::ReadToEndError> for ProtocolError {
    fn from(e: quinn::ReadToEndError) -> Self {
        ProtocolError::Quic(e.to_string())
    }
}

impl From<quinn::ClosedStream> for ProtocolError {
    fn from(e: quinn::ClosedStream) -> Self {
        ProtocolError::Quic(e.to_string())
    }
}

impl From<rustls::Error> for ProtocolError {
    fn from(e: rustls::Error) -> Self {
        ProtocolError::Tls(e.to_string())
    }
}
