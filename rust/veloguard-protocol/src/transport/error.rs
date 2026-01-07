use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("TLS error: {0}")]
    Tls(String),
    
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    
    #[error("HTTP/2 error: {0}")]
    H2(String),
    
    #[error("gRPC error: {0}")]
    Grpc(String),
    
    #[error("Handshake error: {0}")]
    Handshake(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Connection closed")]
    ConnectionClosed,
    
    #[error("Timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, TransportError>;
