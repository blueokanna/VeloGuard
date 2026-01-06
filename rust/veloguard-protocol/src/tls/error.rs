use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("TLS error: {0}")]
    Tls(String),
    
    #[error("Certificate error: {0}")]
    Certificate(String),
    
    #[error("Handshake error: {0}")]
    Handshake(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type Result<T> = std::result::Result<T, TlsError>;
