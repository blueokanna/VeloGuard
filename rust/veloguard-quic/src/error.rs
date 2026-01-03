//! Error types for VeloGuard QUIC

use thiserror::Error;

/// QUIC proxy error types
#[derive(Debug, Error)]
pub enum QuicError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("QUIC write error: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("QUIC read error: {0}")]
    Read(#[from] quinn::ReadError),

    #[error("QUIC read to end error: {0}")]
    ReadToEnd(#[from] quinn::ReadToEndError),

    #[error("QUIC closed stream: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Address parse error: {0}")]
    AddressParse(String),

    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(u8),

    #[error("Unsupported command: {0}")]
    UnsupportedCommand(u8),

    #[error("Connection timeout")]
    Timeout,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Stream closed")]
    StreamClosed,

    #[error("Buffer too small")]
    BufferTooSmall,

    #[error("Invalid packet")]
    InvalidPacket,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Server not ready")]
    ServerNotReady,

    #[error("Client not connected")]
    ClientNotConnected,

    #[error("UDP relay error: {0}")]
    UdpRelay(String),
}

impl From<aead::Error> for QuicError {
    fn from(_: aead::Error) -> Self {
        QuicError::Crypto("AEAD operation failed".to_string())
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, QuicError>;
