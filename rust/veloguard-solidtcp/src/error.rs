//! Error types for VeloGuard SolidTCP stack

use std::io;
use thiserror::Error;

/// Result type alias for SolidTCP operations
pub type Result<T> = std::result::Result<T, SolidTcpError>;

/// Main error type for the SolidTCP stack
#[derive(Error, Debug)]
pub enum SolidTcpError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Packet too short: expected {expected}, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("Invalid IP version: {0}")]
    InvalidIpVersion(u8),

    #[error("TCP error: {0}")]
    TcpError(String),

    #[error("UDP error: {0}")]
    UdpError(String),

    #[error("DNS error: {0}")]
    DnsError(String),

    #[error("Fake-IP pool exhausted")]
    FakeIpPoolExhausted,

    #[error("NAT table full: {0}")]
    NatTableFull(usize),

    #[error("Device not ready")]
    DeviceNotReady,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("Proxy auth failed")]
    ProxyAuthFailed,

    #[error("Unsupported: {0}")]
    Unsupported(String),

    #[error("Internal error: {0}")]
    Internal(String),
}
