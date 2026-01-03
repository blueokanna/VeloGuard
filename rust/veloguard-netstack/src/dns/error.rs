//! DNS error types

use thiserror::Error;

/// DNS-specific errors
#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("DNS server error: {0}")]
    ServerError(String),

    #[error("DNS configuration error: {0}")]
    ConfigError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Fake IP error: {0}")]
    FakeIpError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("HTTP error: {0}")]
    HttpError(String),
}

pub type DnsResult<T> = std::result::Result<T, DnsError>;
