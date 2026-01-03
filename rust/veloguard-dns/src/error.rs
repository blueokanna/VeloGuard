//! DNS error types

use std::io;
use thiserror::Error;

/// DNS operation result type
pub type Result<T> = std::result::Result<T, DnsError>;

/// DNS error types
#[derive(Error, Debug)]
pub enum DnsError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("DNS protocol error: {0}")]
    Protocol(String),

    #[error("DNS query timeout")]
    Timeout,

    #[error("DNS query failed: {0}")]
    QueryFailed(String),

    #[error("DNS resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("No DNS servers available")]
    NoServers,

    #[error("Invalid DNS response")]
    InvalidResponse,

    #[error("DNS name error: {0}")]
    NameError(String),

    #[error("DNS server error: {0}")]
    ServerError(String),

    #[error("DNS refused")]
    Refused,

    #[error("DNS not implemented")]
    NotImplemented,

    #[error("Fake-IP pool exhausted")]
    FakeIpExhausted,

    #[error("Fake-IP error: {0}")]
    FakeIpError(String),

    #[error("Invalid configuration: {0}")]
    Config(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Upstream DNS error: {0}")]
    Upstream(String),
}

impl From<hickory_proto::ProtoError> for DnsError {
    fn from(e: hickory_proto::ProtoError) -> Self {
        DnsError::Protocol(e.to_string())
    }
}

impl From<hickory_resolver::ResolveError> for DnsError {
    fn from(e: hickory_resolver::ResolveError) -> Self {
        DnsError::QueryFailed(e.to_string())
    }
}

impl From<rustls::Error> for DnsError {
    fn from(e: rustls::Error) -> Self {
        DnsError::Tls(e.to_string())
    }
}
