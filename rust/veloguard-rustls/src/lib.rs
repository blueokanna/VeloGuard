pub mod client;
pub mod server;
pub mod connection;
pub mod config;
pub mod stream;
pub mod handshake;
pub mod crypto;
pub mod error;
pub mod x509;
pub mod record;

// Re-export main types
pub use client::TlsConnector;
pub use server::TlsAcceptor;
pub use config::{ClientConfig, ServerConfig};
pub use connection::Connection;
pub use stream::TlsStream;
pub use error::{Error, Result};
pub use x509::{Certificate, PrivateKey};

// Re-export TLS version types
pub use record::{ProtocolVersion, TlsVersion};
pub use crypto::CipherSuite;