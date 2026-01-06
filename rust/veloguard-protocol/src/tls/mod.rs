//! TLS/Rustls implementation for VeloGuard

mod client;
mod server;
mod config;
mod stream;
mod error;
mod verifier;

pub use client::TlsConnector;
pub use server::TlsAcceptor;
pub use config::{ClientConfig, ServerConfig};
pub use stream::TlsStream;
pub use error::{TlsError, Result};
pub use verifier::SkipServerVerification;
