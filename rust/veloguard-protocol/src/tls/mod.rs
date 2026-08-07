//! TLS/Rustls implementation for VeloGuard

mod client;
mod config;
mod error;
mod server;
mod stream;
mod verifier;

pub use client::TlsConnector;
pub use config::{ClientConfig, ServerConfig};
pub use error::{Result, TlsError};
pub use server::TlsAcceptor;
pub use stream::TlsStream;
pub use verifier::SkipServerVerification;
