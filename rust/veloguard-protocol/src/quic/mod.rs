//! VeloGuard QUIC - High-performance QUIC proxy with 0-RTT support
//!
//! Features:
//! - 0-RTT connection establishment for ultra-low latency
//! - SNI camouflage for traffic obfuscation
//! - SOCKS5 proxy protocol support
//! - TCP and UDP relay over QUIC
//! - Stream multiplexing
//! - AEAD encryption (AES-GCM, ChaCha20-Poly1305)
//! - Session resumption with ticket storage

mod address;
mod client;
mod config;
mod crypto;
mod error;
mod protocol;
mod server;
mod session;
mod socks5;
mod stream;

pub use address::{Address, AddressType};
pub use client::{ClientConnection, QuicClient, UdpSession};
pub use config::{CipherKind, ClientConfig, CongestionControl, ServerConfig, TransportConfig};
pub use crypto::{Cipher, CryptoContext};
pub use error::{QuicError, Result};
pub use protocol::{Command, Request, Response, ResponseStatus, UdpHeader};
pub use server::{QuicServer, ServerConnection};
pub use session::{SessionStore, SessionTicket, ZeroRttState};
pub use socks5::Socks5Server;
pub use stream::{QuicRecvStream, QuicSendStream, QuicStream, StreamType};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024;
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

pub mod prelude {
    pub use super::{
        Address, AddressType, CipherKind, ClientConfig, ClientConnection, Command, QuicClient,
        QuicError, QuicServer, Request, Response, Result, ServerConfig, ServerConnection,
    };
}
