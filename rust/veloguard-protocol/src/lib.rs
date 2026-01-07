pub mod address;
pub mod error;
pub mod transport;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "tuic")]
pub mod tuic;

#[cfg(feature = "tuic-quinn")]
#[path = "tuic-quinn/mod.rs"]
pub mod tuic_quinn;

pub use address::{Address, AddressType};
pub use error::{ProtocolError, Result};

pub mod prelude {
    pub use crate::address::{Address, AddressType};
    pub use crate::error::{ProtocolError, Result};
    
    pub use crate::transport::{
        TransportError,
        TlsTransport, TlsConfig, TlsFingerprint, TlsStream,
        WebSocketTransport, WebSocketConfig, WsStream,
        H2Transport, H2Config, H2Stream,
        GrpcTransport, GrpcConfig, GrpcMode, GrpcStream,
    };
    
    #[cfg(feature = "quic")]
    pub use crate::quic::prelude::*;
    
    #[cfg(feature = "tls")]
    pub use crate::tls::{TlsConnector, TlsAcceptor, TlsStream as TlsModuleStream};
    
    #[cfg(feature = "wireguard")]
    pub use crate::wireguard::{WireGuard, DeviceConfig, PeerConfig};
    
    #[cfg(feature = "tuic")]
    pub use crate::tuic::{TuicClient, TuicServer, TuicConnection};
    
    #[cfg(feature = "tuic-quinn")]
    pub use crate::tuic_quinn::{TuicQuinnEndpoint, TuicQuinnConnection, TuicQuinnConfig, TuicQuinnError};
}
