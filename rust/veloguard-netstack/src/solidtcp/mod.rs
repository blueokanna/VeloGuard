//! VeloGuard SolidTCP - High-performance user-space TCP/IP stack
//!
//! This module provides a complete user-space TCP/IP stack implementation
//! based on smoltcp, designed for transparent proxy (tun2socks) functionality.
//!
//! # Features
//!
//! - Full TCP state machine with proper connection handling
//! - UDP session management with NAT support
//! - DNS interception with Fake-IP support
//! - Zero-copy packet processing where possible
//! - Async/await support with Tokio
//! - Connection pooling and reuse
//! - Traffic statistics and monitoring
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                   Application Layer                         |
//! | (HTTP, HTTPS, DNS, etc.)                                    |
//! +-------------------------------------------------------------+
//!                              |
//!                              v
//! +-------------------------------------------------------------+
//! |                   SolidTCP Stack                            |
//! | +-------------+ +-------------+ +-------------+             |
//! | |TCP Manager  | |UDP Manager  | |DNS Handler  |             |
//! | +-------------+ +-------------+ +-------------+             |
//! |          |             |              |                     |
//! |          +-------------+--------------+                     |
//! |                        |                                    |
//! | +-----------------------------------------------------+    |
//! | |             Packet Processor                        |    |
//! | | (IP parsing, checksum, fragmentation)               |    |
//! | +-----------------------------------------------------+    |
//! +-------------------------------------------------------------+
//!                              |
//!                              v
//! +-------------------------------------------------------------+
//! |                   TUN Device                                |
//! | (Virtual network interface)                                 |
//! +-------------------------------------------------------------+
//! ```

pub mod device;
pub mod dns;
pub mod error;
pub mod nat;
pub mod packet;
pub mod stack;
pub mod stats;
pub mod tcp;
pub mod udp;

// Re-exports for convenience
pub use device::{DeviceConfig, DeviceStats, VirtualDevice};
pub use dns::{DnsHandler, DnsQuery, FakeIpConfig, FakeIpPool};
pub use error::{Result, SolidTcpError};
pub use nat::{NatConfig, NatEntry, NatKey, NatState, NatTable};
pub use packet::{PacketBuilder, PacketParser, ParsedPacket, TcpFlags, build_ipv4_tcp, build_ipv4_udp, parse_packet};
pub use stack::{SolidStack, StackBuilder, StackConfig};
pub use stats::{ConnectionStats, StackStats, StatsSnapshot};
pub use tcp::{TcpAction, TcpConfig, TcpConnection, TcpManager, TcpState};
pub use udp::{UdpConfig, UdpManager, UdpSession, UdpSessionState};

// Android-specific exports for socket protection
#[cfg(target_os = "android")]
pub use stack::{set_protect_callback, protect_socket, has_protect_callback, clear_protect_callback};

/// Prelude module for common imports
pub mod prelude {
    pub use crate::solidtcp::error::{Result, SolidTcpError};
    pub use crate::solidtcp::stack::{SolidStack, StackBuilder, StackConfig};
    pub use crate::solidtcp::stats::StackStats;
}
