//! VeloGuard DNS - High-performance DNS resolver and server
//!
//! A comprehensive DNS library for VeloGuard with support for:
//! - Local DNS server (UDP/TCP/DoH/DoT)
//! - Multiple upstream DNS protocols (UDP/TCP/DoH/DoT)
//! - DNS caching with TTL awareness
//! - Fake-IP mode for transparent proxying
//! - Anti-spoofing protection
//! - Domain-based routing (domestic/foreign DNS)
//! - Hosts file support
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                     DNS Manager                             |
//! | +---------+ +---------+ +---------+ +---------+             |
//! | |   DoH   | |   DoT   | |  Cache  | | Fake-IP |             |
//! | +----+----+ +----+----+ +----+----+ +----+----+             |
//! |      +----------+----------+----------+                     |
//! |                        |                                    |
//! |                   +----v----+                               |
//! |                   |Resolver | (Domain-based routing)        |
//! |                   +----+----+                               |
//! |          +-------------+-------------+                      |
//! |     +----v----+  +----v----+  +----v----+                   |
//! |     | Hosts   |  | Primary |  |Fallback |                   |
//! |     |  File   |  |   DNS   |  |   DNS   |                   |
//! |     +---------+  +---------+  +---------+                   |
//! +-------------------------------------------------------------+
//!                        |
//!                   +----v----+
//!                   |  DNS    |
//!                   | Server  |
//!                   +---------+
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use veloguard_dns::{DnsManager, DnsConfig, RecordType};
//!
//! #[tokio::main]
//! async fn main() -> veloguard_dns::Result<()> {
//!     // Create DNS manager with default config
//!     let manager = DnsManager::new()?;
//!
//!     // Resolve a domain
//!     let ips = manager.resolve("google.com").await?;
//!     println!("Resolved: {:?}", ips);
//!
//!     // Start DNS server
//!     manager.start_server().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - **Multi-protocol support**: UDP, TCP, DoH (DNS over HTTPS), DoT (DNS over TLS)
//! - **Intelligent caching**: TTL-aware caching with stale-while-revalidate support
//! - **Fake-IP mode**: Virtual IP allocation for transparent proxying
//! - **Anti-spoofing**: Fallback DNS with bogon IP detection
//! - **Load balancing**: Round-robin across multiple upstream servers
//! - **Hot reload**: Configuration can be reloaded without restart

pub mod bogon;
pub mod cache;
pub mod client;
pub mod config;
pub mod doh;
pub mod doh_server;
pub mod dot;
pub mod dot_server;
pub mod error;
pub mod fake_ip;
pub mod hosts;
pub mod manager;
pub mod resolver;
pub mod server;

#[cfg(test)]
mod tests;

// Re-export main types
pub use bogon::{
    classify_bogon, contains_bogon, filter_bogons, is_bogon, is_bogon_ipv4, is_bogon_ipv6,
    is_loopback, is_private, is_reserved, BogonType,
};
pub use cache::{CacheEntry, CacheStats, DnsCache};
pub use client::{create_clients, DnsClient, DnsProtocol};
pub use config::{DnsConfig, FallbackFilter, UpstreamConfig, UpstreamProtocol};
pub use doh::{DohClient, DohClientConfig, DohMethod, DohResolver};
pub use doh_server::{DohServer, DohServerConfig};
pub use dot::{DotClient, DotClientConfig, DotResolver};
pub use dot_server::{DotServer, DotServerConfig};
pub use error::{DnsError, Result};
pub use fake_ip::{FakeIpEntry, FakeIpPool};
pub use hosts::HostsFile;
pub use manager::{CacheStatistics, DnsManager, DnsManagerState};
pub use resolver::DnsResolver;
pub use server::DnsServer;

/// DNS record types supported by this library
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// IPv4 address record
    A,
    /// IPv6 address record
    AAAA,
    /// Canonical name record
    CNAME,
    /// Text record
    TXT,
    /// Mail exchange record
    MX,
    /// Name server record
    NS,
    /// Start of authority record
    SOA,
    /// Pointer record (reverse DNS)
    PTR,
    /// Service record
    SRV,
    /// HTTPS service binding
    HTTPS,
    /// Service binding
    SVCB,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::MX => write!(f, "MX"),
            RecordType::NS => write!(f, "NS"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::HTTPS => write!(f, "HTTPS"),
            RecordType::SVCB => write!(f, "SVCB"),
        }
    }
}

impl From<hickory_proto::rr::RecordType> for RecordType {
    fn from(rt: hickory_proto::rr::RecordType) -> Self {
        match rt {
            hickory_proto::rr::RecordType::A => RecordType::A,
            hickory_proto::rr::RecordType::AAAA => RecordType::AAAA,
            hickory_proto::rr::RecordType::CNAME => RecordType::CNAME,
            hickory_proto::rr::RecordType::TXT => RecordType::TXT,
            hickory_proto::rr::RecordType::MX => RecordType::MX,
            hickory_proto::rr::RecordType::NS => RecordType::NS,
            hickory_proto::rr::RecordType::SOA => RecordType::SOA,
            hickory_proto::rr::RecordType::PTR => RecordType::PTR,
            hickory_proto::rr::RecordType::SRV => RecordType::SRV,
            hickory_proto::rr::RecordType::HTTPS => RecordType::HTTPS,
            hickory_proto::rr::RecordType::SVCB => RecordType::SVCB,
            _ => RecordType::A, // Default fallback
        }
    }
}

impl From<RecordType> for hickory_proto::rr::RecordType {
    fn from(rt: RecordType) -> Self {
        match rt {
            RecordType::A => hickory_proto::rr::RecordType::A,
            RecordType::AAAA => hickory_proto::rr::RecordType::AAAA,
            RecordType::CNAME => hickory_proto::rr::RecordType::CNAME,
            RecordType::TXT => hickory_proto::rr::RecordType::TXT,
            RecordType::MX => hickory_proto::rr::RecordType::MX,
            RecordType::NS => hickory_proto::rr::RecordType::NS,
            RecordType::SOA => hickory_proto::rr::RecordType::SOA,
            RecordType::PTR => hickory_proto::rr::RecordType::PTR,
            RecordType::SRV => hickory_proto::rr::RecordType::SRV,
            RecordType::HTTPS => hickory_proto::rr::RecordType::HTTPS,
            RecordType::SVCB => hickory_proto::rr::RecordType::SVCB,
        }
    }
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::config::DnsConfig;
    pub use crate::error::{DnsError, Result};
    pub use crate::manager::DnsManager;
    pub use crate::RecordType;
}
