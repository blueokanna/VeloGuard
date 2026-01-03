//! VeloGuard DNS - High-performance DNS resolver and server
//!
//! Features:
//! - Local DNS server (UDP/TCP/DoH/DoT)
//! - Multiple upstream DNS protocols (UDP/TCP/DoH/DoT)
//! - DNS caching with TTL awareness
//! - Fake-IP mode for transparent proxying
//! - Anti-spoofing protection
//! - Domain-based routing (domestic/foreign DNS)
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                     DNS Server                              |
//! | +---------+ +---------+ +---------+ +---------+             |
//! | |   UDP   | |   TCP   | |   DoH   | |   DoT   |             |
//! | +----+----+ +----+----+ +----+----+ +----+----+             |
//! |      +----------+----------+----------+                     |
//! |                        |                                    |
//! |                   +----v----+                               |
//! |                   | Router  | (Domain-based routing)        |
//! |                   +----+----+                               |
//! |          +-------------+-------------+                      |
//! |     +----v----+  +----v----+  +----v----+                   |
//! |     |Fake-IP  |  | Cache   |  |Upstream |                   |
//! |     | Pool    |  |         |  |Resolver |                   |
//! |     +---------+  +---------+  +---------+                   |
//! +-------------------------------------------------------------+
//! ```

pub mod cache;
pub mod client;
pub mod config;
pub mod error;
pub mod fake_ip;
pub mod hosts;
pub mod resolver;
pub mod server;

pub use cache::DnsCache;
pub use client::{DnsClient, DnsProtocol};
pub use config::DnsConfig;
pub use error::{DnsError, Result};
pub use fake_ip::FakeIpPool;
pub use hosts::HostsFile;
pub use resolver::DnsResolver;
pub use server::DnsServer;

/// DNS record types we care about
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    TXT,
    MX,
    NS,
    SOA,
    PTR,
    SRV,
    HTTPS,
    SVCB,
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
