//! Address types for QUIC protocol (SOCKS5 compatible)

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::error::{QuicError, Result};

/// Address type indicator (SOCKS5 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = QuicError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::IPv4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::IPv6),
            _ => Err(QuicError::UnsupportedAddressType(value)),
        }
    }
}

/// Target address (SOCKS5 style)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    SocketAddr(SocketAddr),
    DomainName(String, u16),
}

impl Address {
    /// Create from socket address
    #[inline]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::SocketAddr(addr)
    }

    /// Create from domain name and port
    #[inline]
    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Self::DomainName(domain.into(), port)
    }

    /// Get the port
    #[inline]
    pub fn port(&self) -> u16 {
        match self {
            Self::SocketAddr(addr) => addr.port(),
            Self::DomainName(_, port) => *port,
        }
    }

    /// Get the address type
    #[inline]
    pub fn address_type(&self) -> AddressType {
        match self {
            Self::SocketAddr(SocketAddr::V4(_)) => AddressType::IPv4,
            Self::SocketAddr(SocketAddr::V6(_)) => AddressType::IPv6,
            Self::DomainName(..) => AddressType::Domain,
        }
    }

    /// Serialize the address to buffer
    pub fn write_to(&self, buf: &mut BytesMut) {
        match self {
            Self::SocketAddr(SocketAddr::V4(addr)) => {
                buf.put_u8(AddressType::IPv4 as u8);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddr(SocketAddr::V6(addr)) => {
                buf.put_u8(AddressType::IPv6 as u8);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::DomainName(domain, port) => {
                let domain_bytes = domain.as_bytes();
                buf.put_u8(AddressType::Domain as u8);
                buf.put_u8(domain_bytes.len() as u8);
                buf.put_slice(domain_bytes);
                buf.put_u16(*port);
            }
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to(&mut buf);
        buf.freeze()
    }

    /// Get the serialized length
    #[inline]
    pub fn serialized_len(&self) -> usize {
        match self {
            Self::SocketAddr(SocketAddr::V4(_)) => 7,  // 1 + 4 + 2
            Self::SocketAddr(SocketAddr::V6(_)) => 19, // 1 + 16 + 2
            Self::DomainName(domain, _) => 4 + domain.len(), // 1 + 1 + len + 2
        }
    }

    /// Parse address from cursor
    pub fn read_from(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if !buf.has_remaining() {
            return Err(QuicError::BufferTooSmall);
        }

        let addr_type = AddressType::try_from(buf.get_u8())?;

        match addr_type {
            AddressType::IPv4 => {
                if buf.remaining() < 6 {
                    return Err(QuicError::BufferTooSmall);
                }
                let mut ip = [0u8; 4];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Self::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(ip),
                    port,
                ))))
            }
            AddressType::IPv6 => {
                if buf.remaining() < 18 {
                    return Err(QuicError::BufferTooSmall);
                }
                let mut ip = [0u8; 16];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Self::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                ))))
            }
            AddressType::Domain => {
                if !buf.has_remaining() {
                    return Err(QuicError::BufferTooSmall);
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(QuicError::BufferTooSmall);
                }
                let mut domain = vec![0u8; len];
                buf.copy_to_slice(&mut domain);
                let domain = String::from_utf8(domain)
                    .map_err(|_| QuicError::AddressParse("Invalid UTF-8 domain".into()))?;
                let port = buf.get_u16();
                Ok(Self::DomainName(domain, port))
            }
        }
    }

    /// Parse from bytes slice
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::read_from(&mut Cursor::new(data))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketAddr(addr) => write!(f, "{}", addr),
            Self::DomainName(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl From<SocketAddr> for Address {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        Self::SocketAddr(addr)
    }
}

impl From<(String, u16)> for Address {
    #[inline]
    fn from((domain, port): (String, u16)) -> Self {
        Self::DomainName(domain, port)
    }
}

impl From<(&str, u16)> for Address {
    #[inline]
    fn from((domain, port): (&str, u16)) -> Self {
        Self::DomainName(domain.to_string(), port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_roundtrip() {
        let addr = Address::from_socket_addr("127.0.0.1:8080".parse().unwrap());
        let bytes = addr.to_bytes();
        assert_eq!(addr, Address::from_bytes(&bytes).unwrap());
    }

    #[test]
    fn test_ipv6_roundtrip() {
        let addr = Address::from_socket_addr("[::1]:8080".parse().unwrap());
        let bytes = addr.to_bytes();
        assert_eq!(addr, Address::from_bytes(&bytes).unwrap());
    }

    #[test]
    fn test_domain_roundtrip() {
        let addr = Address::from_domain("example.com", 443);
        let bytes = addr.to_bytes();
        assert_eq!(addr, Address::from_bytes(&bytes).unwrap());
    }
}
