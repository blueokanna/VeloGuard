use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{ProtocolError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::IPv4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::IPv6),
            _ => Err(ProtocolError::UnsupportedAddressType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Domain(String, u16),
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
}

impl Address {
    #[inline]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::Ipv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Self::Ipv6(*v6.ip(), v6.port()),
        }
    }

    #[inline]
    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Self::Domain(domain.into(), port)
    }

    #[inline]
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, port) => *port,
            Self::Ipv4(_, port) => *port,
            Self::Ipv6(_, port) => *port,
        }
    }

    #[inline]
    pub fn host(&self) -> String {
        match self {
            Self::Domain(domain, _) => domain.clone(),
            Self::Ipv4(ip, _) => ip.to_string(),
            Self::Ipv6(ip, _) => ip.to_string(),
        }
    }

    #[inline]
    pub fn address_type(&self) -> AddressType {
        match self {
            Self::Ipv4(..) => AddressType::IPv4,
            Self::Ipv6(..) => AddressType::IPv6,
            Self::Domain(..) => AddressType::Domain,
        }
    }

    pub fn write_to(&self, buf: &mut impl BufMut) {
        match self {
            Self::Ipv4(ip, port) => {
                buf.put_u8(AddressType::IPv4 as u8);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
            Self::Ipv6(ip, port) => {
                buf.put_u8(AddressType::IPv6 as u8);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
            Self::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                buf.put_u8(AddressType::Domain as u8);
                buf.put_u8(domain_bytes.len() as u8);
                buf.put_slice(domain_bytes);
                buf.put_u16(*port);
            }
        }
    }

    pub fn write_to_vec(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Ipv4(ip, port) => {
                buf.push(AddressType::IPv4 as u8);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::Ipv6(ip, port) => {
                buf.push(AddressType::IPv6 as u8);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                buf.push(AddressType::Domain as u8);
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    pub fn write_address_to(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Ipv4(ip, _) => {
                buf.push(AddressType::IPv4 as u8);
                buf.extend_from_slice(&ip.octets());
            }
            Self::Ipv6(ip, _) => {
                buf.push(AddressType::IPv6 as u8);
                buf.extend_from_slice(&ip.octets());
            }
            Self::Domain(domain, _) => {
                let domain_bytes = domain.as_bytes();
                if domain_bytes.len() > 255 {
                    return Err(ProtocolError::AddressParse("Domain name too long".into()));
                }
                buf.push(AddressType::Domain as u8);
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
            }
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to(&mut buf);
        buf.freeze()
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        match self {
            Self::Ipv4(..) => 7,
            Self::Ipv6(..) => 19,
            Self::Domain(domain, _) => 4 + domain.len(),
        }
    }

    pub fn read_from(buf: &[u8]) -> Result<(Self, usize)> {
        let mut cursor = Cursor::new(buf);
        let addr = Self::read_from_cursor(&mut cursor)?;
        Ok((addr, cursor.position() as usize))
    }

    pub fn read_from_cursor(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if !buf.has_remaining() {
            return Err(ProtocolError::BufferTooSmall);
        }

        let addr_type = AddressType::try_from(buf.get_u8())?;

        match addr_type {
            AddressType::IPv4 => {
                if buf.remaining() < 6 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let mut ip = [0u8; 4];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Self::Ipv4(Ipv4Addr::from(ip), port))
            }
            AddressType::IPv6 => {
                if buf.remaining() < 18 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let mut ip = [0u8; 16];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Self::Ipv6(Ipv6Addr::from(ip), port))
            }
            AddressType::Domain => {
                if !buf.has_remaining() {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let mut domain = vec![0u8; len];
                buf.copy_to_slice(&mut domain);
                let domain = String::from_utf8(domain)
                    .map_err(|_| ProtocolError::AddressParse("Invalid UTF-8 domain".into()))?;
                let port = buf.get_u16();
                Ok(Self::Domain(domain, port))
            }
        }
    }

    pub async fn read_from_async<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let addr_type_byte = reader.read_u8().await
            .map_err(ProtocolError::Io)?;
        let addr_type = AddressType::try_from(addr_type_byte)?;

        match addr_type {
            AddressType::IPv4 => {
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip).await
                    .map_err(ProtocolError::Io)?;
                let port = reader.read_u16().await
                    .map_err(ProtocolError::Io)?;
                Ok(Self::Ipv4(Ipv4Addr::from(ip), port))
            }
            AddressType::IPv6 => {
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip).await
                    .map_err(ProtocolError::Io)?;
                let port = reader.read_u16().await
                    .map_err(ProtocolError::Io)?;
                Ok(Self::Ipv6(Ipv6Addr::from(ip), port))
            }
            AddressType::Domain => {
                let len = reader.read_u8().await
                    .map_err(ProtocolError::Io)? as usize;
                let mut domain = vec![0u8; len];
                reader.read_exact(&mut domain).await
                    .map_err(ProtocolError::Io)?;
                let domain = String::from_utf8(domain)
                    .map_err(|_| ProtocolError::AddressParse("Invalid UTF-8 domain".into()))?;
                let port = reader.read_u16().await
                    .map_err(ProtocolError::Io)?;
                Ok(Self::Domain(domain, port))
            }
        }
    }

    #[inline]
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::read_from_cursor(&mut Cursor::new(data))
    }

    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ipv4(ip, port) => Some(SocketAddr::V4(SocketAddrV4::new(*ip, *port))),
            Self::Ipv6(ip, port) => Some(SocketAddr::V6(SocketAddrV6::new(*ip, *port, 0, 0))),
            Self::Domain(..) => None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain, port) => write!(f, "{}:{}", domain, port),
            Self::Ipv4(ip, port) => write!(f, "{}:{}", ip, port),
            Self::Ipv6(ip, port) => write!(f, "[{}]:{}", ip, port),
        }
    }
}

impl From<SocketAddr> for Address {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        Self::from_socket_addr(addr)
    }
}

impl From<SocketAddrV4> for Address {
    #[inline]
    fn from(addr: SocketAddrV4) -> Self {
        Self::Ipv4(*addr.ip(), addr.port())
    }
}

impl From<SocketAddrV6> for Address {
    #[inline]
    fn from(addr: SocketAddrV6) -> Self {
        Self::Ipv6(*addr.ip(), addr.port())
    }
}

impl From<(String, u16)> for Address {
    #[inline]
    fn from((domain, port): (String, u16)) -> Self {
        Self::Domain(domain, port)
    }
}

impl From<(&str, u16)> for Address {
    #[inline]
    fn from((domain, port): (&str, u16)) -> Self {
        Self::Domain(domain.to_string(), port)
    }
}

impl From<(Ipv4Addr, u16)> for Address {
    #[inline]
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        Self::Ipv4(ip, port)
    }
}

impl From<(Ipv6Addr, u16)> for Address {
    #[inline]
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        Self::Ipv6(ip, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_ipv4_roundtrip() {
        let addr = Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1), 8080);
        let bytes = addr.to_bytes();
        let (parsed, len) = Address::read_from(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(len, 7);
    }

    #[test]
    fn test_address_ipv6_roundtrip() {
        let addr = Address::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443);
        let bytes = addr.to_bytes();
        let (parsed, len) = Address::read_from(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(len, 19);
    }

    #[test]
    fn test_address_domain_roundtrip() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let bytes = addr.to_bytes();
        let (parsed, len) = Address::read_from(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(len, 4 + "example.com".len());
    }

    #[test]
    fn test_address_display() {
        assert_eq!(
            Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 80).to_string(),
            "127.0.0.1:80"
        );
        assert_eq!(
            Address::Ipv6(Ipv6Addr::LOCALHOST, 443).to_string(),
            "[::1]:443"
        );
        assert_eq!(
            Address::Domain("example.com".to_string(), 8080).to_string(),
            "example.com:8080"
        );
    }

    #[test]
    fn test_address_from_socket_addr() {
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234));
        let addr: Address = v4.into();
        assert!(matches!(addr, Address::Ipv4(_, 1234)));

        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5678, 0, 0));
        let addr: Address = v6.into();
        assert!(matches!(addr, Address::Ipv6(_, 5678)));
    }

    #[test]
    fn test_address_port_and_host() {
        let addr = Address::Domain("test.local".to_string(), 9000);
        assert_eq!(addr.port(), 9000);
        assert_eq!(addr.host(), "test.local");

        let addr = Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 80);
        assert_eq!(addr.port(), 80);
        assert_eq!(addr.host(), "1.2.3.4");
    }

    #[tokio::test]
    async fn test_address_async_read() {
        let addr = Address::Domain("async.test".to_string(), 12345);
        let bytes = addr.to_bytes();
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        let parsed = Address::read_from_async(&mut cursor).await.unwrap();
        assert_eq!(addr, parsed);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_ipv4_addr() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    fn arb_ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
        (
            any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(),
            any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(),
        )
            .prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn arb_domain() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{0,62}(\\.[a-z][a-z0-9]{0,62}){0,3}"
            .prop_filter("domain must be <= 255 bytes", |s| s.len() <= 255)
    }

    fn arb_port() -> impl Strategy<Value = u16> {
        1u16..=65535u16
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        prop_oneof![
            (arb_ipv4_addr(), arb_port()).prop_map(|(ip, port)| Address::Ipv4(ip, port)),
            (arb_ipv6_addr(), arb_port()).prop_map(|(ip, port)| Address::Ipv6(ip, port)),
            (arb_domain(), arb_port()).prop_map(|(domain, port)| Address::Domain(domain, port)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_address_serialization_roundtrip(addr in arb_address()) {
            let bytes = addr.to_bytes();
            let (parsed, len) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(&addr, &parsed);
            prop_assert_eq!(len, addr.serialized_len());
        }

        #[test]
        fn prop_address_ipv4_roundtrip(ip in arb_ipv4_addr(), port in arb_port()) {
            let addr = Address::Ipv4(ip, port);
            let bytes = addr.to_bytes();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr, parsed);
        }

        #[test]
        fn prop_address_ipv6_roundtrip(ip in arb_ipv6_addr(), port in arb_port()) {
            let addr = Address::Ipv6(ip, port);
            let bytes = addr.to_bytes();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr, parsed);
        }

        #[test]
        fn prop_address_domain_roundtrip(domain in arb_domain(), port in arb_port()) {
            let addr = Address::Domain(domain, port);
            let bytes = addr.to_bytes();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr, parsed);
        }

        #[test]
        fn prop_address_port_preserved(addr in arb_address()) {
            let bytes = addr.to_bytes();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr.port(), parsed.port());
        }

        #[test]
        fn prop_address_host_preserved(addr in arb_address()) {
            let bytes = addr.to_bytes();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr.host(), parsed.host());
        }

        #[test]
        fn prop_address_type_preserved(addr in arb_address()) {
            let bytes = addr.to_bytes();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr.address_type(), parsed.address_type());
        }

        #[test]
        fn prop_address_serialized_len_correct(addr in arb_address()) {
            let bytes = addr.to_bytes();
            prop_assert_eq!(bytes.len(), addr.serialized_len());
        }

        #[test]
        fn prop_socket_addr_conversion_roundtrip(ip in arb_ipv4_addr(), port in arb_port()) {
            let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            let addr = Address::from(socket_addr);
            let back = addr.to_socket_addr().unwrap();
            prop_assert_eq!(socket_addr, back);
        }
    }
}
