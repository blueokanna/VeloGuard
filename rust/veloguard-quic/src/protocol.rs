//! VeloGuard QUIC protocol definitions

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

use crate::address::Address;
use crate::error::{Result, QuicError};
use crate::PROTOCOL_VERSION;

/// Command types (SOCKS5 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// TCP connect
    Connect = 0x01,
    /// TCP bind (not commonly used)
    Bind = 0x02,
    /// UDP associate
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = QuicError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(QuicError::UnsupportedCommand(value)),
        }
    }
}

/// Response status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    /// Success
    Success = 0x00,
    /// General failure
    GeneralFailure = 0x01,
    /// Connection not allowed
    ConnectionNotAllowed = 0x02,
    /// Network unreachable
    NetworkUnreachable = 0x03,
    /// Host unreachable
    HostUnreachable = 0x04,
    /// Connection refused
    ConnectionRefused = 0x05,
    /// TTL expired
    TtlExpired = 0x06,
    /// Command not supported
    CommandNotSupported = 0x07,
    /// Address type not supported
    AddressTypeNotSupported = 0x08,
}

impl From<u8> for ResponseStatus {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ResponseStatus::Success,
            0x01 => ResponseStatus::GeneralFailure,
            0x02 => ResponseStatus::ConnectionNotAllowed,
            0x03 => ResponseStatus::NetworkUnreachable,
            0x04 => ResponseStatus::HostUnreachable,
            0x05 => ResponseStatus::ConnectionRefused,
            0x06 => ResponseStatus::TtlExpired,
            0x07 => ResponseStatus::CommandNotSupported,
            _ => ResponseStatus::AddressTypeNotSupported,
        }
    }
}

/// Request packet
#[derive(Debug, Clone)]
pub struct Request {
    /// Protocol version
    pub version: u8,
    /// Command
    pub command: Command,
    /// Target address
    pub address: Address,
    /// Optional payload (for 0-RTT)
    pub payload: Option<Bytes>,
}

impl Request {
    /// Create a new connect request
    pub fn connect(address: Address) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            command: Command::Connect,
            address,
            payload: None,
        }
    }

    /// Create a new UDP associate request
    pub fn udp_associate(address: Address) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            command: Command::UdpAssociate,
            address,
            payload: None,
        }
    }

    /// Add payload for 0-RTT
    pub fn with_payload(mut self, payload: Bytes) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Bytes {
        let addr_len = self.address.serialized_len();
        let payload_len = self.payload.as_ref().map(|p| p.len()).unwrap_or(0);
        let mut buf = BytesMut::with_capacity(2 + addr_len + 2 + payload_len);

        buf.put_u8(self.version);
        buf.put_u8(self.command as u8);
        self.address.write_to(&mut buf);

        if let Some(ref payload) = self.payload {
            buf.put_u16(payload.len() as u16);
            buf.put_slice(payload);
        } else {
            buf.put_u16(0);
        }

        buf.freeze()
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        if cursor.remaining() < 2 {
            return Err(QuicError::BufferTooSmall);
        }

        let version = cursor.get_u8();
        let command = Command::try_from(cursor.get_u8())?;
        let address = Address::read_from(&mut cursor)?;

        let payload = if cursor.remaining() >= 2 {
            let payload_len = cursor.get_u16() as usize;
            if payload_len > 0 {
                if cursor.remaining() < payload_len {
                    return Err(QuicError::BufferTooSmall);
                }
                let pos = cursor.position() as usize;
                Some(Bytes::copy_from_slice(&data[pos..pos + payload_len]))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            version,
            command,
            address,
            payload,
        })
    }
}

/// Response packet
#[derive(Debug, Clone)]
pub struct Response {
    /// Protocol version
    pub version: u8,
    /// Status code
    pub status: ResponseStatus,
    /// Bound address (for UDP associate)
    pub address: Option<Address>,
}

impl Response {
    /// Create a success response
    pub fn success() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status: ResponseStatus::Success,
            address: None,
        }
    }

    /// Create a success response with bound address
    pub fn success_with_address(address: Address) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status: ResponseStatus::Success,
            address: Some(address),
        }
    }

    /// Create an error response
    pub fn error(status: ResponseStatus) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status,
            address: None,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Bytes {
        let addr_len = self.address.as_ref().map(|a| a.serialized_len()).unwrap_or(0);
        let mut buf = BytesMut::with_capacity(3 + addr_len);

        buf.put_u8(self.version);
        buf.put_u8(self.status as u8);
        buf.put_u8(if self.address.is_some() { 1 } else { 0 });

        if let Some(ref addr) = self.address {
            addr.write_to(&mut buf);
        }

        buf.freeze()
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        if cursor.remaining() < 3 {
            return Err(QuicError::BufferTooSmall);
        }

        let version = cursor.get_u8();
        let status = ResponseStatus::from(cursor.get_u8());
        let has_address = cursor.get_u8() != 0;

        let address = if has_address {
            Some(Address::read_from(&mut cursor)?)
        } else {
            None
        };

        Ok(Self {
            version,
            status,
            address,
        })
    }

    /// Check if the response indicates success
    pub fn is_success(&self) -> bool {
        self.status == ResponseStatus::Success
    }
}

/// UDP packet header
#[derive(Debug, Clone)]
pub struct UdpHeader {
    /// Fragment ID (0 for no fragmentation)
    pub frag: u8,
    /// Target address
    pub address: Address,
}

impl UdpHeader {
    /// Create a new UDP header
    pub fn new(address: Address) -> Self {
        Self { frag: 0, address }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Bytes {
        let addr_len = self.address.serialized_len();
        let mut buf = BytesMut::with_capacity(3 + addr_len);

        buf.put_u16(0); // Reserved
        buf.put_u8(self.frag);
        self.address.write_to(&mut buf);

        buf.freeze()
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        let mut cursor = Cursor::new(data);

        if cursor.remaining() < 3 {
            return Err(QuicError::BufferTooSmall);
        }

        let _reserved = cursor.get_u16();
        let frag = cursor.get_u8();
        let address = Address::read_from(&mut cursor)?;

        let header_len = cursor.position() as usize;

        Ok((Self { frag, address }, header_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_request_serialization() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let request = Request::connect(Address::from(addr));
        let bytes = request.to_bytes();
        let parsed = Request::from_bytes(&bytes).unwrap();

        assert_eq!(request.version, parsed.version);
        assert_eq!(request.command, parsed.command);
        assert_eq!(request.address, parsed.address);
    }

    #[test]
    fn test_response_serialization() {
        let response = Response::success();
        let bytes = response.to_bytes();
        let parsed = Response::from_bytes(&bytes).unwrap();

        assert_eq!(response.version, parsed.version);
        assert_eq!(response.status, parsed.status);
    }

    #[test]
    fn test_udp_header() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let header = UdpHeader::new(Address::from(addr));
        let bytes = header.to_bytes();
        let (parsed, _) = UdpHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.frag, parsed.frag);
        assert_eq!(header.address, parsed.address);
    }
}
