use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

use super::address::Address;
use super::error::{Result, QuicError};
use super::PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Success = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
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

#[derive(Debug, Clone)]
pub struct Request {
    pub version: u8,
    pub command: Command,
    pub address: Address,
    pub payload: Option<Bytes>,
}

impl Request {
    pub fn connect(address: Address) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            command: Command::Connect,
            address,
            payload: None,
        }
    }

    pub fn udp_associate(address: Address) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            command: Command::UdpAssociate,
            address,
            payload: None,
        }
    }

    pub fn with_payload(mut self, payload: Bytes) -> Self {
        self.payload = Some(payload);
        self
    }

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

#[derive(Debug, Clone)]
pub struct Response {
    pub version: u8,
    pub status: ResponseStatus,
    pub address: Option<Address>,
}

impl Response {
    pub fn success() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status: ResponseStatus::Success,
            address: None,
        }
    }

    pub fn success_with_address(address: Address) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status: ResponseStatus::Success,
            address: Some(address),
        }
    }

    pub fn error(status: ResponseStatus) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status,
            address: None,
        }
    }

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

    pub fn is_success(&self) -> bool {
        self.status == ResponseStatus::Success
    }
}

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub frag: u8,
    pub address: Address,
}

impl UdpHeader {
    pub fn new(address: Address) -> Self {
        Self { frag: 0, address }
    }

    pub fn to_bytes(&self) -> Bytes {
        let addr_len = self.address.serialized_len();
        let mut buf = BytesMut::with_capacity(3 + addr_len);

        buf.put_u16(0);
        buf.put_u8(self.frag);
        self.address.write_to(&mut buf);

        buf.freeze()
    }

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
