//! TLS handshake protocol implementation

use crate::error::{Error, Result};
use crate::record::{ProtocolVersion};
use crate::crypto::{CipherSuite, random_array, SignatureAlgorithm};
use crate::x509::CertificateChain;

/// Handshake message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    HelloRetryRequest = 6,
    EncryptedExtensions = 8,
    RequestConnectionId = 9,
    NewConnectionId = 10,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateUrl = 21,
    CertificateStatus = 22,
    SupplementalData = 23,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl HandshakeType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(HandshakeType::HelloRequest),
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            3 => Ok(HandshakeType::HelloVerifyRequest),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            6 => Ok(HandshakeType::HelloRetryRequest),
            8 => Ok(HandshakeType::EncryptedExtensions),
            9 => Ok(HandshakeType::RequestConnectionId),
            10 => Ok(HandshakeType::NewConnectionId),
            11 => Ok(HandshakeType::Certificate),
            12 => Ok(HandshakeType::ServerKeyExchange),
            13 => Ok(HandshakeType::CertificateRequest),
            14 => Ok(HandshakeType::ServerHelloDone),
            15 => Ok(HandshakeType::CertificateVerify),
            16 => Ok(HandshakeType::ClientKeyExchange),
            20 => Ok(HandshakeType::Finished),
            21 => Ok(HandshakeType::CertificateUrl),
            22 => Ok(HandshakeType::CertificateStatus),
            23 => Ok(HandshakeType::SupplementalData),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(Error::UnexpectedMessage(format!("Unknown handshake type: {}", value))),
        }
    }
}

/// TLS handshake message
#[derive(Debug)]
pub struct HandshakeMessage {
    pub msg_type: HandshakeType,
    pub data: Vec<u8>,
}

impl HandshakeMessage {
    pub fn new(msg_type: HandshakeType, data: Vec<u8>) -> Self {
        HandshakeMessage { msg_type, data }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.msg_type as u8);

        let length = (self.data.len() as u32).to_be_bytes();
        buf.extend_from_slice(&length[1..]); // 3 bytes for length

        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::DecodingError("Handshake message too short".to_string()));
        }

        let msg_type = HandshakeType::from_u8(data[0])?;
        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

        if data.len() < 4 + length {
            return Err(Error::DecodingError("Incomplete handshake message".to_string()));
        }

        let message_data = data[4..4 + length].to_vec();

        Ok(HandshakeMessage {
            msg_type,
            data: message_data,
        })
    }
}

/// ClientHello message
#[derive(Debug)]
pub struct ClientHello {
    pub version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn new(server_name: Option<&str>) -> Result<Self> {
        let random = random_array()?;
        let cipher_suites = vec![
            CipherSuite::TlsAes256GcmSha384,
            CipherSuite::TlsAes128GcmSha256,
            CipherSuite::TlsChacha20Poly1305Sha256,
        ];

        let mut extensions = Vec::new();

        // Server Name extension
        if let Some(name) = server_name {
            extensions.push(Extension::ServerName(vec![ServerName::new(name)]));
        }

        // Supported versions extension
        extensions.push(Extension::SupportedVersions(vec![
            ProtocolVersion::TLS_1_3,
            ProtocolVersion::TLS_1_2,
        ]));

        Ok(ClientHello {
            version: ProtocolVersion::TLS_1_2, // Legacy version
            random,
            session_id: Vec::new(),
            cipher_suites,
            compression_methods: vec![0], // null compression
            extensions,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Protocol version
        buf.extend_from_slice(&self.version.encode());

        // Random
        buf.extend_from_slice(&self.random);

        // Session ID
        buf.push(self.session_id.len() as u8);
        buf.extend_from_slice(&self.session_id);

        // Cipher suites
        let cipher_len = (self.cipher_suites.len() * 2) as u16;
        buf.extend_from_slice(&cipher_len.to_be_bytes());
        for suite in &self.cipher_suites {
            buf.extend_from_slice(&suite.to_u16().to_be_bytes());
        }

        // Compression methods
        buf.push(self.compression_methods.len() as u8);
        buf.extend_from_slice(&self.compression_methods);

        // Extensions
        if !self.extensions.is_empty() {
            let mut ext_data = Vec::new();
            for ext in &self.extensions {
                ext_data.extend_from_slice(&ext.encode());
            }
            let ext_len = (ext_data.len() as u16).to_be_bytes();
            buf.extend_from_slice(&ext_len);
            buf.extend_from_slice(&ext_data);
        }

        buf
    }
}

/// ServerHello message
#[derive(Debug)]
pub struct ServerHello {
    pub version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.version.encode());
        buf.extend_from_slice(&self.random);

        buf.push(self.session_id.len() as u8);
        buf.extend_from_slice(&self.session_id);

        buf.extend_from_slice(&self.cipher_suite.to_u16().to_be_bytes());
        buf.push(self.compression_method);

        if !self.extensions.is_empty() {
            let mut ext_data = Vec::new();
            for ext in &self.extensions {
                ext_data.extend_from_slice(&ext.encode());
            }
            let ext_len = (ext_data.len() as u16).to_be_bytes();
            buf.extend_from_slice(&ext_len);
            buf.extend_from_slice(&ext_data);
        }

        buf
    }
}

/// TLS extensions
#[derive(Debug, Clone)]
pub enum Extension {
    ServerName(Vec<ServerName>),
    SupportedVersions(Vec<ProtocolVersion>),
    SignatureAlgorithms(Vec<SignatureAlgorithm>),
    KeyShare(Vec<KeyShareEntry>),
    Unknown(u16, Vec<u8>),
}

impl Extension {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Extension::ServerName(names) => {
                let mut data = Vec::new();
                let name_len = (names.len() * 5) as u16; // Rough estimate
                data.extend_from_slice(&name_len.to_be_bytes());
                for name in names {
                    data.extend_from_slice(&name.encode());
                }
                Self::make_extension(0x0000, data)
            }
            Extension::SupportedVersions(versions) => {
                let mut data = Vec::new();
                data.push(versions.len() as u8 * 2);
                for version in versions {
                    data.extend_from_slice(&version.encode());
                }
                Self::make_extension(0x002b, data)
            }
            Extension::SignatureAlgorithms(algorithms) => {
                let mut data = Vec::new();
                let alg_len = (algorithms.len() * 2) as u16;
                data.extend_from_slice(&alg_len.to_be_bytes());
                for alg in algorithms {
                    data.extend_from_slice(&((*alg as u16).to_be_bytes()));
                }
                Self::make_extension(0x000d, data)
            }
            Extension::KeyShare(entries) => {
                let mut data = Vec::new();
                let share_len = (entries.len() * 36) as u16; // Rough estimate
                data.extend_from_slice(&share_len.to_be_bytes());
                for entry in entries {
                    data.extend_from_slice(&entry.encode());
                }
                Self::make_extension(0x0033, data)
            }
            Extension::Unknown(ext_type, data) => {
                Self::make_extension(*ext_type, data.clone())
            }
        }
    }

    fn make_extension(ext_type: u16, data: Vec<u8>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&ext_type.to_be_bytes());
        let len = (data.len() as u16).to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&data);
        buf
    }
}

/// Server Name Indication
#[derive(Debug, Clone)]
pub struct ServerName {
    pub name: String,
}

impl ServerName {
    pub fn new(name: &str) -> Self {
        ServerName {
            name: name.to_string(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0); // hostname type
        let name_len = (self.name.len() as u16).to_be_bytes();
        buf.extend_from_slice(&name_len);
        buf.extend_from_slice(self.name.as_bytes());
        buf
    }
}

/// Key share entry for TLS 1.3
#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.group as u16).to_be_bytes());
        let key_len = (self.key_exchange.len() as u16).to_be_bytes();
        buf.extend_from_slice(&key_len);
        buf.extend_from_slice(&self.key_exchange);
        buf
    }
}

/// Named groups for key exchange
#[derive(Debug, Clone, Copy)]
pub enum NamedGroup {
    X25519 = 0x001d,
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
}

/// Certificate message
#[derive(Debug)]
pub struct CertificateMsg {
    pub certificate_chain: CertificateChain,
}

impl CertificateMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Certificate request context (empty for TLS 1.2)
        buf.push(0);

        // Certificate list
        let mut cert_data = Vec::new();
        for cert in self.certificate_chain.certificates() {
            let cert_der = cert.as_der();
            let cert_len = (cert_der.len() as u32).to_be_bytes();
            cert_data.extend_from_slice(&cert_len[1..]); // 3 bytes
            cert_data.extend_from_slice(cert_der);
        }

        let cert_list_len = (cert_data.len() as u32).to_be_bytes();
        buf.extend_from_slice(&cert_list_len[1..]); // 3 bytes
        buf.extend_from_slice(&cert_data);

        buf
    }
}

/// Client Key Exchange message
#[derive(Debug)]
pub struct ClientKeyExchange {
    pub key_exchange_data: Vec<u8>,
}

impl ClientKeyExchange {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let len = (self.key_exchange_data.len() as u16).to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&self.key_exchange_data);
        buf
    }
}

/// Finished message
#[derive(Debug)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn encode(&self) -> Vec<u8> {
        self.verify_data.clone()
    }
}

/// Handshake context for tracking handshake messages
#[derive(Debug)]
pub struct HandshakeContext {
    pub messages: Vec<Vec<u8>>,
}

impl HandshakeContext {
    pub fn new() -> Self {
        HandshakeContext {
            messages: Vec::new(),
        }
    }

    pub fn add_message(&mut self, message: &[u8]) {
        self.messages.push(message.to_vec());
    }

    pub fn transcript_hash(&self, algorithm: &'static ring::digest::Algorithm) -> Vec<u8> {
        let mut ctx = ring::digest::Context::new(algorithm);
        for message in &self.messages {
            ctx.update(message);
        }
        ctx.finish().as_ref().to_vec()
    }
}

impl Default for HandshakeContext {
    fn default() -> Self {
        Self::new()
    }
}
