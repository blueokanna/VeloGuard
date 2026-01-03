//! TLS record protocol implementation

use crate::error::{Error, Result};
use crate::crypto::{CipherSuite, KeyMaterial};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
use std::io::{Read, Write};

/// TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn to_protocol_version(self) -> ProtocolVersion {
        match self {
            TlsVersion::Tls12 => ProtocolVersion::TLS_1_2,
            TlsVersion::Tls13 => ProtocolVersion::TLS_1_3,
        }
    }
}

/// TLS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

impl ContentType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            24 => Ok(ContentType::Heartbeat),
            _ => Err(Error::InvalidRecord(format!("Unknown content type: {}", value))),
        }
    }
}

/// TLS record
#[derive(Debug)]
pub struct Record {
    pub content_type: ContentType,
    pub version: ProtocolVersion,
    pub data: Vec<u8>,
}

impl Record {
    /// Create a new record
    pub fn new(content_type: ContentType, version: ProtocolVersion, data: Vec<u8>) -> Self {
        Record {
            content_type,
            version,
            data,
        }
    }

    /// Encode record to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.content_type as u8);
        buf.extend_from_slice(&self.version.encode());
        let length = (self.data.len() as u16).to_be_bytes();
        buf.extend_from_slice(&length);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode record from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(Error::InvalidRecord("Record too short".to_string()));
        }

        let content_type = ContentType::from_u8(data[0])?;
        let version = ProtocolVersion::decode(&data[1..3])?;
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if data.len() < 5 + length {
            return Err(Error::InvalidRecord("Incomplete record".to_string()));
        }

        let record_data = data[5..5 + length].to_vec();

        Ok(Record {
            content_type,
            version,
            data: record_data,
        })
    }
}

/// Protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub const TLS_1_2: Self = ProtocolVersion { major: 3, minor: 3 };
    pub const TLS_1_3: Self = ProtocolVersion { major: 3, minor: 4 };

    pub fn encode(&self) -> [u8; 2] {
        [self.major, self.minor]
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != 2 {
            return Err(Error::DecodingError("Invalid version length".to_string()));
        }
        Ok(ProtocolVersion {
            major: data[0],
            minor: data[1],
        })
    }
}

/// TLS record reader
#[derive(Debug)]
pub struct RecordReader<R> {
    pub inner: R,
    buffer: Vec<u8>,
}

impl<R: Read> RecordReader<R> {
    pub fn new(inner: R) -> Self {
        RecordReader {
            inner,
            buffer: Vec::new(),
        }
    }

    pub fn read_record(&mut self) -> Result<Record> {
        // Read record header
        while self.buffer.len() < 5 {
            let mut buf = [0u8; 1];
            match self.inner.read(&mut buf) {
                Ok(0) => return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                ))),
                Ok(_) => self.buffer.push(buf[0]),
                Err(e) => return Err(Error::Io(e)),
            }
        }

        // Parse header
        let length = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        let total_length = 5 + length;

        // Read record body
        while self.buffer.len() < total_length {
            let mut buf = [0u8; 1];
            match self.inner.read(&mut buf) {
                Ok(0) => return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                ))),
                Ok(_) => self.buffer.push(buf[0]),
                Err(e) => return Err(Error::Io(e)),
            }
        }

        // Parse record
        let record = Record::decode(&self.buffer[..total_length])?;
        self.buffer.drain(..total_length);

        Ok(record)
    }
}

/// TLS record writer
#[derive(Debug)]
pub struct RecordWriter<W> {
    pub inner: W,
}

impl<W: Write> RecordWriter<W> {
    pub fn new(inner: W) -> Self {
        RecordWriter { inner }
    }

    pub fn write_record(&mut self, record: &Record) -> Result<()> {
        let data = record.encode();
        self.inner.write_all(&data)?;
        self.inner.flush()?;
        Ok(())
    }
}

/// Encrypted record reader/writer
pub struct EncryptedRecordStream<R, W> {
    reader: RecordReader<R>,
    writer: RecordWriter<W>,
    key_material: Option<KeyMaterial>,
}

impl<R: Read, W: Write> EncryptedRecordStream<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        EncryptedRecordStream {
            reader: RecordReader::new(reader),
            writer: RecordWriter::new(writer),
            key_material: None,
        }
    }

    pub fn set_key_material(&mut self, key_material: KeyMaterial) {
        self.key_material = Some(key_material);
    }

    pub fn read_record(&mut self) -> Result<Record> {
        let mut record = self.reader.read_record()?;

        if let Some(ref key_material) = self.key_material {
            // Decrypt record
            record = self.decrypt_record(record, key_material)?;
        }

        Ok(record)
    }

    pub fn write_record(&mut self, mut record: Record) -> Result<()> {
        if let Some(ref key_material) = self.key_material {
            // Encrypt record
            record = self.encrypt_record(record, key_material)?;
        }

        self.writer.write_record(&record)
    }

    fn decrypt_record(&self, record: Record, key_material: &KeyMaterial) -> Result<Record> {
        match record.content_type {
            ContentType::ApplicationData => {
                // Decrypt application data
                let decrypted = self.decrypt(&record.data, key_material)?;
                Ok(Record::new(record.content_type, record.version, decrypted))
            }
            _ => Ok(record), // Other record types may not be encrypted
        }
    }

    fn encrypt_record(&self, record: Record, key_material: &KeyMaterial) -> Result<Record> {
        match record.content_type {
            ContentType::ApplicationData => {
                // Encrypt application data
                let encrypted = self.encrypt(&record.data, key_material)?;
                Ok(Record::new(ContentType::ApplicationData, record.version, encrypted))
            }
            _ => Ok(record), // Other record types may not be encrypted
        }
    }

    fn decrypt(&self, data: &[u8], key_material: &KeyMaterial) -> Result<Vec<u8>> {
        let cipher = self.get_cipher(key_material.cipher_suite)?;
        let key = LessSafeKey::new(UnboundKey::new(&cipher, &key_material.key).map_err(|_| {
            Error::DecryptError("Invalid key".to_string())
        })?);

        let nonce = Nonce::try_assume_unique_for_key(&key_material.nonce)
            .map_err(|_| Error::DecryptError("Invalid nonce".to_string()))?;

        let mut in_out = data.to_vec();
        let aad = Aad::empty();

        key.open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| Error::DecryptError("Decryption failed".to_string()))?;

        // Remove auth tag
        let tag_len = cipher.tag_len();
        in_out.truncate(in_out.len() - tag_len);

        Ok(in_out)
    }

    fn encrypt(&self, data: &[u8], key_material: &KeyMaterial) -> Result<Vec<u8>> {
        let cipher = self.get_cipher(key_material.cipher_suite)?;
        let key = LessSafeKey::new(UnboundKey::new(&cipher, &key_material.key).map_err(|_| {
            Error::EncryptError("Invalid key".to_string())
        })?);

        let nonce = Nonce::try_assume_unique_for_key(&key_material.nonce)
            .map_err(|_| Error::EncryptError("Invalid nonce".to_string()))?;

        let mut in_out = data.to_vec();
        let aad = Aad::empty();

        key.seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| Error::EncryptError("Encryption failed".to_string()))?;

        Ok(in_out)
    }

    fn get_cipher(&self, cipher_suite: CipherSuite) -> Result<&'static ring::aead::Algorithm> {
        match cipher_suite {
            CipherSuite::TlsAes128GcmSha256 => Ok(&AES_128_GCM),
            CipherSuite::TlsAes256GcmSha384 => Ok(&AES_256_GCM),
            CipherSuite::TlsChacha20Poly1305Sha256 => Ok(&CHACHA20_POLY1305),
        }
    }
}
