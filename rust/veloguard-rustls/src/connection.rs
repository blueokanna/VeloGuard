//! TLS connection implementation

use crate::error::{Error, Result};
use crate::record::{RecordReader, RecordWriter, Record, ContentType, ProtocolVersion};
use crate::handshake::{HandshakeContext, ClientHello, ServerHello, HandshakeMessage, HandshakeType};
use crate::crypto::{CipherSuite, random_array};
use std::io::{Read, Write};

/// TLS connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state
    Initial,
    /// Handshake in progress
    Handshaking,
    /// Connection established
    Established,
    /// Connection closed
    Closed,
}

/// TLS connection
#[derive(Debug)]
pub struct Connection<R, W> {
    reader: RecordReader<R>,
    writer: RecordWriter<W>,
    state: ConnectionState,
    handshake_context: HandshakeContext,
    _cipher_suite: Option<CipherSuite>,
}

impl<R: Read, W: Write> Connection<R, W> {
    /// Create a new TLS connection
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: RecordReader::new(reader),
            writer: RecordWriter::new(writer),
            state: ConnectionState::Initial,
            handshake_context: HandshakeContext::new(),
            _cipher_suite: None,
        }
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Check if connection is established
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established
    }

    /// Send ClientHello message
    pub fn send_client_hello(&mut self, server_name: Option<&str>) -> Result<()> {
        let client_hello = ClientHello::new(server_name)?;
        let hello_data = client_hello.encode();
        let hello_msg = HandshakeMessage::new(HandshakeType::ClientHello, hello_data);

        // Add to handshake context
        self.handshake_context.add_message(&hello_msg.encode());

        let record = Record::new(ContentType::Handshake, ProtocolVersion::TLS_1_2, hello_msg.encode());
        self.writer.write_record(&record)?;

        self.state = ConnectionState::Handshaking;
        Ok(())
    }

    /// Receive ServerHello message
    pub fn receive_server_hello(&mut self) -> Result<ServerHello> {
        let record = self.reader.read_record()?;

        if record.content_type != ContentType::Handshake {
            return Err(Error::UnexpectedMessage("Expected handshake message".to_string()));
        }

        let handshake_msg = HandshakeMessage::decode(&record.data)?;
        if handshake_msg.msg_type != HandshakeType::ServerHello {
            return Err(Error::UnexpectedMessage("Expected ServerHello".to_string()));
        }

        // Add to handshake context
        self.handshake_context.add_message(&record.data);

        // Parse ServerHello
        // For now, return a basic ServerHello
        Ok(ServerHello {
            version: ProtocolVersion::TLS_1_2,
            random: random_array()?,
            session_id: Vec::new(),
            cipher_suite: CipherSuite::TlsAes256GcmSha384,
            compression_method: 0,
            extensions: Vec::new(),
        })
    }

    /// Read data from the connection
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.is_established() {
            return Err(Error::Protocol("Connection not established".to_string()));
        }

        let record = self.reader.read_record()?;

        match record.content_type {
            ContentType::ApplicationData => {
                // Decrypt data if needed
                let data_len = std::cmp::min(buf.len(), record.data.len());
                buf[..data_len].copy_from_slice(&record.data[..data_len]);
                Ok(data_len)
            }
            _ => Err(Error::UnexpectedMessage("Expected application data".to_string())),
        }
    }

    /// Write data to the connection
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.is_established() {
            return Err(Error::Protocol("Connection not established".to_string()));
        }

        let record = Record::new(ContentType::ApplicationData, ProtocolVersion::TLS_1_2, data.to_vec());
        self.writer.write_record(&record)?;
        Ok(data.len())
    }

    /// Close the connection
    pub fn close(&mut self) -> Result<()> {
        if self.state != ConnectionState::Closed {
            // Send close notify alert
            let alert = [0x01, 0x00]; // close_notify
            let record = Record::new(ContentType::Alert, ProtocolVersion::TLS_1_2, alert.to_vec());
            let _ = self.writer.write_record(&record); // Ignore errors during close
            self.state = ConnectionState::Closed;
        }
        Ok(())
    }
}
