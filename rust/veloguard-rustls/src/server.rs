use crate::config::ServerConfig;
use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::x509::{Certificate, PrivateKey};
use crate::record::TlsVersion;
use crate::crypto::CipherSuite;
use crate::stream::TlsStream;
use std::io::{Read, Write};

/// TLS acceptor for server connections
#[derive(Debug)]
pub struct TlsAcceptor {
    config: ServerConfig,
}

impl TlsAcceptor {
    /// Create a new TLS acceptor from configuration
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    /// Create a new TLS acceptor with certificate and private key
    pub fn with_cert(cert: Certificate, key: PrivateKey) -> Result<Self> {
        let mut chain = crate::x509::CertificateChain::new();
        chain.add(cert);
        let config = ServerConfig::new(chain, key);
        Ok(Self::new(config))
    }

    /// Accept a TLS connection over the given stream
    pub fn accept<R, W>(&self, reader: R, writer: W) -> Result<TlsStream<R, W>>
    where
        R: Read,
        W: Write,
    {
        let connection = Connection::new(reader, writer);
        let mut stream = TlsStream::new(connection);

        // Send ServerHello
        let server_hello = self.create_server_hello()?;
        stream.write_all(&server_hello)?;

        // Send server certificate
        let certificate_msg = self.create_certificate_message()?;
        stream.write_all(&certificate_msg)?;

        // Send ServerHelloDone
        let hello_done = self.create_server_hello_done()?;
        stream.write_all(&hello_done)?;

        // Read client key exchange and other handshake messages
        let mut handshake_buf = [0u8; 4096];
        let n = stream.read(&mut handshake_buf)?;
        let handshake_data = &handshake_buf[..n];

        // Process client key exchange (simplified)
        self.process_client_key_exchange(handshake_data)?;

        Ok(stream)
    }

    // TODO: This method is currently unused but may be needed for proper ClientHello validation
    fn _validate_client_hello(&self, data: &[u8]) -> Result<()> {
        // Simplified ClientHello validation
        if data.len() < 5 || data[0] != 0x16 {
            return Err(Error::HandshakeFailed("Invalid ClientHello".to_string()));
        }

        // Check TLS version
        if data[1] != 0x03 || (data[2] != 0x03 && data[2] != 0x04) {
            return Err(Error::HandshakeFailed(
                "Unsupported TLS version".to_string(),
            ));
        }

        Ok(())
    }

    fn create_server_hello(&self) -> Result<Vec<u8>> {
        let mut hello = Vec::new();

        // TLS record header
        hello.extend_from_slice(&[0x16, 0x03, 0x03]); // handshake, TLS 1.2

        // Handshake data
        let mut handshake = Vec::new();
        handshake.push(2); // ServerHello

        // Length placeholder
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Protocol version
        match self.config.version {
            TlsVersion::Tls12 => handshake.extend_from_slice(&[0x03, 0x03]),
            TlsVersion::Tls13 => handshake.extend_from_slice(&[0x03, 0x04]),
        }

        // Random (32 bytes)
        let random: [u8; 32] = rand::random();
        handshake.extend_from_slice(&random);

        // Session ID (empty)
        handshake.push(0);

        // Selected cipher suite (first one from config)
        let cipher_suite = match self.config.cipher_suites.first() {
            Some(CipherSuite::TlsAes128GcmSha256) => [0x13, 0x01],
            Some(CipherSuite::TlsAes256GcmSha384) => [0x13, 0x02],
            Some(CipherSuite::TlsChacha20Poly1305Sha256) => [0x13, 0x03],
            None => [0x13, 0x01], // default
        };
        handshake.extend_from_slice(&cipher_suite);

        // Compression method (none)
        handshake.push(0);

        // Extensions (empty for now)
        handshake.extend_from_slice(&[0x00, 0x00]);

        // Fix handshake length
        let len = (handshake.len() - 4) as u32;
        handshake[1..4].copy_from_slice(&(len.to_be_bytes()[1..]));

        // Add to record
        let record_len = (handshake.len() as u16).to_be_bytes();
        hello.extend_from_slice(&record_len);
        hello.extend_from_slice(&handshake);

        Ok(hello)
    }

    fn create_certificate_message(&self) -> Result<Vec<u8>> {
        let cert = self.config.cert_chain.certificates().first()
            .ok_or_else(|| Error::Protocol("No certificate configured".to_string()))?;

        let mut msg = Vec::new();

        // TLS record header
        msg.extend_from_slice(&[0x16, 0x03, 0x03]);

        // Handshake data
        let mut handshake = Vec::new();
        handshake.push(11); // Certificate

        // Certificate data
        let cert_data = cert.as_der();
        let cert_len = (cert_data.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&cert_len[1..]); // 3 bytes
        handshake.extend_from_slice(cert_data);

        // Add handshake length
        let handshake_len = (handshake.len() - 4) as u32;
        let len_bytes = handshake_len.to_be_bytes();
        handshake[1..4].copy_from_slice(&len_bytes[1..]);

        // Record length
        let record_len = (handshake.len() as u16).to_be_bytes();
        msg.extend_from_slice(&record_len);
        msg.extend_from_slice(&handshake);

        Ok(msg)
    }

    fn create_server_hello_done(&self) -> Result<Vec<u8>> {
        let mut msg = Vec::new();

        // TLS record header
        msg.extend_from_slice(&[0x16, 0x03, 0x03]);

        // Handshake data
        let handshake = vec![
            14, // ServerHelloDone
            0x00, 0x00, 0x00, // length
        ];

        // Record length
        let record_len = (handshake.len() as u16).to_be_bytes();
        msg.extend_from_slice(&record_len);
        msg.extend_from_slice(&handshake);

        Ok(msg)
    }

    fn process_client_key_exchange(&self, data: &[u8]) -> Result<()> {
        // Simplified client key exchange processing
        // In real implementation, this would decrypt pre-master secret,
        // derive session keys, etc.

        if data.is_empty() {
            return Err(Error::HandshakeFailed(
                "Empty client key exchange".to_string(),
            ));
        }

        Ok(())
    }
}

