use crate::{Error, Result, TlsConfig, Certificate, PrivateKey};
use std::io::{Read, Write};

/// TLS acceptor for server connections
#[derive(Debug)]
pub struct TlsAcceptor {
    config: TlsConfig,
    certificate: Option<Certificate>,
    private_key: Option<PrivateKey>,
}

impl TlsAcceptor {
    /// Create a new TLS acceptor
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: TlsConfig::default(),
            certificate: None,
            private_key: None,
        })
    }

    /// Set the server certificate
    pub fn set_certificate(&mut self, cert: Certificate) -> Result<()> {
        self.certificate = Some(cert);
        Ok(())
    }

    /// Set the private key
    pub fn set_private_key(&mut self, key: PrivateKey) -> Result<()> {
        self.private_key = Some(key);
        Ok(())
    }

    /// Accept a TLS connection over the given stream
    pub fn accept<S>(&self, mut stream: S) -> Result<TlsStream<S>>
    where
        S: Read + Write,
    {
        // Check if certificate and key are set
        let _cert = self.certificate.as_ref()
            .ok_or_else(|| Error::Protocol("Server certificate not set".to_string()))?;
        let _key = self.private_key.as_ref()
            .ok_or_else(|| Error::Protocol("Private key not set".to_string()))?;

        // Read ClientHello
        let mut client_hello_buf = [0u8; 4096];
        let n = stream.read(&mut client_hello_buf)?;
        let client_hello = &client_hello_buf[..n];

        // Parse ClientHello (simplified)
        self.validate_client_hello(client_hello)?;

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

        Ok(TlsStream {
            stream,
            established: true,
        })
    }

    fn validate_client_hello(&self, data: &[u8]) -> Result<()> {
        // Simplified ClientHello validation
        if data.len() < 5 || data[0] != 0x16 {
            return Err(Error::HandshakeFailed("Invalid ClientHello".to_string()));
        }

        // Check TLS version
        if data[1] != 0x03 || (data[2] != 0x03 && data[2] != 0x04) {
            return Err(Error::HandshakeFailed("Unsupported TLS version".to_string()));
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
            crate::TlsVersion::Tls12 => handshake.extend_from_slice(&[0x03, 0x03]),
            crate::TlsVersion::Tls13 => handshake.extend_from_slice(&[0x03, 0x04]),
        }

        // Random (32 bytes)
        let random: [u8; 32] = rand::random();
        handshake.extend_from_slice(&random);

        // Session ID (empty)
        handshake.push(0);

        // Selected cipher suite (first one from config)
        let cipher_suite = match self.config.cipher_suites.first() {
            Some(crate::CipherSuite::TlsAes128GcmSha256) => [0x13, 0x01],
            Some(crate::CipherSuite::TlsAes256GcmSha384) => [0x13, 0x02],
            Some(crate::CipherSuite::TlsChacha20Poly1305Sha256) => [0x13, 0x03],
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
        let cert = self.certificate.as_ref()
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
            return Err(Error::HandshakeFailed("Empty client key exchange".to_string()));
        }

        Ok(())
    }
}

/// TLS stream wrapper for server
#[derive(Debug)]
pub struct TlsStream<S> {
    stream: S,
    established: bool,
}

impl<S> TlsStream<S> {
    /// Get the inner stream back
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Check if TLS connection is established
    pub fn is_established(&self) -> bool {
        self.established
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // In real implementation, this would decrypt TLS records
        self.stream.read(buf)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // In real implementation, this would encrypt data into TLS records
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
