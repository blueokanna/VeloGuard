use crate::error::Result;
use crate::config::ClientConfig;
use crate::connection::Connection;
use crate::stream::TlsStream;
use crate::x509::Certificate;
use std::io::{Read, Write};

/// TLS connector for client connections
#[derive(Debug)]
pub struct TlsConnector {
    config: ClientConfig,
}

impl TlsConnector {
    /// Create a new TLS connector with default configuration
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: ClientConfig::new(),
        })
    }

    /// Add a root certificate for trust verification
    pub fn add_root_certificate(&mut self, cert: Certificate) -> &mut Self {
        self.config.add_root_certificate(cert);
        self
    }

    /// Establish a TLS connection over the given stream
    pub fn connect<R, W>(
        &self,
        domain: &str,
        reader: R,
        writer: W,
    ) -> Result<TlsStream<R, W>>
    where
        R: Read,
        W: Write,
    {
        let mut connection = Connection::new(reader, writer);

        // Send ClientHello
        connection.send_client_hello(Some(domain))?;

        // Receive ServerHello
        let _server_hello = connection.receive_server_hello()?;

        // For now, mark as established (full handshake implementation needed)
        // In a complete implementation, this would include:
        // - Certificate verification
        // - Key exchange
        // - Finished message exchange

        Ok(TlsStream::new(connection))
    }
}

