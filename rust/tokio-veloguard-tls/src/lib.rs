pub use tokio::*;

pub mod client;
pub mod server;

pub use client::TlsConnector;
pub use client::TlsStream;
pub use server::TlsAcceptor;
pub use server::TlsStream as ServerTlsStream;

/// Error types for TLS operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Alert received: {0}")]
    AlertReceived(String),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// Cipher suite
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha256,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub version: TlsVersion,
    pub cipher_suites: Vec<CipherSuite>,
    pub server_name: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            version: TlsVersion::Tls13,
            cipher_suites: vec![
                CipherSuite::TlsAes256GcmSha384,
                CipherSuite::TlsAes128GcmSha256,
                CipherSuite::TlsChacha20Poly1305Sha256,
            ],
            server_name: None,
        }
    }
}

/// Certificate representation
#[derive(Debug, Clone)]
pub struct Certificate(pub Vec<u8>);

impl Certificate {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        // Basic PEM parsing - in real implementation this would be more robust
        let pem_str = std::str::from_utf8(pem)
            .map_err(|_| Error::InvalidCertificate("Invalid PEM encoding".to_string()))?;

        if !pem_str.contains("BEGIN CERTIFICATE") || !pem_str.contains("END CERTIFICATE") {
            return Err(Error::InvalidCertificate("Not a certificate".to_string()));
        }

        // Extract base64 content between BEGIN and END markers
        let start = pem_str.find("BEGIN CERTIFICATE").unwrap() + "BEGIN CERTIFICATE".len();
        let end = pem_str.find("END CERTIFICATE").unwrap();
        let base64_content = pem_str[start..end].trim();

        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, base64_content)
            .map_err(|_| Error::InvalidCertificate("Invalid base64 in certificate".to_string()))?;

        Ok(Certificate(der))
    }

    pub fn from_der(der: Vec<u8>) -> Self {
        Certificate(der)
    }

    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

/// Private key representation
#[derive(Debug, Clone)]
pub struct PrivateKey(pub Vec<u8>);

impl PrivateKey {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pem_str = std::str::from_utf8(pem)
            .map_err(|_| Error::InvalidCertificate("Invalid PEM encoding".to_string()))?;

        if !pem_str.contains("BEGIN PRIVATE KEY") || !pem_str.contains("END PRIVATE KEY") {
            return Err(Error::InvalidCertificate("Not a private key".to_string()));
        }

        let start = pem_str.find("BEGIN PRIVATE KEY").unwrap() + "BEGIN PRIVATE KEY".len();
        let end = pem_str.find("END PRIVATE KEY").unwrap();
        let base64_content = pem_str[start..end].trim();

        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, base64_content)
            .map_err(|_| Error::InvalidCertificate("Invalid base64 in private key".to_string()))?;

        Ok(PrivateKey(der))
    }

    pub fn from_der(der: Vec<u8>) -> Self {
        PrivateKey(der)
    }

    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}
