//! TLS configuration

use crate::x509::{Certificate, CertificateChain, PrivateKey};
use crate::crypto::CipherSuite;
use crate::record::TlsVersion;

/// Client configuration for TLS connections
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Root certificates for trust verification
    pub root_certs: Vec<Certificate>,
    /// Enabled cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Server name indication
    pub server_name: Option<String>,
}

impl ClientConfig {
    /// Create a new client configuration
    pub fn new() -> Self {
        Self {
            root_certs: Vec::new(),
            cipher_suites: vec![
                CipherSuite::TlsAes256GcmSha384,
                CipherSuite::TlsAes128GcmSha256,
                CipherSuite::TlsChacha20Poly1305Sha256,
            ],
            server_name: None,
        }
    }

    /// Add a root certificate
    pub fn add_root_certificate(&mut self, cert: Certificate) -> &mut Self {
        self.root_certs.push(cert);
        self
    }

    /// Set server name
    pub fn set_server_name(&mut self, name: &str) -> &mut Self {
        self.server_name = Some(name.to_string());
        self
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Server configuration for TLS connections
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server certificate chain
    pub cert_chain: CertificateChain,
    /// Private key
    pub private_key: PrivateKey,
    /// Enabled cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// TLS version to use
    pub version: TlsVersion,
}

impl ServerConfig {
    /// Create a new server configuration
    pub fn new(cert_chain: CertificateChain, private_key: PrivateKey) -> Self {
        Self {
            cert_chain,
            private_key,
            cipher_suites: vec![
                CipherSuite::TlsAes256GcmSha384,
                CipherSuite::TlsAes128GcmSha256,
                CipherSuite::TlsChacha20Poly1305Sha256,
            ],
            version: TlsVersion::Tls13,
        }
    }

    /// Set cipher suites
    pub fn set_cipher_suites(&mut self, suites: Vec<CipherSuite>) -> &mut Self {
        self.cipher_suites = suites;
        self
    }
}
