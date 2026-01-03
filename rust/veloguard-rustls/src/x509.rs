//! X.509 certificate handling

use crate::error::{Error, Result};
use base64::{Engine as _, engine::general_purpose};

/// Certificate representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate(pub Vec<u8>);

impl Certificate {
    /// Create certificate from PEM format
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pem_str = std::str::from_utf8(pem)
            .map_err(|_| Error::InvalidCertificate("Invalid PEM encoding".to_string()))?;

        if !pem_str.contains("BEGIN CERTIFICATE") || !pem_str.contains("END CERTIFICATE") {
            return Err(Error::InvalidCertificate("Not a certificate".to_string()));
        }

        // Extract base64 content between BEGIN and END markers
        let start = pem_str.find("BEGIN CERTIFICATE")
            .ok_or_else(|| Error::InvalidCertificate("Missing BEGIN CERTIFICATE".to_string()))?
            + "BEGIN CERTIFICATE".len();
        let end = pem_str.find("END CERTIFICATE")
            .ok_or_else(|| Error::InvalidCertificate("Missing END CERTIFICATE".to_string()))?;

        let base64_content = pem_str[start..end].trim();

        let der = general_purpose::STANDARD
            .decode(base64_content)
            .map_err(|_| Error::InvalidCertificate("Invalid base64 in certificate".to_string()))?;

        Ok(Certificate(der))
    }

    /// Create certificate from DER format
    pub fn from_der(der: Vec<u8>) -> Self {
        Certificate(der)
    }

    /// Get DER bytes
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }

    /// Get certificate as PEM string
    pub fn to_pem(&self) -> Result<String> {
        let base64 = general_purpose::STANDARD.encode(&self.0);
        Ok(format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64.chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

/// Private key representation
#[derive(Debug, Clone)]
pub struct PrivateKey(pub Vec<u8>);

impl PrivateKey {
    /// Create private key from PEM format
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pem_str = std::str::from_utf8(pem)
            .map_err(|_| Error::InvalidCertificate("Invalid PEM encoding".to_string()))?;

        // Support both PKCS#1 and PKCS#8
        let (begin_marker, end_marker) = if pem_str.contains("BEGIN PRIVATE KEY") {
            ("BEGIN PRIVATE KEY", "END PRIVATE KEY")
        } else if pem_str.contains("BEGIN RSA PRIVATE KEY") {
            ("BEGIN RSA PRIVATE KEY", "END RSA PRIVATE KEY")
        } else if pem_str.contains("BEGIN EC PRIVATE KEY") {
            ("BEGIN EC PRIVATE KEY", "END EC PRIVATE KEY")
        } else {
            return Err(Error::InvalidCertificate("Not a private key".to_string()));
        };

        let start = pem_str.find(begin_marker)
            .ok_or_else(|| Error::InvalidCertificate(format!("Missing {}", begin_marker)))?
            + begin_marker.len();
        let end = pem_str.find(end_marker)
            .ok_or_else(|| Error::InvalidCertificate(format!("Missing {}", end_marker)))?;

        let base64_content = pem_str[start..end].trim();

        let der = general_purpose::STANDARD
            .decode(base64_content)
            .map_err(|_| Error::InvalidCertificate("Invalid base64 in private key".to_string()))?;

        Ok(PrivateKey(der))
    }

    /// Create private key from DER format
    pub fn from_der(der: Vec<u8>) -> Self {
        PrivateKey(der)
    }

    /// Get DER bytes
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }

    /// Get private key as PEM string (PKCS#8 format)
    pub fn to_pem(&self) -> Result<String> {
        let base64 = general_purpose::STANDARD.encode(&self.0);
        Ok(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64.chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

/// Certificate chain
#[derive(Debug, Clone)]
pub struct CertificateChain(pub Vec<Certificate>);

impl CertificateChain {
    /// Create empty certificate chain
    pub fn new() -> Self {
        CertificateChain(Vec::new())
    }

    /// Add certificate to chain
    pub fn add(&mut self, cert: Certificate) {
        self.0.push(cert);
    }

    /// Get certificates
    pub fn certificates(&self) -> &[Certificate] {
        &self.0
    }

    /// Get leaf certificate
    pub fn leaf(&self) -> Option<&Certificate> {
        self.0.first()
    }
}

impl Default for CertificateChain {
    fn default() -> Self {
        Self::new()
    }
}
