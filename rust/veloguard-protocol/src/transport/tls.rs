use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector;

use super::{Result, TransportError};

#[cfg(feature = "tls")]
use crate::tls::SkipServerVerification;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsFingerprint {
    #[default]
    None,
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default = "default_enable_sni")]
    pub enable_sni: bool,
    #[serde(default)]
    pub fingerprint: TlsFingerprint,
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub max_version: Option<String>,
}

fn default_enable_sni() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            sni: None,
            alpn: vec!["h2".into(), "http/1.1".into()],
            skip_cert_verify: false,
            enable_sni: true,
            fingerprint: TlsFingerprint::None,
            min_version: None,
            max_version: None,
        }
    }
}

pub struct TlsTransport {
    config: TlsConfig,
    connector: TlsConnector,
    server_name: String,
}

impl TlsTransport {
    pub fn new(config: TlsConfig, server_name: &str) -> Result<Self> {
        let connector = Self::build_connector(&config)?;
        let sni = config.sni.clone().unwrap_or_else(|| server_name.to_string());
        
        Ok(Self {
            config,
            connector,
            server_name: sni,
        })
    }

    fn build_connector(config: &TlsConfig) -> Result<TlsConnector> {
        let mut root_store = rustls::RootCertStore::empty();
        
        let certs = rustls_native_certs::load_native_certs();
        for cert in certs.certs {
            root_store.add(cert).ok();
        }

        let builder = rustls::ClientConfig::builder()
            .with_root_certificates(root_store);

        let mut tls_config = if config.skip_cert_verify {
            let verifier = Arc::new(SkipServerVerification);
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        } else {
            builder.with_no_client_auth()
        };

        tls_config.alpn_protocols = config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        if !config.enable_sni {
            tls_config.enable_sni = false;
        }

        Self::apply_fingerprint(&mut tls_config, config.fingerprint);

        Ok(TlsConnector::from(Arc::new(tls_config)))
    }

    fn apply_fingerprint(config: &mut rustls::ClientConfig, fingerprint: TlsFingerprint) {
        match fingerprint {
            TlsFingerprint::None => {}
            TlsFingerprint::Chrome => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            TlsFingerprint::Firefox => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            TlsFingerprint::Safari => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            TlsFingerprint::Ios => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            TlsFingerprint::Android => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            TlsFingerprint::Edge => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            TlsFingerprint::Random => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
        }
    }

    pub async fn connect<S>(&self, stream: S) -> Result<TlsStream<tokio_rustls::client::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| TransportError::InvalidConfig(format!("Invalid SNI: {}", self.server_name)))?;

        let tls_stream = self.connector.connect(server_name, stream).await
            .map_err(|e| TransportError::Handshake(format!("TLS handshake failed: {}", e)))?;

        Ok(TlsStream::new(tls_stream))
    }

    pub fn config(&self) -> &TlsConfig {
        &self.config
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

pub struct TlsStream<S> {
    inner: S,
}

impl<S> TlsStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(not(feature = "tls"))]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(not(feature = "tls"))]
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert!(config.sni.is_none());
        assert_eq!(config.alpn, vec!["h2", "http/1.1"]);
        assert!(!config.skip_cert_verify);
        assert!(config.enable_sni);
        assert_eq!(config.fingerprint, TlsFingerprint::None);
    }

    #[test]
    fn test_tls_transport_new() {
        let config = TlsConfig::default();
        let transport = TlsTransport::new(config, "example.com").unwrap();
        assert_eq!(transport.server_name(), "example.com");
    }

    #[test]
    fn test_tls_transport_with_custom_sni() {
        let config = TlsConfig {
            sni: Some("custom.sni.com".to_string()),
            ..Default::default()
        };
        let transport = TlsTransport::new(config, "example.com").unwrap();
        assert_eq!(transport.server_name(), "custom.sni.com");
    }

    #[test]
    fn test_tls_config_serialization() {
        let config = TlsConfig {
            sni: Some("test.com".to_string()),
            alpn: vec!["h2".to_string()],
            skip_cert_verify: true,
            enable_sni: true,
            fingerprint: TlsFingerprint::Chrome,
            min_version: None,
            max_version: None,
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TlsConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.sni, config.sni);
        assert_eq!(deserialized.alpn, config.alpn);
        assert_eq!(deserialized.skip_cert_verify, config.skip_cert_verify);
        assert_eq!(deserialized.fingerprint, config.fingerprint);
    }
}
