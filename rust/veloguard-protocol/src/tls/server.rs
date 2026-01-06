use std::sync::Arc;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;

use super::config::ServerConfig;
use super::error::{TlsError, Result};
use super::stream::TlsStream;

pub struct TlsAcceptor {
    inner: TokioTlsAcceptor,
}

impl TlsAcceptor {
    pub fn new(config: ServerConfig) -> Result<Self> {
        let cert_pem = config.certificate.as_bytes();
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*cert_pem)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(TlsError::Certificate("No certificates found".to_string()));
        }

        let key_pem = config.private_key.as_bytes();
        let key = rustls_pemfile::private_key(&mut &*key_pem)
            .map_err(|e| TlsError::Certificate(format!("Invalid private key: {}", e)))?
            .ok_or_else(|| TlsError::Certificate("No private key found".to_string()))?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::Tls(e.to_string()))?;

        tls_config.alpn_protocols = config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        let acceptor = TokioTlsAcceptor::from(Arc::new(tls_config));

        Ok(Self { inner: acceptor })
    }

    pub async fn accept<S>(&self, stream: S) -> Result<TlsStream<tokio_rustls::server::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let tls_stream = self.inner.accept(stream).await
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        Ok(TlsStream::new(tls_stream))
    }
}
