use std::sync::Arc;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector as TokioTlsConnector;

use super::config::ClientConfig;
use super::error::{TlsError, Result};
use super::stream::TlsStream;
use super::verifier::SkipServerVerification;

pub struct TlsConnector {
    inner: TokioTlsConnector,
    config: ClientConfig,
}

impl TlsConnector {
    pub fn new(config: ClientConfig) -> Result<Self> {
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

        let connector = TokioTlsConnector::from(Arc::new(tls_config));

        Ok(Self { inner: connector, config })
    }

    pub async fn connect<S>(&self, stream: S, server_name: &str) -> Result<TlsStream<tokio_rustls::client::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let name = self.config.server_name.as_deref().unwrap_or(server_name);
        let server_name = ServerName::try_from(name.to_string())
            .map_err(|_| TlsError::InvalidConfig("Invalid server name".to_string()))?;

        let tls_stream = self.inner.connect(server_name, stream).await
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        Ok(TlsStream::new(tls_stream))
    }
}
