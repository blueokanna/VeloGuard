use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, RecvStream, SendStream,
    ServerConfig as QuinnServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[derive(Debug, Error)]
pub enum TuicQuinnError {
    #[error("QUIC connection error: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid configuration")]
    InvalidConfig,
    #[error("Connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("Rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("Write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("Read error: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("Read to end error: {0}")]
    ReadToEnd(#[from] quinn::ReadToEndError),
    #[error("Closed stream: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("Send datagram error: {0}")]
    SendDatagram(#[from] quinn::SendDatagramError),
    #[error("Protocol error: {0}")]
    Protocol(String),
}

pub struct TuicQuinnEndpoint {
    endpoint: Endpoint,
    is_server: bool,
}

impl TuicQuinnEndpoint {
    pub fn client(local_addr: SocketAddr) -> Result<Self, TuicQuinnError> {
        let endpoint = Endpoint::client(local_addr)?;

        Ok(Self {
            endpoint,
            is_server: false,
        })
    }

    pub fn server(
        local_addr: SocketAddr,
        server_config: QuinnServerConfig,
    ) -> Result<Self, TuicQuinnError> {
        let endpoint = Endpoint::server(server_config, local_addr)?;

        Ok(Self {
            endpoint,
            is_server: true,
        })
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<TuicQuinnConnection, TuicQuinnError> {
        if self.is_server {
            return Err(TuicQuinnError::InvalidConfig);
        }

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let client_config = QuinnClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TuicQuinnError::Protocol(e.to_string()))?,
        ));

        let connecting = self
            .endpoint
            .connect_with(client_config, addr, server_name)?;
        let connection = connecting.await?;

        Ok(TuicQuinnConnection { connection })
    }

    pub async fn accept(&self) -> Result<TuicQuinnConnection, TuicQuinnError> {
        if !self.is_server {
            return Err(TuicQuinnError::InvalidConfig);
        }

        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TuicQuinnError::InvalidConfig)?;
        let connection = incoming.await?;

        Ok(TuicQuinnConnection { connection })
    }

    pub fn stats(&self) -> quinn::EndpointStats {
        self.endpoint.stats()
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), &[]);
    }
}

pub struct TuicQuinnConnection {
    connection: Connection,
}

impl TuicQuinnConnection {
    pub async fn open_uni(&self) -> Result<TuicQuinnSendStream, TuicQuinnError> {
        let stream = self.connection.open_uni().await?;
        Ok(TuicQuinnSendStream { stream })
    }

    pub async fn open_bi(
        &self,
    ) -> Result<(TuicQuinnSendStream, TuicQuinnRecvStream), TuicQuinnError> {
        let (send, recv) = self.connection.open_bi().await?;
        Ok((
            TuicQuinnSendStream { stream: send },
            TuicQuinnRecvStream { stream: recv },
        ))
    }

    pub async fn accept_uni(&self) -> Result<TuicQuinnRecvStream, TuicQuinnError> {
        let stream = self.connection.accept_uni().await?;
        Ok(TuicQuinnRecvStream { stream })
    }

    pub async fn accept_bi(
        &self,
    ) -> Result<(TuicQuinnSendStream, TuicQuinnRecvStream), TuicQuinnError> {
        let (send, recv) = self.connection.accept_bi().await?;
        Ok((
            TuicQuinnSendStream { stream: send },
            TuicQuinnRecvStream { stream: recv },
        ))
    }

    pub fn send_datagram(&self, data: &[u8]) -> Result<(), TuicQuinnError> {
        self.connection.send_datagram(data.to_vec().into())?;
        Ok(())
    }

    pub async fn recv_datagram(&self) -> Result<Vec<u8>, TuicQuinnError> {
        let data = self.connection.read_datagram().await?;
        Ok(data.to_vec())
    }

    pub fn stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub fn local_ip(&self) -> Option<std::net::IpAddr> {
        self.connection.local_ip()
    }

    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.connection.close(error_code.into(), reason);
    }

    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

pub struct TuicQuinnSendStream {
    stream: SendStream,
}

impl TuicQuinnSendStream {
    pub async fn write(&mut self, buf: &[u8]) -> Result<(), TuicQuinnError> {
        self.stream.write_all(buf).await?;
        Ok(())
    }

    pub async fn write_all_and_finish(&mut self, buf: &[u8]) -> Result<(), TuicQuinnError> {
        self.stream.write_all(buf).await?;
        self.stream.finish()?;
        Ok(())
    }

    /// Finish the stream
    pub fn finish(&mut self) -> Result<(), TuicQuinnError> {
        self.stream.finish()?;
        Ok(())
    }

    pub fn reset(&mut self, error_code: u32) {
        self.stream.reset(error_code.into()).ok();
    }
}

pub struct TuicQuinnRecvStream {
    stream: RecvStream,
}

impl TuicQuinnRecvStream {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TuicQuinnError> {
        let result = self.stream.read(buf).await?;
        Ok(result)
    }

    pub async fn read_to_end(&mut self, max_size: usize) -> Result<Vec<u8>, TuicQuinnError> {
        let data = self.stream.read_to_end(max_size).await?;
        Ok(data)
    }

    pub fn stop(&mut self, error_code: u32) {
        self.stream.stop(error_code.into()).ok();
    }
}

pub struct TuicQuinnConfig {
    pub max_concurrent_bidi_streams: u32,
    pub max_concurrent_uni_streams: u32,
    pub max_idle_timeout: std::time::Duration,
    pub keep_alive_interval: Option<std::time::Duration>,
    pub max_packet_size: usize,
}

impl Default for TuicQuinnConfig {
    fn default() -> Self {
        Self {
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            max_idle_timeout: std::time::Duration::from_secs(30),
            keep_alive_interval: Some(std::time::Duration::from_secs(10)),
            max_packet_size: 1350,
        }
    }
}

impl TuicQuinnConfig {
    pub fn client_config(&self) -> Result<QuinnClientConfig, TuicQuinnError> {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let mut config = QuinnClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TuicQuinnError::Protocol(e.to_string()))?,
        ));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(self.max_concurrent_bidi_streams.into());
        transport_config.max_concurrent_uni_streams(self.max_concurrent_uni_streams.into());
        transport_config.max_idle_timeout(Some(self.max_idle_timeout.try_into().unwrap()));
        transport_config.keep_alive_interval(self.keep_alive_interval);

        config.transport_config(Arc::new(transport_config));

        Ok(config)
    }

    pub fn server_config(
        &self,
        cert: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<QuinnServerConfig, TuicQuinnError> {
        let cert_der = CertificateDer::from(cert);
        let key_der = PrivateKeyDer::try_from(key).map_err(|_| TuicQuinnError::InvalidConfig)?;

        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;

        let mut server_config = QuinnServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| TuicQuinnError::Protocol(e.to_string()))?,
        ));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(self.max_concurrent_bidi_streams.into());
        transport_config.max_concurrent_uni_streams(self.max_concurrent_uni_streams.into());
        transport_config.max_idle_timeout(Some(self.max_idle_timeout.try_into().unwrap()));
        transport_config.keep_alive_interval(self.keep_alive_interval);

        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }
}

pub mod utils {
    use super::*;
    pub fn create_client_endpoint(
        local_addr: SocketAddr,
        config: &TuicQuinnConfig,
    ) -> Result<TuicQuinnEndpoint, TuicQuinnError> {
        let _client_config = config.client_config()?;
        let endpoint = Endpoint::client(local_addr)?;

        Ok(TuicQuinnEndpoint {
            endpoint,
            is_server: false,
        })
    }

    pub fn create_server_endpoint(
        local_addr: SocketAddr,
        config: &TuicQuinnConfig,
        cert: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<TuicQuinnEndpoint, TuicQuinnError> {
        let server_config = config.server_config(cert, key)?;
        let endpoint = Endpoint::server(server_config, local_addr)?;

        Ok(TuicQuinnEndpoint {
            endpoint,
            is_server: true,
        })
    }

    pub async fn ping_server(
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<std::time::Duration, TuicQuinnError> {
        let endpoint = TuicQuinnEndpoint::client("0.0.0.0:0".parse().unwrap())?;
        let start = std::time::Instant::now();
        let connection = endpoint.connect(server_addr, server_name).await?;
        let elapsed = start.elapsed();

        connection.close(0, &[]);
        Ok(elapsed)
    }
}
