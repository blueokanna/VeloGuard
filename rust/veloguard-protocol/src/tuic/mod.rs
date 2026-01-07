//! TUIC protocol implementation for VeloGuard

use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use quinn::{ClientConfig as QuinnClientConfig, ServerConfig as QuinnServerConfig, Endpoint, Connection};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde::{Serialize, Deserialize};

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
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[derive(Debug, Error)]
pub enum TuicError {
    #[error("QUIC error: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC read error: {0}")]
    Read(#[from] quinn::ReadToEndError),
    #[error("QUIC closed stream: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("Rustls error: {0}")]
    Rustls(#[from] quinn::rustls::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid configuration")]
    InvalidConfig,
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Protocol error: {0}")]
    Protocol(String),
}

const TUIC_PROTOCOL_VERSION: u8 = 5;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum Command {
    Connect = 0,
    Bind = 1,
    Dns = 2,
    Associate = 3,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub uuid: Uuid,
    pub password: Vec<String>,
    pub certificate: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub udp_relay_mode: UdpRelayMode,
    pub congestion_control: CongestionControl,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub uuid: Uuid,
    pub password: Vec<String>,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

#[derive(Debug, Clone, Copy)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthRequest {
    version: u8,
    uuid: Uuid,
    password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct AuthResponse {
    success: bool,
    message: Option<String>,
}

pub struct TuicClient {
    config: ClientConfig,
}

impl TuicClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub async fn connect(&self) -> Result<TuicConnection, TuicError> {
        let crypto = quinn::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        
        let _client_config = QuinnClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TuicError::Protocol(e.to_string()))?
        ));

        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;

        let server_name = self.config.certificate.as_deref().unwrap_or("tuic-server");
        let connection = endpoint.connect(self.config.server_addr, server_name)?
            .await?;

        self.authenticate(&connection).await?;

        Ok(TuicConnection {
            connection,
            _config: self.config.clone(),
        })
    }

    async fn authenticate(&self, connection: &Connection) -> Result<(), TuicError> {
        let mut auth_stream = connection.open_uni().await?;
        let password = self.config.password.first().ok_or(TuicError::InvalidConfig)?;

        let auth_request = AuthRequest {
            version: TUIC_PROTOCOL_VERSION,
            uuid: self.config.uuid,
            password: password.clone(),
        };

        let auth_data = bincode::serialize(&auth_request)
            .map_err(|e| TuicError::Protocol(e.to_string()))?;

        auth_stream.write_all(&auth_data).await?;
        auth_stream.finish()?;

        Ok(())
    }
}

pub struct TuicServer {
    config: ServerConfig,
}

impl TuicServer {
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    pub async fn serve(&self) -> Result<(), TuicError> {
        let cert_der = CertificateDer::from(self.config.certificate.clone());
        let key_der = PrivateKeyDer::try_from(self.config.private_key.clone())
            .map_err(|_| TuicError::InvalidConfig)?;
        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(TuicError::Rustls)?;
        let server_config = QuinnServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| TuicError::Protocol(e.to_string()))?
        ));

        let endpoint = Endpoint::server(server_config, self.config.listen_addr)?;

        loop {
            let incoming = endpoint.accept().await.ok_or(TuicError::InvalidConfig)?;
            let _connection = incoming.await?;
        }
    }
}

pub struct TuicConnection {
    connection: Connection,
    _config: ClientConfig,
}

impl TuicConnection {
    pub async fn send(&mut self, data: &[u8]) -> Result<(), TuicError> {
        let mut stream = self.connection.open_uni().await?;
        stream.write_all(data).await?;
        stream.finish()?;
        Ok(())
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TuicError> {
        let mut stream = self.connection.accept_uni().await?;
        let temp_buf = stream.read_to_end(1024 * 1024).await?;

        let len = std::cmp::min(temp_buf.len(), buf.len());
        buf[..len].copy_from_slice(&temp_buf[..len]);
        Ok(len)
    }

    pub async fn send_command(&self, command: Command, payload: &[u8]) -> Result<(), TuicError> {
        let mut command_data = vec![command as u8];
        command_data.extend_from_slice(payload);

        let mut stream = self.connection.open_uni().await?;
        stream.write_all(&command_data).await?;
        stream.finish()?;
        Ok(())
    }
}
