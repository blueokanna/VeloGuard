use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, ServerConfig as QuinnServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

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
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            root_store.add(cert).map_err(TuicError::Rustls)?;
        }
        if root_store.is_empty() {
            return Err(TuicError::Protocol(
                "no trusted platform certificates are available".to_string(),
            ));
        }

        let mut crypto = quinn::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        crypto.alpn_protocols = self
            .config
            .alpn
            .clone()
            .unwrap_or_else(|| vec!["h3".to_string()])
            .into_iter()
            .map(String::into_bytes)
            .collect();

        let client_config = QuinnClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TuicError::Protocol(e.to_string()))?,
        ));

        let bind_addr = if self.config.server_addr.is_ipv6() {
            "[::]:0".parse().expect("valid IPv6 wildcard address")
        } else {
            "0.0.0.0:0".parse().expect("valid IPv4 wildcard address")
        };
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        let default_server_name = self.config.server_addr.ip().to_string();
        let server_name = self
            .config
            .certificate
            .as_deref()
            .unwrap_or(&default_server_name);
        let connection = endpoint
            .connect(self.config.server_addr, server_name)?
            .await?;

        self.authenticate(&connection).await?;

        Ok(TuicConnection {
            connection,
            _endpoint: endpoint,
            _config: self.config.clone(),
        })
    }

    async fn authenticate(&self, connection: &Connection) -> Result<(), TuicError> {
        let mut auth_stream = connection.open_uni().await?;
        let password = self
            .config
            .password
            .first()
            .ok_or(TuicError::InvalidConfig)?;

        let auth_request = AuthRequest {
            version: TUIC_PROTOCOL_VERSION,
            uuid: self.config.uuid,
            password: password.clone(),
        };

        // RustBinary 0.1.4 changed the top-level helpers to the compact V1
        // profile. Keep this pre-existing packet format explicit so dependency
        // upgrades cannot silently change bytes sent over the network.
        let auth_data = rustbinary::legacy_options()
            .with_limit(64 * 1024)
            .reject_trailing_bytes()
            .serialize(&auth_request)
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
                .map_err(|e| TuicError::Protocol(e.to_string()))?,
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
    _endpoint: Endpoint,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_auth_wire_format_is_stable_across_rustbinary_upgrade() {
        let request = AuthRequest {
            version: TUIC_PROTOCOL_VERSION,
            uuid: Uuid::from_bytes([0x11; 16]),
            password: "secret".to_string(),
        };

        let encoded = rustbinary::legacy_options()
            .with_limit(64 * 1024)
            .reject_trailing_bytes()
            .serialize(&request)
            .expect("legacy TUIC auth request must serialize");
        let decoded: AuthRequest = rustbinary::legacy_options()
            .with_limit(64 * 1024)
            .reject_trailing_bytes()
            .deserialize(&encoded)
            .expect("legacy TUIC auth request must deserialize");

        assert_eq!(decoded.version, request.version);
        assert_eq!(decoded.uuid, request.uuid);
        assert_eq!(decoded.password, request.password);

        let mut expected = vec![TUIC_PROTOCOL_VERSION];
        expected.extend_from_slice(&36u64.to_le_bytes());
        expected.extend_from_slice(b"11111111-1111-1111-1111-111111111111");
        expected.extend_from_slice(&6u64.to_le_bytes());
        expected.extend_from_slice(b"secret");
        assert_eq!(encoded, expected);
    }
}
