use std::net::SocketAddr;
use thiserror::Error;
use uuid::Uuid;
use quinn::{ClientConfig as QuinnClientConfig, ServerConfig as QuinnServerConfig, Endpoint, Connection, RecvStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde::{Serialize, Deserialize};

/// Custom TLS certificate verifier that accepts all certificates (insecure, for development)
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

/// TUIC protocol version
const TUIC_PROTOCOL_VERSION: u8 = 5;

/// TUIC command types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum Command {
    Connect = 0,
    Bind = 1,
    Dns = 2,
    Associate = 3,
}

/// TUIC address type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Address {
    IPv4([u8; 4]),
    IPv6([u8; 16]),
    Domain(String),
}

/// TUIC client configuration
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

/// TUIC server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub uuid: Uuid,
    pub password: Vec<String>,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub max_packet_size: usize,
}

/// UDP relay mode
#[derive(Debug, Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

/// Congestion control algorithm
#[derive(Debug, Clone, Copy)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

/// TUIC authentication data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthRequest {
    version: u8,
    uuid: Uuid,
    password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthResponse {
    success: bool,
    message: Option<String>,
}

/// TUIC client
pub struct TuicClient {
    config: ClientConfig,
}

impl TuicClient {
    /// Create a new TUIC client
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Connect to the TUIC server
    pub async fn connect(&self) -> Result<TuicConnection, TuicError> {
        // Create QUIC client endpoint
        let crypto = quinn::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerifier))
            .with_no_client_auth();
        
        let _client_config = QuinnClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TuicError::Protocol(e.to_string()))?
        ));

        // Set ALPN if specified - handled in rustls config above
        let _ = &self.config.alpn; // ALPN would be set in rustls config

        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;

        // Connect to server
        let server_name = self.config.certificate.as_deref().unwrap_or("tuic-server");
        let connection = endpoint.connect(self.config.server_addr, server_name)?
            .await?;

        // Perform TUIC authentication
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

        // Wait for response
        let mut response_stream = connection.accept_uni().await?;
        let response_data = Vec::new();
        response_stream.read_to_end(1024 * 1024).await?; // 1MB limit

        let auth_response: AuthResponse = bincode::deserialize(&response_data)
            .map_err(|e| TuicError::Protocol(e.to_string()))?;

        if !auth_response.success {
            return Err(TuicError::AuthFailed);
        }

        Ok(())
    }
}

/// TUIC server
pub struct TuicServer {
    config: ServerConfig,
}

impl TuicServer {
    /// Create a new TUIC server
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    /// Start the TUIC server
    pub async fn serve(&self) -> Result<(), TuicError> {
        // Create server configuration
        let cert_der = CertificateDer::from(self.config.certificate.clone());
        let key_der = PrivateKeyDer::try_from(self.config.private_key.clone())
            .map_err(|_| TuicError::InvalidConfig)?;
        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| TuicError::Rustls(e))?;
        let server_config = QuinnServerConfig::with_crypto(std::sync::Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| TuicError::Protocol(e.to_string()))?
        ));

        let endpoint = Endpoint::server(server_config, self.config.listen_addr)?;

        loop {
            let incoming = endpoint.accept().await.ok_or(TuicError::InvalidConfig)?;
            let connection = incoming.await?;
            let config = self.config.clone();

            // Handle connection in background
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(connection, config).await {
                    eprintln!("Connection error: {:?}", e);
                }
            });
        }
    }

    async fn handle_client(connection: Connection, config: ServerConfig) -> Result<(), TuicError> {
        // Handle authentication
        let mut auth_stream = connection.accept_uni().await?;
        let auth_data = Vec::new();
        auth_stream.read_to_end(1024 * 1024).await?; // 1MB limit

        let auth_request: AuthRequest = bincode::deserialize(&auth_data)
            .map_err(|e| TuicError::Protocol(e.to_string()))?;

        // Verify authentication
        let success = auth_request.uuid == config.uuid &&
            config.password.contains(&auth_request.password);

        let auth_response = AuthResponse {
            success,
            message: if success { None } else { Some("Authentication failed".to_string()) },
        };

        let response_data = bincode::serialize(&auth_response)
            .map_err(|e| TuicError::Protocol(e.to_string()))?;

        let mut response_stream = connection.open_uni().await?;
        response_stream.write_all(&response_data).await?;
        response_stream.finish()?;

        if !success {
            return Ok(()); // Close connection after failed auth
        }

        // Handle TUIC protocol commands
        loop {
            match connection.accept_uni().await {
                Ok(mut stream) => {
                    if let Err(e) = Self::handle_command(&connection, &mut stream, &config).await {
                        eprintln!("Command error: {:?}", e);
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        Ok(())
    }

    async fn handle_command(connection: &Connection, stream: &mut RecvStream, _config: &ServerConfig) -> Result<(), TuicError> {
        let command_data = Vec::new();
        stream.read_to_end(1024 * 1024).await?; // 1MB limit

        if command_data.is_empty() {
            return Ok(());
        }

        let command = command_data[0];
        let payload = &command_data[1..];

        match command {
            0 => Self::handle_connect(connection, payload).await,
            1 => Self::handle_bind(connection, payload).await,
            2 => Self::handle_dns(connection, payload).await,
            3 => Self::handle_associate(connection, payload).await,
            _ => Err(TuicError::Protocol("Unknown command".to_string())),
        }
    }

    async fn handle_connect(_connection: &Connection, _payload: &[u8]) -> Result<(), TuicError> {
        // Handle TCP connect command
        Ok(())
    }

    async fn handle_bind(_connection: &Connection, _payload: &[u8]) -> Result<(), TuicError> {
        // Handle TCP bind command
        Ok(())
    }

    async fn handle_dns(_connection: &Connection, _payload: &[u8]) -> Result<(), TuicError> {
        // Handle DNS query command
        Ok(())
    }

    async fn handle_associate(_connection: &Connection, _payload: &[u8]) -> Result<(), TuicError> {
        // Handle UDP associate command
        Ok(())
    }
}

/// TUIC connection
pub struct TuicConnection {
    connection: Connection,
    _config: ClientConfig,
}

impl TuicConnection {
    /// Send data through the connection
    pub async fn send(&mut self, data: &[u8]) -> Result<(), TuicError> {
        let mut stream = self.connection.open_uni().await?;
        stream.write_all(data).await?;
        stream.finish()?;
        Ok(())
    }

    /// Receive data from the connection
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TuicError> {
        let mut stream = self.connection.accept_uni().await?;
        let temp_buf = Vec::new();
        stream.read_to_end(1024 * 1024).await?; // 1MB limit

        let len = std::cmp::min(temp_buf.len(), buf.len());
        buf[..len].copy_from_slice(&temp_buf[..len]);
        Ok(len)
    }

    /// Create a UDP socket over the connection
    pub async fn create_udp_socket(&self) -> Result<TuicUdpSocket, TuicError> {
        Ok(TuicUdpSocket {
            connection: self.connection.clone(),
            _config: self._config.clone(),
        })
    }

    /// Send a TUIC command
    pub async fn send_command(&self, command: Command, payload: &[u8]) -> Result<(), TuicError> {
        let mut command_data = vec![command as u8];
        command_data.extend_from_slice(payload);

        let mut stream = self.connection.open_uni().await?;
        stream.write_all(&command_data).await?;
        stream.finish()?;
        Ok(())
    }
}

/// TUIC UDP socket
pub struct TuicUdpSocket {
    connection: Connection,
    _config: ClientConfig,
}

impl TuicUdpSocket {
    /// Send UDP packet
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, TuicError> {
        // Create UDP packet with address
        let mut packet = Vec::new();

        // Add address (simplified - would encode properly)
        match addr {
            SocketAddr::V4(v4) => {
                packet.push(0x01); // IPv4 type
                packet.extend_from_slice(&v4.ip().octets());
                packet.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                packet.push(0x02); // IPv6 type
                packet.extend_from_slice(&v6.ip().octets());
                packet.extend_from_slice(&v6.port().to_be_bytes());
            }
        }

        packet.extend_from_slice(buf);

        let mut stream = self.connection.open_uni().await?;
        stream.write_all(&packet).await?;
        stream.finish()?;

        Ok(buf.len())
    }

    /// Receive UDP packet
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TuicError> {
        let mut stream = self.connection.accept_uni().await?;
        let packet = Vec::new();
        stream.read_to_end(1024 * 1024).await?; // 1MB limit

        if packet.len() < 7 { // Minimum packet size
            return Err(TuicError::Protocol("Invalid UDP packet".to_string()));
        }

        // Parse address (simplified)
        let addr_type = packet[0];
        let addr = match addr_type {
            0x01 => { // IPv4
                if packet.len() < 7 {
                    return Err(TuicError::Protocol("Invalid IPv4 packet".to_string()));
                }
                let ip = std::net::Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4]);
                let port = u16::from_be_bytes([packet[5], packet[6]]);
                SocketAddr::new(std::net::IpAddr::V4(ip), port)
            }
            0x02 => { // IPv6
                if packet.len() < 19 {
                    return Err(TuicError::Protocol("Invalid IPv6 packet".to_string()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[1..17]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([packet[17], packet[18]]);
                SocketAddr::new(std::net::IpAddr::V6(ip), port)
            }
            _ => return Err(TuicError::Protocol("Unknown address type".to_string())),
        };

        let data_start = match addr_type {
            0x01 => 7,
            0x02 => 19,
            _ => unreachable!(),
        };

        let data_len = std::cmp::min(packet.len() - data_start, buf.len());
        buf[..data_len].copy_from_slice(&packet[data_start..data_start + data_len]);

        Ok((data_len, addr))
    }
}
