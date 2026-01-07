use bytes::Bytes;
use parking_lot::RwLock;
use quinn::{
    crypto::rustls::QuicClientConfig, Connection, Endpoint,
    TransportConfig as QuinnTransportConfig,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use super::address::Address;
use super::config::{ClientConfig, CongestionControl};
use super::crypto::CryptoContext;
use super::error::{Result, QuicError};
use super::protocol::{Request, Response};
use super::stream::{QuicStream, StreamType};

#[cfg(feature = "tls")]
use crate::tls::SkipServerVerification;

#[cfg(not(feature = "tls"))]
use rustls::pki_types::{CertificateDer, ServerName};

pub struct QuicClient {
    config: ClientConfig,
    endpoint: Option<Endpoint>,
    connection: RwLock<Option<Arc<ClientConnection>>>,
    #[allow(dead_code)]
    crypto: CryptoContext,
}

impl QuicClient {
    pub fn new(config: ClientConfig) -> Self {
        let crypto = CryptoContext::new(config.cipher, &config.password);
        Self {
            config,
            endpoint: None,
            connection: RwLock::new(None),
            crypto,
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        let bind_addr: SocketAddr = self
            .config
            .local_addr
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

        let socket = UdpSocket::bind(bind_addr).await?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| QuicError::InvalidConfig("No async runtime".to_string()))?;

        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket.into_std()?,
            runtime,
        )?;

        self.endpoint = Some(endpoint);
        info!("Client endpoint initialized on {}", bind_addr);
        Ok(())
    }

    pub async fn connect(&self) -> Result<Arc<ClientConnection>> {
        {
            let conn = self.connection.read();
            if let Some(ref c) = *conn {
                if !c.is_closed() {
                    return Ok(c.clone());
                }
            }
        }

        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or(QuicError::ClientNotConnected)?;

        let tls_config = self.build_tls_config()?;
        let quic_config: QuicClientConfig = tls_config.try_into().map_err(|e| {
            QuicError::InvalidConfig(format!("Failed to create QUIC config: {:?}", e))
        })?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));

        let mut transport = QuinnTransportConfig::default();
        transport.max_idle_timeout(Some(
            self.config.transport.idle_timeout.try_into().unwrap(),
        ));
        if let Some(keep_alive) = self.config.transport.keep_alive_interval {
            transport.keep_alive_interval(Some(keep_alive));
        }
        transport.max_concurrent_bidi_streams(self.config.transport.max_concurrent_bi_streams.into());
        transport.max_concurrent_uni_streams(self.config.transport.max_concurrent_uni_streams.into());
        transport.initial_rtt(self.config.transport.initial_rtt);

        match self.config.transport.congestion_control {
            CongestionControl::Cubic => {
                transport.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
            }
            CongestionControl::NewReno => {
                transport.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default()));
            }
            CongestionControl::Bbr => {
                transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            }
        }

        client_config.transport_config(Arc::new(transport));

        let server_name = self
            .config
            .server_name
            .clone()
            .unwrap_or_else(|| self.config.server_addr.ip().to_string());

        let connecting = endpoint.connect_with(
            client_config,
            self.config.server_addr,
            &server_name,
        )?;

        let connection = if self.config.transport.zero_rtt {
            match connecting.into_0rtt() {
                Ok((conn, zero_rtt_accepted)) => {
                    debug!("0-RTT connection established");
                    tokio::spawn(async move {
                        if zero_rtt_accepted.await {
                            debug!("0-RTT data accepted by server");
                        } else {
                            warn!("0-RTT data rejected by server");
                        }
                    });
                    conn
                }
                Err(connecting) => {
                    debug!("0-RTT not available, falling back to 1-RTT");
                    connecting.await?
                }
            }
        } else {
            connecting.await?
        };

        info!("Connected to server: {}", self.config.server_addr);

        let client_conn = Arc::new(ClientConnection::new(
            connection,
            CryptoContext::new(self.config.cipher, &self.config.password),
        ));

        {
            let mut conn = self.connection.write();
            *conn = Some(client_conn.clone());
        }

        Ok(client_conn)
    }

    fn build_tls_config(&self) -> Result<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();

        for cert in rustls_native_certs::load_native_certs().expect("Failed to load native certs") {
            root_store.add(cert).ok();
        }

        let builder = rustls::ClientConfig::builder()
            .with_root_certificates(root_store);

        let mut config = if self.config.skip_cert_verify {
            let verifier = Arc::new(SkipServerVerification);
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        } else {
            builder.with_no_client_auth()
        };

        config.alpn_protocols = self
            .config
            .alpn
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();

        if self.config.transport.zero_rtt {
            config.enable_early_data = true;
        }

        Ok(config)
    }

    pub fn connection(&self) -> Option<Arc<ClientConnection>> {
        self.connection.read().clone()
    }

    pub fn close(&self) {
        if let Some(ref conn) = *self.connection.read() {
            conn.close();
        }
        if let Some(ref endpoint) = self.endpoint {
            endpoint.close(0u32.into(), b"client closed");
        }
    }
}

pub struct ClientConnection {
    inner: Connection,
    #[allow(dead_code)]
    crypto: CryptoContext,
}

impl ClientConnection {
    pub fn new(connection: Connection, crypto: CryptoContext) -> Self {
        Self {
            inner: connection,
            crypto,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.close_reason().is_some()
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    pub fn rtt(&self) -> Duration {
        self.inner.rtt()
    }

    pub async fn open_tcp_stream(&self, target: Address) -> Result<QuicStream> {
        let (send, recv) = self.inner.open_bi().await?;
        let mut stream = QuicStream::new(send, recv, StreamType::Tcp);

        let request = Request::connect(target);
        stream.write_raw(&request.to_bytes()).await?;

        let mut resp_buf = [0u8; 64];
        let n = stream
            .read_raw(&mut resp_buf)
            .await?
            .ok_or(QuicError::ConnectionClosed)?;

        let response = Response::from_bytes(&resp_buf[..n])?;
        if !response.is_success() {
            return Err(QuicError::Protocol(format!(
                "Server returned error: {:?}",
                response.status
            )));
        }

        debug!("TCP stream opened to target");
        Ok(stream)
    }

    pub async fn open_tcp_stream_0rtt(
        &self,
        target: Address,
        early_data: Bytes,
    ) -> Result<QuicStream> {
        let (send, recv) = self.inner.open_bi().await?;
        let mut stream = QuicStream::new(send, recv, StreamType::Tcp);

        let request = Request::connect(target).with_payload(early_data);
        stream.write_raw(&request.to_bytes()).await?;

        let mut resp_buf = [0u8; 64];
        let n = stream
            .read_raw(&mut resp_buf)
            .await?
            .ok_or(QuicError::ConnectionClosed)?;

        let response = Response::from_bytes(&resp_buf[..n])?;
        if !response.is_success() {
            return Err(QuicError::Protocol(format!(
                "Server returned error: {:?}",
                response.status
            )));
        }

        debug!("TCP stream opened with 0-RTT data");
        Ok(stream)
    }

    pub async fn open_udp_session(&self, bind_addr: Address) -> Result<UdpSession> {
        let (send, recv) = self.inner.open_bi().await?;
        let mut stream = QuicStream::new(send, recv, StreamType::Udp);

        let request = Request::udp_associate(bind_addr);
        stream.write_raw(&request.to_bytes()).await?;

        let mut resp_buf = [0u8; 128];
        let n = stream
            .read_raw(&mut resp_buf)
            .await?
            .ok_or(QuicError::ConnectionClosed)?;

        let response = Response::from_bytes(&resp_buf[..n])?;
        if !response.is_success() {
            return Err(QuicError::Protocol(format!(
                "UDP associate failed: {:?}",
                response.status
            )));
        }

        let bound_addr = response.address.ok_or_else(|| {
            QuicError::Protocol("No bound address in UDP response".to_string())
        })?;

        debug!("UDP session opened, bound to {}", bound_addr);
        Ok(UdpSession::new(stream, bound_addr))
    }

    pub fn close(&self) {
        self.inner.close(0u32.into(), b"connection closed");
    }
}

pub struct UdpSession {
    stream: QuicStream,
    bound_addr: Address,
}

impl UdpSession {
    pub fn new(stream: QuicStream, bound_addr: Address) -> Self {
        Self { stream, bound_addr }
    }

    pub fn bound_addr(&self) -> &Address {
        &self.bound_addr
    }

    pub async fn send_to(&mut self, data: &[u8], target: &Address) -> Result<()> {
        use super::protocol::UdpHeader;

        let header = UdpHeader::new(target.clone());
        let header_bytes = header.to_bytes();

        let mut packet = Vec::with_capacity(header_bytes.len() + data.len());
        packet.extend_from_slice(&header_bytes);
        packet.extend_from_slice(data);

        self.stream.write_encrypted(&packet).await
    }

    pub async fn recv_from(&mut self) -> Result<Option<(Vec<u8>, Address)>> {
        use super::protocol::UdpHeader;

        let data = match self.stream.read_encrypted().await? {
            Some(d) => d,
            None => return Ok(None),
        };

        let (header, header_len) = UdpHeader::from_bytes(&data)?;
        let payload = data[header_len..].to_vec();

        Ok(Some((payload, header.address)))
    }

    pub async fn close(&mut self) -> Result<()> {
        self.stream.finish().await
    }
}

#[cfg(not(feature = "tls"))]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(not(feature = "tls"))]
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
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
