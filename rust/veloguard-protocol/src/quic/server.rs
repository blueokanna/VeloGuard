use dashmap::DashMap;
use quinn::{
    Endpoint, ServerConfig as QuinnServerConfig,
    TransportConfig as QuinnTransportConfig, Connection,
};
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use super::address::Address;
use super::config::{CongestionControl, ServerConfig};
use super::crypto::CryptoContext;
use super::error::{Result, QuicError};
use super::protocol::{Command, Request, Response, ResponseStatus, UdpHeader};
use super::stream::{QuicStream, StreamType, QuicSendStream, QuicRecvStream};

pub struct QuicServer {
    config: ServerConfig,
    endpoint: Option<Endpoint>,
    running: AtomicBool,
    connections: DashMap<u64, Arc<ServerConnection>>,
    connection_counter: AtomicU64,
}

impl QuicServer {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            endpoint: None,
            running: AtomicBool::new(false),
            connections: DashMap::new(),
            connection_counter: AtomicU64::new(0),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        let server_config = self.build_server_config()?;
        let endpoint = Endpoint::server(server_config, self.config.listen_addr)?;
        info!("Server listening on {}", self.config.listen_addr);

        self.endpoint = Some(endpoint);
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub async fn accept(&self) -> Result<Option<Arc<ServerConnection>>> {
        let endpoint = self.endpoint.as_ref().ok_or(QuicError::ServerNotReady)?;

        if !self.running.load(Ordering::SeqCst) {
            return Ok(None);
        }

        match endpoint.accept().await {
            Some(incoming) => {
                let connection = incoming.await?;
                let conn_id = self.connection_counter.fetch_add(1, Ordering::SeqCst);

                let crypto = CryptoContext::new(self.config.cipher, &self.config.password);
                let server_conn = Arc::new(ServerConnection::new(
                    conn_id,
                    connection,
                    crypto,
                    self.config.udp_relay,
                    self.config.fallback,
                ));

                self.connections.insert(conn_id, server_conn.clone());
                info!("New connection {} from {}", conn_id, server_conn.remote_addr());

                Ok(Some(server_conn))
            }
            None => Ok(None),
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!("Server running...");

        while self.running.load(Ordering::SeqCst) {
            match self.accept().await {
                Ok(Some(conn)) => {
                    let conn_clone = conn.clone();
                    tokio::spawn(async move {
                        if let Err(e) = conn_clone.handle().await {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    error!("Accept error: {}", e);
                    continue;
                }
            }
        }

        Ok(())
    }

    fn build_server_config(&self) -> Result<QuinnServerConfig> {
        let cert_pem = self.config.certificate.as_bytes();
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*cert_pem)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(QuicError::InvalidConfig("No certificates found".to_string()));
        }

        let key_pem = self.config.private_key.as_bytes();
        let key = rustls_pemfile::private_key(&mut &*key_pem)
            .map_err(|e| QuicError::InvalidConfig(format!("Invalid private key: {}", e)))?
            .ok_or_else(|| QuicError::InvalidConfig("No private key found".to_string()))?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(QuicError::Tls)?;

        tls_config.alpn_protocols = self.config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        if self.config.transport.zero_rtt {
            tls_config.max_early_data_size = u32::MAX;
        }

        let quic_config: quinn::crypto::rustls::QuicServerConfig = tls_config.try_into().map_err(|e| {
            QuicError::InvalidConfig(format!("Failed to create QUIC server config: {:?}", e))
        })?;
        let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_config));

        let mut transport = QuinnTransportConfig::default();
        transport.max_idle_timeout(Some(self.config.transport.idle_timeout.try_into().unwrap()));
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

        server_config.transport_config(Arc::new(transport));
        Ok(server_config)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(ref endpoint) = self.endpoint {
            endpoint.close(0u32.into(), b"server shutdown");
        }

        for conn in self.connections.iter() {
            conn.close();
        }
        self.connections.clear();
        info!("Server stopped");
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn remove_connection(&self, conn_id: u64) {
        self.connections.remove(&conn_id);
    }
}

pub struct ServerConnection {
    id: u64,
    inner: Connection,
    crypto: CryptoContext,
    udp_relay_enabled: bool,
    fallback: Option<SocketAddr>,
}

impl ServerConnection {
    pub fn new(
        id: u64,
        connection: Connection,
        crypto: CryptoContext,
        udp_relay_enabled: bool,
        fallback: Option<SocketAddr>,
    ) -> Self {
        Self { id, inner: connection, crypto, udp_relay_enabled, fallback }
    }

    pub fn id(&self) -> u64 { self.id }
    pub fn remote_addr(&self) -> SocketAddr { self.inner.remote_address() }
    pub fn is_closed(&self) -> bool { self.inner.close_reason().is_some() }

    pub async fn handle(&self) -> Result<()> {
        loop {
            match self.inner.accept_bi().await {
                Ok((send, recv)) => {
                    let _crypto = CryptoContext::new(self.crypto.cipher_kind(), "");
                    let fallback = self.fallback;
                    let udp_enabled = self.udp_relay_enabled;

                    tokio::spawn(async move {
                        let stream = QuicStream::new(send, recv, StreamType::Tcp);
                        if let Err(e) = Self::handle_stream(stream, fallback, udp_enabled).await {
                            debug!("Stream error: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    debug!("Connection closed by application");
                    break;
                }
                Err(quinn::ConnectionError::LocallyClosed) => {
                    debug!("Connection closed locally");
                    break;
                }
                Err(e) => {
                    error!("Connection error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_stream(mut stream: QuicStream, fallback: Option<SocketAddr>, udp_enabled: bool) -> Result<()> {
        let mut req_buf = vec![0u8; 512];
        let n = stream.read_raw(&mut req_buf).await?.ok_or(QuicError::ConnectionClosed)?;

        let request = Request::from_bytes(&req_buf[..n])?;
        debug!("Received request: {:?}", request.command);

        match request.command {
            Command::Connect => Self::handle_tcp_connect(stream, request, fallback).await,
            Command::UdpAssociate => {
                if udp_enabled {
                    Self::handle_udp_associate(stream, request).await
                } else {
                    let response = Response::error(ResponseStatus::CommandNotSupported);
                    stream.write_raw(&response.to_bytes()).await?;
                    Err(QuicError::UnsupportedCommand(Command::UdpAssociate as u8))
                }
            }
            Command::Bind => {
                let response = Response::error(ResponseStatus::CommandNotSupported);
                stream.write_raw(&response.to_bytes()).await?;
                Err(QuicError::UnsupportedCommand(Command::Bind as u8))
            }
        }
    }

    async fn handle_tcp_connect(mut stream: QuicStream, request: Request, _fallback: Option<SocketAddr>) -> Result<()> {
        let target_addr = match &request.address {
            Address::SocketAddr(addr) => *addr,
            Address::DomainName(domain, port) => {
                match tokio::net::lookup_host(format!("{}:{}", domain, port)).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => addr,
                        None => {
                            let response = Response::error(ResponseStatus::HostUnreachable);
                            stream.write_raw(&response.to_bytes()).await?;
                            return Err(QuicError::AddressParse("Failed to resolve domain".to_string()));
                        }
                    },
                    Err(_) => {
                        let response = Response::error(ResponseStatus::HostUnreachable);
                        stream.write_raw(&response.to_bytes()).await?;
                        return Err(QuicError::AddressParse("Failed to resolve domain".to_string()));
                    }
                }
            }
        };

        let target = match TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => {
                let status = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => ResponseStatus::ConnectionRefused,
                    std::io::ErrorKind::TimedOut => ResponseStatus::TtlExpired,
                    _ => ResponseStatus::NetworkUnreachable,
                };
                let response = Response::error(status);
                stream.write_raw(&response.to_bytes()).await?;
                return Err(e.into());
            }
        };

        let response = Response::success();
        stream.write_raw(&response.to_bytes()).await?;

        if let Some(ref payload) = request.payload {
            if !payload.is_empty() {
                let (target_read, mut target_write) = target.into_split();
                target_write.write_all(payload).await?;
                let (send_stream, recv_stream) = stream.split();
                Self::relay_tcp(send_stream, recv_stream, target_read, target_write).await
            } else {
                let (target_read, target_write) = target.into_split();
                let (send_stream, recv_stream) = stream.split();
                Self::relay_tcp(send_stream, recv_stream, target_read, target_write).await
            }
        } else {
            let (target_read, target_write) = target.into_split();
            let (send_stream, recv_stream) = stream.split();
            Self::relay_tcp(send_stream, recv_stream, target_read, target_write).await
        }
    }

    async fn relay_tcp(
        mut quic_send: QuicSendStream,
        mut quic_recv: QuicRecvStream,
        mut tcp_read: tokio::net::tcp::OwnedReadHalf,
        mut tcp_write: tokio::net::tcp::OwnedWriteHalf,
    ) -> Result<()> {
        let client_to_server = async {
            let mut buf = vec![0u8; 8192];
            loop {
                match quic_recv.read_raw(&mut buf).await {
                    Ok(Some(n)) if n > 0 => {
                        if tcp_write.write_all(&buf[..n]).await.is_err() { break; }
                    }
                    _ => break,
                }
            }
        };

        let server_to_client = async {
            let mut buf = vec![0u8; 8192];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if quic_send.write_raw(&buf[..n]).await.is_err() { break; }
                    }
                    _ => break,
                }
            }
        };

        tokio::select! {
            _ = client_to_server => {}
            _ = server_to_client => {}
        }

        Ok(())
    }

    async fn handle_udp_associate(mut stream: QuicStream, _request: Request) -> Result<()> {
        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = udp_socket.local_addr()?;

        let response = Response::success_with_address(Address::from(local_addr));
        stream.write_raw(&response.to_bytes()).await?;

        debug!("UDP session bound to {}", local_addr);

        let udp_socket = Arc::new(udp_socket);
        let (send_stream, recv_stream) = stream.split();

        Self::relay_udp(send_stream, recv_stream, udp_socket).await
    }

    #[allow(clippy::while_let_loop)]
    async fn relay_udp(
        mut quic_send: QuicSendStream,
        mut quic_recv: QuicRecvStream,
        udp_socket: Arc<tokio::net::UdpSocket>,
    ) -> Result<()> {
        let socket_clone = udp_socket.clone();

        let client_to_server = async {
            loop {
                match quic_recv.read_encrypted().await {
                    Ok(Some(data)) => {
                        match UdpHeader::from_bytes(&data) {
                            Ok((header, header_len)) => {
                                let payload = &data[header_len..];
                                let target = match &header.address {
                                    Address::SocketAddr(addr) => *addr,
                                    Address::DomainName(domain, port) => {
                                        match tokio::net::lookup_host(format!("{}:{}", domain, port)).await {
                                            Ok(mut addrs) => match addrs.next() {
                                                Some(addr) => addr,
                                                None => continue,
                                            },
                                            Err(_) => continue,
                                        }
                                    }
                                };
                                let _ = socket_clone.send_to(payload, target).await;
                            }
                            Err(_) => continue,
                        }
                    }
                    _ => break,
                }
            }
        };

        let server_to_client = async {
            let mut buf = vec![0u8; 65535];
            loop {
                match udp_socket.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let header = UdpHeader::new(Address::from(from));
                        let header_bytes = header.to_bytes();

                        let mut packet = Vec::with_capacity(header_bytes.len() + n);
                        packet.extend_from_slice(&header_bytes);
                        packet.extend_from_slice(&buf[..n]);

                        if quic_send.write_encrypted(&packet).await.is_err() { break; }
                    }
                    Err(_) => break,
                }
            }
        };

        tokio::select! {
            _ = client_to_server => {}
            _ = server_to_client => {}
        }

        Ok(())
    }

    pub fn close(&self) {
        self.inner.close(0u32.into(), b"connection closed");
    }
}
