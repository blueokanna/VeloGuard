use crate::config::OutboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use crate::tls::{yaml_value_to_string, SkipServerVerification};
use bytes::{Buf, BufMut, BytesMut};
use parking_lot::RwLock;
use quinn::{ClientConfig as QuinnClientConfig, Connection, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

const TUIC_VERSION: u8 = 0x05;
const TUIC_CMD_AUTHENTICATE: u8 = 0x00;
const TUIC_CMD_CONNECT: u8 = 0x01;
const TUIC_CMD_PACKET: u8 = 0x02;
const TUIC_CMD_DISSOCIATE: u8 = 0x03;
#[allow(dead_code)]
const TUIC_CMD_HEARTBEAT: u8 = 0x04;

const TUIC_ADDR_TYPE_IPV4: u8 = 0x01;
const TUIC_ADDR_TYPE_DOMAIN: u8 = 0x03;
const TUIC_ADDR_TYPE_IPV6: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq)]
#[derive(Default)]
pub enum CongestionControl {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}


impl std::str::FromStr for CongestionControl {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "cubic" => Ok(Self::Cubic),
            "new_reno" | "newreno" => Ok(Self::NewReno),
            "bbr" => Ok(Self::Bbr),
            _ => Err(Error::config(format!("Unknown congestion control: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[derive(Default)]
pub enum UdpRelayMode {
    #[default]
    Native,
    Quic,
}


impl std::str::FromStr for UdpRelayMode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "native" => Ok(Self::Native),
            "quic" => Ok(Self::Quic),
            _ => Err(Error::config(format!("Unknown UDP relay mode: {}", s))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TuicConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub disable_sni: bool,
    pub congestion_control: CongestionControl,
    pub udp_relay_mode: UdpRelayMode,
    pub zero_rtt_handshake: bool,
    pub heartbeat: u64,
    pub reduce_rtt: bool,
}

impl Default for TuicConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            uuid: String::new(),
            password: String::new(),
            alpn: vec!["h3".to_string()],
            sni: None,
            skip_cert_verify: false,
            disable_sni: false,
            congestion_control: CongestionControl::Cubic,
            udp_relay_mode: UdpRelayMode::Native,
            zero_rtt_handshake: false,
            heartbeat: 10000,
            reduce_rtt: false,
        }
    }
}

pub struct TuicConnection {
    connection: Connection,
    uuid: Uuid,
    password: String,
    authenticated: RwLock<bool>,
    udp_relay_mode: UdpRelayMode,
}

impl TuicConnection {
    pub fn new(connection: Connection, uuid: Uuid, password: String, udp_relay_mode: UdpRelayMode) -> Self {
        Self {
            connection,
            uuid,
            password,
            authenticated: RwLock::new(false),
            udp_relay_mode,
        }
    }

    pub async fn authenticate(&self) -> Result<()> {
        if *self.authenticated.read() {
            return Ok(());
        }

        let mut stream = self.connection.open_uni().await.map_err(|e| {
            Error::network(format!("Failed to open auth stream: {}", e))
        })?;

        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(TUIC_VERSION);
        buf.put_u8(TUIC_CMD_AUTHENTICATE);
        buf.put_slice(self.uuid.as_bytes());

        let token = compute_auth_token(&self.uuid, &self.password);
        buf.put_slice(&token);

        stream.write_all(&buf).await.map_err(|e| {
            Error::network(format!("Failed to send auth: {}", e))
        })?;
        stream.finish().map_err(|e| {
            Error::network(format!("Failed to finish auth stream: {}", e))
        })?;

        *self.authenticated.write() = true;
        debug!("TUIC authentication completed");
        Ok(())
    }

    pub async fn open_tcp_stream(&self, target: &TargetAddr) -> Result<(SendStream, RecvStream)> {
        self.authenticate().await?;

        let (mut send, recv) = self.connection.open_bi().await.map_err(|e| {
            Error::network(format!("Failed to open bi stream: {}", e))
        })?;

        let mut buf = BytesMut::with_capacity(128);
        buf.put_u8(TUIC_VERSION);
        buf.put_u8(TUIC_CMD_CONNECT);
        encode_address(&mut buf, target)?;

        send.write_all(&buf).await.map_err(|e| {
            Error::network(format!("Failed to send connect: {}", e))
        })?;

        debug!("TUIC TCP stream opened for target: {}", target);
        Ok((send, recv))
    }

    pub async fn send_udp_packet(&self, assoc_id: u16, target: &TargetAddr, data: &[u8], frag_id: u8, frag_total: u8) -> Result<()> {
        self.authenticate().await?;

        match self.udp_relay_mode {
            UdpRelayMode::Native => {
                let mut buf = BytesMut::with_capacity(data.len() + 64);
                buf.put_u8(TUIC_VERSION);
                buf.put_u8(TUIC_CMD_PACKET);
                buf.put_u16(assoc_id);
                buf.put_u8(frag_total);
                buf.put_u8(frag_id);
                buf.put_u16(data.len() as u16);
                encode_address(&mut buf, target)?;
                buf.put_slice(data);

                self.connection.send_datagram(buf.freeze()).map_err(|e| {
                    Error::network(format!("Failed to send UDP datagram: {}", e))
                })?;
            }
            UdpRelayMode::Quic => {
                let mut stream = self.connection.open_uni().await.map_err(|e| {
                    Error::network(format!("Failed to open UDP stream: {}", e))
                })?;

                let mut buf = BytesMut::with_capacity(data.len() + 64);
                buf.put_u8(TUIC_VERSION);
                buf.put_u8(TUIC_CMD_PACKET);
                buf.put_u16(assoc_id);
                buf.put_u8(frag_total);
                buf.put_u8(frag_id);
                buf.put_u16(data.len() as u16);
                encode_address(&mut buf, target)?;
                buf.put_slice(data);

                stream.write_all(&buf).await.map_err(|e| {
                    Error::network(format!("Failed to send UDP packet: {}", e))
                })?;
                stream.finish().map_err(|e| {
                    Error::network(format!("Failed to finish UDP stream: {}", e))
                })?;
            }
        }

        debug!("TUIC UDP packet sent to {} ({} bytes)", target, data.len());
        Ok(())
    }

    pub async fn recv_udp_packet(&self) -> Result<(u16, TargetAddr, Vec<u8>)> {
        match self.udp_relay_mode {
            UdpRelayMode::Native => {
                let datagram = self.connection.read_datagram().await.map_err(|e| {
                    Error::network(format!("Failed to receive UDP datagram: {}", e))
                })?;
                parse_udp_packet(&datagram)
            }
            UdpRelayMode::Quic => {
                let mut stream = self.connection.accept_uni().await.map_err(|e| {
                    Error::network(format!("Failed to accept UDP stream: {}", e))
                })?;
                let data = stream.read_to_end(65536).await.map_err(|e| {
                    Error::network(format!("Failed to read UDP stream: {}", e))
                })?;
                parse_udp_packet(&data)
            }
        }
    }

    pub async fn dissociate(&self, assoc_id: u16) -> Result<()> {
        let mut stream = self.connection.open_uni().await.map_err(|e| {
            Error::network(format!("Failed to open dissociate stream: {}", e))
        })?;

        let mut buf = BytesMut::with_capacity(4);
        buf.put_u8(TUIC_VERSION);
        buf.put_u8(TUIC_CMD_DISSOCIATE);
        buf.put_u16(assoc_id);

        stream.write_all(&buf).await.map_err(|e| {
            Error::network(format!("Failed to send dissociate: {}", e))
        })?;
        stream.finish().ok();
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn heartbeat(&self) -> Result<()> {
        let mut stream = self.connection.open_uni().await.map_err(|e| {
            Error::network(format!("Failed to open heartbeat stream: {}", e))
        })?;

        let mut buf = BytesMut::with_capacity(2);
        buf.put_u8(TUIC_VERSION);
        buf.put_u8(TUIC_CMD_HEARTBEAT);

        stream.write_all(&buf).await.map_err(|e| {
            Error::network(format!("Failed to send heartbeat: {}", e))
        })?;
        stream.finish().ok();
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    pub fn close(&self) {
        self.connection.close(0u32.into(), b"close");
    }

    #[allow(dead_code)]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }
}

fn compute_auth_token(uuid: &Uuid, password: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut token = [0u8; 32];
    token.copy_from_slice(&result);
    token
}

fn encode_address(buf: &mut BytesMut, target: &TargetAddr) -> Result<()> {
    match target {
        TargetAddr::Domain(domain, port) => {
            if domain.len() > 255 {
                return Err(Error::protocol("Domain name too long"));
            }
            buf.put_u8(TUIC_ADDR_TYPE_DOMAIN);
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain.as_bytes());
            buf.put_u16(*port);
        }
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => {
                buf.put_u8(TUIC_ADDR_TYPE_IPV4);
                buf.put_slice(&v4.ip().octets());
                buf.put_u16(v4.port());
            }
            std::net::SocketAddr::V6(v6) => {
                buf.put_u8(TUIC_ADDR_TYPE_IPV6);
                buf.put_slice(&v6.ip().octets());
                buf.put_u16(v6.port());
            }
        },
    }
    Ok(())
}

fn parse_udp_packet(data: &[u8]) -> Result<(u16, TargetAddr, Vec<u8>)> {
    if data.len() < 8 {
        return Err(Error::protocol("UDP packet too short"));
    }

    let mut buf = data;
    let version = buf.get_u8();
    if version != TUIC_VERSION {
        return Err(Error::protocol(format!("Invalid TUIC version: {}", version)));
    }

    let cmd = buf.get_u8();
    if cmd != TUIC_CMD_PACKET {
        return Err(Error::protocol(format!("Invalid UDP command: {}", cmd)));
    }

    let assoc_id = buf.get_u16();
    let _frag_total = buf.get_u8();
    let _frag_id = buf.get_u8();
    let length = buf.get_u16() as usize;

    let (target, remaining) = parse_address(buf)?;

    if remaining.len() < length {
        return Err(Error::protocol("UDP packet data truncated"));
    }

    let payload = remaining[..length].to_vec();
    Ok((assoc_id, target, payload))
}

fn parse_address(data: &[u8]) -> Result<(TargetAddr, &[u8])> {
    if data.is_empty() {
        return Err(Error::protocol("Empty address data"));
    }

    let addr_type = data[0];
    let remaining = &data[1..];

    match addr_type {
        TUIC_ADDR_TYPE_IPV4 => {
            if remaining.len() < 6 {
                return Err(Error::protocol("IPv4 address too short"));
            }
            let ip = std::net::Ipv4Addr::new(remaining[0], remaining[1], remaining[2], remaining[3]);
            let port = u16::from_be_bytes([remaining[4], remaining[5]]);
            let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));
            Ok((TargetAddr::Ip(addr), &remaining[6..]))
        }
        TUIC_ADDR_TYPE_DOMAIN => {
            if remaining.is_empty() {
                return Err(Error::protocol("Domain length missing"));
            }
            let len = remaining[0] as usize;
            if remaining.len() < 1 + len + 2 {
                return Err(Error::protocol("Domain data too short"));
            }
            let domain = String::from_utf8(remaining[1..1 + len].to_vec())
                .map_err(|_| Error::protocol("Invalid domain encoding"))?;
            let port = u16::from_be_bytes([remaining[1 + len], remaining[2 + len]]);
            Ok((TargetAddr::Domain(domain, port), &remaining[3 + len..]))
        }
        TUIC_ADDR_TYPE_IPV6 => {
            if remaining.len() < 18 {
                return Err(Error::protocol("IPv6 address too short"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&remaining[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([remaining[16], remaining[17]]);
            let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0));
            Ok((TargetAddr::Ip(addr), &remaining[18..]))
        }
        _ => Err(Error::protocol(format!("Unknown address type: {}", addr_type))),
    }
}

pub struct TuicOutbound {
    config: OutboundConfig,
    tuic_config: TuicConfig,
    uuid: Uuid,
    endpoint: Mutex<Option<Endpoint>>,
    connection: Mutex<Option<Arc<TuicConnection>>>,
}

impl TuicOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| Error::config("Missing server address for TUIC"))?
            .clone();

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for TUIC"))?;

        let uuid_str = config
            .options
            .get("uuid")
            .map(yaml_value_to_string)
            .ok_or_else(|| Error::config("Missing UUID for TUIC"))?;

        let uuid = Uuid::parse_str(&uuid_str)
            .map_err(|e| Error::config(format!("Invalid UUID: {}", e)))?;

        let password = config
            .options
            .get("password")
            .map(yaml_value_to_string)
            .unwrap_or_default();

        let alpn = config
            .options
            .get("alpn")
            .and_then(|v| v.as_sequence())
            .map(|seq| seq.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["h3".to_string()]);

        let sni = config
            .options
            .get("sni")
            .map(yaml_value_to_string)
            .filter(|s| !s.is_empty());

        let skip_cert_verify = config
            .options
            .get("skip-cert-verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let disable_sni = config
            .options
            .get("disable-sni")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let congestion_control = config
            .options
            .get("congestion-controller")
            .or_else(|| config.options.get("congestion_control"))
            .map(yaml_value_to_string)
            .and_then(|s| s.parse().ok())
            .unwrap_or_default();

        let udp_relay_mode = config
            .options
            .get("udp-relay-mode")
            .map(yaml_value_to_string)
            .and_then(|s| s.parse().ok())
            .unwrap_or_default();

        let zero_rtt_handshake = config
            .options
            .get("reduce-rtt")
            .or_else(|| config.options.get("zero-rtt-handshake"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let heartbeat = config
            .options
            .get("heartbeat-interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(10000);

        let reduce_rtt = config
            .options
            .get("reduce-rtt")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let tuic_config = TuicConfig {
            server,
            port,
            uuid: uuid_str,
            password,
            alpn,
            sni,
            skip_cert_verify,
            disable_sni,
            congestion_control,
            udp_relay_mode,
            zero_rtt_handshake,
            heartbeat,
            reduce_rtt,
        };

        debug!(
            "Creating TUIC outbound: server={}:{}, uuid={}, cc={:?}",
            tuic_config.server, tuic_config.port, tuic_config.uuid, tuic_config.congestion_control
        );

        Ok(Self {
            config,
            tuic_config,
            uuid,
            endpoint: Mutex::new(None),
            connection: Mutex::new(None),
        })
    }

    pub fn tuic_config(&self) -> &TuicConfig {
        &self.tuic_config
    }

    fn create_client_config(&self) -> Result<QuinnClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        for cert in certs.certs {
            root_store.add(cert).ok();
        }

        let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

        let mut tls_config = if self.tuic_config.skip_cert_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth()
        } else {
            builder.with_no_client_auth()
        };

        tls_config.alpn_protocols = self.tuic_config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| Error::config(format!("Failed to create QUIC config: {}", e)))?;

        let mut client_config = QuinnClientConfig::new(Arc::new(quic_config));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(100u32.into());
        transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(Duration::from_millis(self.tuic_config.heartbeat)));

        match self.tuic_config.congestion_control {
            CongestionControl::Bbr => {
                transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            }
            CongestionControl::Cubic => {
                transport_config.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
            }
            CongestionControl::NewReno => {}
        }

        client_config.transport_config(Arc::new(transport_config));
        Ok(client_config)
    }

    async fn get_or_create_connection(&self) -> Result<Arc<TuicConnection>> {
        let mut conn_guard = self.connection.lock().await;

        if let Some(ref conn) = *conn_guard {
            if !conn.is_closed() {
                return Ok(conn.clone());
            }
        }

        let addr = format!("{}:{}", self.tuic_config.server, self.tuic_config.port);
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to resolve TUIC server {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| Error::network(format!("No addresses found for TUIC server {}", addr)))?;

        let mut endpoint_guard = self.endpoint.lock().await;
        let endpoint = match endpoint_guard.take() {
            Some(ep) => ep,
            None => {
                let bind_addr: SocketAddr = if socket_addr.is_ipv6() {
                    "[::]:0".parse().unwrap()
                } else {
                    "0.0.0.0:0".parse().unwrap()
                };
                Endpoint::client(bind_addr).map_err(|e| {
                    Error::network(format!("Failed to create QUIC endpoint: {}", e))
                })?
            }
        };

        let client_config = self.create_client_config()?;
        let server_name = if self.tuic_config.disable_sni {
            "localhost"
        } else {
            self.tuic_config.sni.as_deref().unwrap_or(&self.tuic_config.server)
        };

        let connecting = endpoint.connect_with(client_config, socket_addr, server_name)
            .map_err(|e| Error::network(format!("Failed to connect to TUIC server: {}", e)))?;

        let connection = connecting.await.map_err(|e| {
            Error::network(format!("QUIC connection failed: {}", e))
        })?;

        debug!("TUIC QUIC connection established to {}", socket_addr);

        let tuic_conn = Arc::new(TuicConnection::new(
            connection,
            self.uuid,
            self.tuic_config.password.clone(),
            self.tuic_config.udp_relay_mode,
        ));

        tuic_conn.authenticate().await?;

        *endpoint_guard = Some(endpoint);
        *conn_guard = Some(tuic_conn.clone());

        Ok(tuic_conn)
    }

    pub async fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let conn = self.get_or_create_connection().await?;
        let assoc_id: u16 = rand::random();

        conn.send_udp_packet(assoc_id, target, data, 0, 1).await?;

        let timeout = Duration::from_secs(30);
        let result = tokio::time::timeout(timeout, conn.recv_udp_packet()).await
            .map_err(|_| Error::network("UDP receive timeout"))?;

        let (_recv_assoc_id, _recv_target, payload) = result?;
        conn.dissociate(assoc_id).await.ok();

        Ok(payload)
    }
}

#[async_trait::async_trait]
impl OutboundProxy for TuicOutbound {
    async fn connect(&self) -> Result<()> {
        let _conn = self.get_or_create_connection().await?;
        info!(
            "TUIC outbound '{}' connected to {}:{}",
            self.config.tag, self.tuic_config.server, self.tuic_config.port
        );
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        let mut conn_guard = self.connection.lock().await;
        if let Some(conn) = conn_guard.take() {
            conn.close();
        }
        let mut endpoint_guard = self.endpoint.lock().await;
        if let Some(endpoint) = endpoint_guard.take() {
            endpoint.close(0u32.into(), b"disconnect");
        }
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.tuic_config.server.clone(), self.tuic_config.port))
    }

    async fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        use std::time::Instant;

        let url = url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;

        let host = url.host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() { "/" } else { url.path() };

        let start = Instant::now();

        let conn = tokio::time::timeout(timeout, self.get_or_create_connection())
            .await
            .map_err(|_| Error::network("Connection timeout"))??;

        let target = TargetAddr::Domain(host.clone(), url_port);
        let (mut send, mut recv) = conn.open_tcp_stream(&target).await?;

        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: VeloGuard/1.0\r\n\r\n",
            path, host
        );

        send.write_all(http_request.as_bytes()).await.map_err(|e| {
            Error::network(format!("Failed to send HTTP request: {}", e))
        })?;

        let result = tokio::time::timeout(timeout, async {
            let mut response = vec![0u8; 1024];
            let n = recv.read(&mut response).await
                .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?
                .ok_or_else(|| Error::network("Empty response"))?;

            let response_str = String::from_utf8_lossy(&response[..n]);
            if response_str.starts_with("HTTP/") {
                Ok(())
            } else {
                Err(Error::network("Invalid HTTP response"))
            }
        }).await;

        match result {
            Ok(Ok(())) => {
                let elapsed = start.elapsed();
                info!("TUIC latency test success: {}ms", elapsed.as_millis());
                Ok(elapsed)
            }
            Ok(Err(e)) => {
                warn!("TUIC latency test failed: {}", e);
                Err(e)
            }
            Err(_) => {
                warn!("TUIC latency test timeout");
                Err(Error::network("Response timeout"))
            }
        }
    }

    async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None).await
    }

    async fn relay_tcp_with_connection(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<Arc<TrackedConnection>>,
    ) -> Result<()> {
        let conn = self.get_or_create_connection().await?;
        let (mut send, mut recv) = conn.open_tcp_stream(&target).await?;

        debug!(
            "TUIC: relaying TCP to {} via {}:{}",
            target, self.tuic_config.server, self.tuic_config.port
        );

        let tracker = global_tracker();
        let (mut ri, mut wi) = tokio::io::split(inbound);

        let conn_upload = connection.clone();
        let conn_download = connection.clone();

        let client_to_remote = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = ri.read(&mut buf).await.map_err(|e| {
                    Error::network(format!("Failed to read from inbound: {}", e))
                })?;
                if n == 0 {
                    break;
                }
                send.write_all(&buf[..n]).await.map_err(|e| {
                    Error::network(format!("Failed to write to TUIC: {}", e))
                })?;

                tracker.add_global_upload(n as u64);
                if let Some(ref conn) = conn_upload {
                    conn.add_upload(n as u64);
                }
            }
            send.finish().ok();
            Ok::<(), Error>(())
        };

        let remote_to_client = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) if n > 0 => {
                        wi.write_all(&buf[..n]).await.map_err(|e| {
                            Error::network(format!("Failed to write to inbound: {}", e))
                        })?;

                        tracker.add_global_download(n as u64);
                        if let Some(ref conn) = conn_download {
                            conn.add_download(n as u64);
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("reset") || err_str.contains("closed") {
                            break;
                        }
                        return Err(Error::network(format!("Failed to read from TUIC: {}", e)));
                    }
                }
            }
            wi.shutdown().await.ok();
            Ok::<(), Error>(())
        };

        let result = tokio::try_join!(client_to_remote, remote_to_client);

        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("connection") || err_str.contains("reset") || err_str.contains("broken") {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_control_from_str() {
        assert_eq!("cubic".parse::<CongestionControl>().unwrap(), CongestionControl::Cubic);
        assert_eq!("bbr".parse::<CongestionControl>().unwrap(), CongestionControl::Bbr);
        assert_eq!("newreno".parse::<CongestionControl>().unwrap(), CongestionControl::NewReno);
        assert_eq!("new_reno".parse::<CongestionControl>().unwrap(), CongestionControl::NewReno);
        assert!("invalid".parse::<CongestionControl>().is_err());
    }

    #[test]
    fn test_udp_relay_mode_from_str() {
        assert_eq!("native".parse::<UdpRelayMode>().unwrap(), UdpRelayMode::Native);
        assert_eq!("quic".parse::<UdpRelayMode>().unwrap(), UdpRelayMode::Quic);
        assert!("invalid".parse::<UdpRelayMode>().is_err());
    }

    #[test]
    fn test_tuic_config_default() {
        let config = TuicConfig::default();
        assert_eq!(config.port, 443);
        assert_eq!(config.alpn, vec!["h3".to_string()]);
        assert_eq!(config.congestion_control, CongestionControl::Cubic);
        assert_eq!(config.udp_relay_mode, UdpRelayMode::Native);
        assert!(!config.skip_cert_verify);
        assert!(!config.disable_sni);
    }

    #[test]
    fn test_compute_auth_token() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let password = "test_password";
        let token = compute_auth_token(&uuid, password);
        assert_eq!(token.len(), 32);

        let token2 = compute_auth_token(&uuid, password);
        assert_eq!(token, token2);
    }

    #[test]
    fn test_encode_address_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        encode_address(&mut buf, &target).unwrap();

        assert_eq!(buf[0], TUIC_ADDR_TYPE_DOMAIN);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([buf[13], buf[14]]), 443);
    }

    #[test]
    fn test_encode_address_ipv4() {
        let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            8080,
        ));
        let target = TargetAddr::Ip(addr);
        let mut buf = BytesMut::new();
        encode_address(&mut buf, &target).unwrap();

        assert_eq!(buf[0], TUIC_ADDR_TYPE_IPV4);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(u16::from_be_bytes([buf[5], buf[6]]), 8080);
    }

    #[test]
    fn test_encode_address_ipv6() {
        let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            443,
            0,
            0,
        ));
        let target = TargetAddr::Ip(addr);
        let mut buf = BytesMut::new();
        encode_address(&mut buf, &target).unwrap();

        assert_eq!(buf[0], TUIC_ADDR_TYPE_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);
    }

    #[test]
    fn test_parse_address_ipv4() {
        let data = [TUIC_ADDR_TYPE_IPV4, 192, 168, 1, 1, 0x1F, 0x90];
        let (target, remaining) = parse_address(&data).unwrap();

        match target {
            TargetAddr::Ip(addr) => {
                assert_eq!(addr.port(), 8080);
                match addr {
                    std::net::SocketAddr::V4(v4) => {
                        assert_eq!(*v4.ip(), std::net::Ipv4Addr::new(192, 168, 1, 1));
                    }
                    _ => panic!("Expected IPv4"),
                }
            }
            _ => panic!("Expected IP address"),
        }
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_parse_address_domain() {
        let mut data = vec![TUIC_ADDR_TYPE_DOMAIN, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());

        let (target, remaining) = parse_address(&data).unwrap();

        match target {
            TargetAddr::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected domain"),
        }
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_tuic_outbound_new() {
        let mut options = std::collections::HashMap::new();
        options.insert("uuid".to_string(), serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()));
        options.insert("password".to_string(), serde_yaml::Value::String("test_pass".to_string()));
        options.insert("skip-cert-verify".to_string(), serde_yaml::Value::Bool(true));
        options.insert("congestion-controller".to_string(), serde_yaml::Value::String("bbr".to_string()));

        let config = OutboundConfig {
            tag: "tuic-test".to_string(),
            outbound_type: crate::config::OutboundType::Tuic,
            server: Some("tuic.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = TuicOutbound::new(config).unwrap();

        assert_eq!(outbound.tag(), "tuic-test");
        assert_eq!(outbound.tuic_config.server, "tuic.example.com");
        assert_eq!(outbound.tuic_config.port, 443);
        assert!(outbound.tuic_config.skip_cert_verify);
        assert_eq!(outbound.tuic_config.congestion_control, CongestionControl::Bbr);
    }

    #[test]
    fn test_tuic_outbound_missing_uuid() {
        let config = OutboundConfig {
            tag: "tuic-test".to_string(),
            outbound_type: crate::config::OutboundType::Tuic,
            server: Some("tuic.example.com".to_string()),
            port: Some(443),
            options: std::collections::HashMap::new(),
        };

        let result = TuicOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_tuic_outbound_server_addr() {
        let mut options = std::collections::HashMap::new();
        options.insert("uuid".to_string(), serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()));

        let config = OutboundConfig {
            tag: "tuic-test".to_string(),
            outbound_type: crate::config::OutboundType::Tuic,
            server: Some("tuic.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "tuic.example.com");
        assert_eq!(port, 443);
    }
}
