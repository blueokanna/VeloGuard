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

const HY2_VERSION: u8 = 0x03;
const HY2_FRAME_TYPE_TCP: u8 = 0x00;
const HY2_FRAME_TYPE_UDP: u8 = 0x01;

const HY2_ADDR_TYPE_IPV4: u8 = 0x01;
const HY2_ADDR_TYPE_DOMAIN: u8 = 0x03;
const HY2_ADDR_TYPE_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq)]
#[derive(Default)]
pub enum ObfsType {
    #[default]
    None,
    Salamander(String),
}


#[derive(Debug, Clone)]
pub struct Hysteria2Config {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub obfs: ObfsType,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub fingerprint: Option<String>,
    pub ports: Option<String>,
    pub hop_interval: Option<u32>,
    pub disable_mtu_discovery: bool,
}

impl Default for Hysteria2Config {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            password: String::new(),
            obfs: ObfsType::None,
            sni: None,
            skip_cert_verify: false,
            alpn: vec!["h3".to_string()],
            up_mbps: None,
            down_mbps: None,
            fingerprint: None,
            ports: None,
            hop_interval: None,
            disable_mtu_discovery: false,
        }
    }
}

pub struct Hysteria2Connection {
    connection: Connection,
    password: String,
    authenticated: RwLock<bool>,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
}

impl Hysteria2Connection {
    pub fn new(connection: Connection, password: String, up_mbps: Option<u32>, down_mbps: Option<u32>) -> Self {
        Self {
            connection,
            password,
            authenticated: RwLock::new(false),
            up_mbps,
            down_mbps,
        }
    }

    pub async fn authenticate(&self) -> Result<()> {
        if *self.authenticated.read() {
            return Ok(());
        }

        let (mut send, mut recv) = self.connection.open_bi().await.map_err(|e| {
            Error::network(format!("Failed to open auth stream: {}", e))
        })?;

        let auth_request = self.build_auth_request();
        send.write_all(&auth_request).await.map_err(|e| {
            Error::network(format!("Failed to send auth request: {}", e))
        })?;
        send.finish().map_err(|e| {
            Error::network(format!("Failed to finish auth stream: {}", e))
        })?;

        let mut response = vec![0u8; 256];
        let n = recv.read(&mut response).await
            .map_err(|e| Error::network(format!("Failed to read auth response: {}", e)))?
            .ok_or_else(|| Error::network("Empty auth response"))?;

        if n < 1 {
            return Err(Error::protocol("Invalid auth response"));
        }

        let status = response[0];
        if status != 0x00 {
            let msg = if n > 1 {
                String::from_utf8_lossy(&response[1..n]).to_string()
            } else {
                format!("Auth failed with status: {}", status)
            };
            return Err(Error::protocol(msg));
        }

        *self.authenticated.write() = true;
        debug!("Hysteria2 authentication completed");
        Ok(())
    }

    fn build_auth_request(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(256);
        buf.put_u8(HY2_VERSION);
        let password_bytes = self.password.as_bytes();
        buf.put_u8(password_bytes.len() as u8);
        buf.put_slice(password_bytes);
        if let Some(up) = self.up_mbps {
            buf.put_u32(up);
        } else {
            buf.put_u32(0);
        }
        if let Some(down) = self.down_mbps {
            buf.put_u32(down);
        } else {
            buf.put_u32(0);
        }
        buf.to_vec()
    }

    pub async fn open_tcp_stream(&self, target: &TargetAddr) -> Result<(SendStream, RecvStream)> {
        self.authenticate().await?;

        let (mut send, recv) = self.connection.open_bi().await.map_err(|e| {
            Error::network(format!("Failed to open bi stream: {}", e))
        })?;

        let mut buf = BytesMut::with_capacity(128);
        buf.put_u8(HY2_FRAME_TYPE_TCP);
        encode_address(&mut buf, target)?;

        send.write_all(&buf).await.map_err(|e| {
            Error::network(format!("Failed to send connect request: {}", e))
        })?;

        debug!("Hysteria2 TCP stream opened for target: {}", target);
        Ok((send, recv))
    }

    pub async fn send_udp_packet(&self, session_id: u32, target: &TargetAddr, data: &[u8]) -> Result<()> {
        self.authenticate().await?;

        let mut buf = BytesMut::with_capacity(data.len() + 64);
        buf.put_u8(HY2_FRAME_TYPE_UDP);
        buf.put_u32(session_id);
        buf.put_u16(data.len() as u16);
        encode_address(&mut buf, target)?;
        buf.put_slice(data);

        self.connection.send_datagram(buf.freeze()).map_err(|e| {
            Error::network(format!("Failed to send UDP datagram: {}", e))
        })?;

        debug!("Hysteria2 UDP packet sent to {} ({} bytes)", target, data.len());
        Ok(())
    }

    pub async fn recv_udp_packet(&self) -> Result<(u32, TargetAddr, Vec<u8>)> {
        let datagram = self.connection.read_datagram().await.map_err(|e| {
            Error::network(format!("Failed to receive UDP datagram: {}", e))
        })?;
        parse_udp_packet(&datagram)
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

fn encode_address(buf: &mut BytesMut, target: &TargetAddr) -> Result<()> {
    match target {
        TargetAddr::Domain(domain, port) => {
            if domain.len() > 255 {
                return Err(Error::protocol("Domain name too long"));
            }
            buf.put_u8(HY2_ADDR_TYPE_DOMAIN);
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain.as_bytes());
            buf.put_u16(*port);
        }
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => {
                buf.put_u8(HY2_ADDR_TYPE_IPV4);
                buf.put_slice(&v4.ip().octets());
                buf.put_u16(v4.port());
            }
            std::net::SocketAddr::V6(v6) => {
                buf.put_u8(HY2_ADDR_TYPE_IPV6);
                buf.put_slice(&v6.ip().octets());
                buf.put_u16(v6.port());
            }
        },
    }
    Ok(())
}

fn parse_udp_packet(data: &[u8]) -> Result<(u32, TargetAddr, Vec<u8>)> {
    if data.len() < 8 {
        return Err(Error::protocol("UDP packet too short"));
    }

    let mut buf = data;
    let frame_type = buf.get_u8();
    if frame_type != HY2_FRAME_TYPE_UDP {
        return Err(Error::protocol(format!("Invalid UDP frame type: {}", frame_type)));
    }

    let session_id = buf.get_u32();
    let length = buf.get_u16() as usize;

    let (target, remaining) = parse_address(buf)?;

    if remaining.len() < length {
        return Err(Error::protocol("UDP packet data truncated"));
    }

    let payload = remaining[..length].to_vec();
    Ok((session_id, target, payload))
}

fn parse_address(data: &[u8]) -> Result<(TargetAddr, &[u8])> {
    if data.is_empty() {
        return Err(Error::protocol("Empty address data"));
    }

    let addr_type = data[0];
    let remaining = &data[1..];

    match addr_type {
        HY2_ADDR_TYPE_IPV4 => {
            if remaining.len() < 6 {
                return Err(Error::protocol("IPv4 address too short"));
            }
            let ip = std::net::Ipv4Addr::new(remaining[0], remaining[1], remaining[2], remaining[3]);
            let port = u16::from_be_bytes([remaining[4], remaining[5]]);
            let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));
            Ok((TargetAddr::Ip(addr), &remaining[6..]))
        }
        HY2_ADDR_TYPE_DOMAIN => {
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
        HY2_ADDR_TYPE_IPV6 => {
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

pub struct SalamanderObfs {
    #[allow(dead_code)]
    key: [u8; 32],
}

impl SalamanderObfs {
    pub fn new(password: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"hysteria2-salamander-");
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self { key }
    }

    #[allow(dead_code)]
    pub fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        for (i, byte) in result.iter_mut().enumerate() {
            *byte ^= self.key[i % 32];
        }
        result
    }

    #[allow(dead_code)]
    pub fn deobfuscate(&self, data: &[u8]) -> Vec<u8> {
        self.obfuscate(data)
    }
}

pub struct Hysteria2Outbound {
    config: OutboundConfig,
    hy2_config: Hysteria2Config,
    #[allow(dead_code)]
    obfs: Option<SalamanderObfs>,
    endpoint: Mutex<Option<Endpoint>>,
    connection: Mutex<Option<Arc<Hysteria2Connection>>>,
}

impl Hysteria2Outbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| Error::config("Missing server address for Hysteria2"))?
            .clone();

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for Hysteria2"))?;

        let password = config
            .options
            .get("password")
            .or_else(|| config.options.get("auth"))
            .map(yaml_value_to_string)
            .ok_or_else(|| Error::config("Missing password for Hysteria2"))?;

        let obfs = if let Some(obfs_type) = config.options.get("obfs").map(yaml_value_to_string) {
            if obfs_type == "salamander" {
                let obfs_password = config
                    .options
                    .get("obfs-password")
                    .map(yaml_value_to_string)
                    .unwrap_or_default();
                ObfsType::Salamander(obfs_password)
            } else {
                ObfsType::None
            }
        } else {
            ObfsType::None
        };

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

        let alpn = config
            .options
            .get("alpn")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["h3".to_string()]);

        let up_mbps = config
            .options
            .get("up")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let down_mbps = config
            .options
            .get("down")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let fingerprint = config
            .options
            .get("fingerprint")
            .map(yaml_value_to_string)
            .filter(|s| !s.is_empty());

        let ports = config
            .options
            .get("ports")
            .map(yaml_value_to_string)
            .filter(|s| !s.is_empty());

        let hop_interval = config
            .options
            .get("hop-interval")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let disable_mtu_discovery = config
            .options
            .get("disable-mtu-discovery")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let obfs_impl = match &obfs {
            ObfsType::Salamander(pwd) => Some(SalamanderObfs::new(pwd)),
            ObfsType::None => None,
        };

        let hy2_config = Hysteria2Config {
            server,
            port,
            password,
            obfs,
            sni,
            skip_cert_verify,
            alpn,
            up_mbps,
            down_mbps,
            fingerprint,
            ports,
            hop_interval,
            disable_mtu_discovery,
        };

        debug!(
            "Creating Hysteria2 outbound: server={}:{}, obfs={:?}, up={:?}Mbps, down={:?}Mbps",
            hy2_config.server, hy2_config.port, hy2_config.obfs, hy2_config.up_mbps, hy2_config.down_mbps
        );

        Ok(Self {
            config,
            hy2_config,
            obfs: obfs_impl,
            endpoint: Mutex::new(None),
            connection: Mutex::new(None),
        })
    }

    pub fn hy2_config(&self) -> &Hysteria2Config {
        &self.hy2_config
    }

    fn create_client_config(&self) -> Result<QuinnClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        for cert in certs.certs {
            root_store.add(cert).ok();
        }

        let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

        let mut tls_config = if self.hy2_config.skip_cert_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth()
        } else {
            builder.with_no_client_auth()
        };

        tls_config.alpn_protocols = self.hy2_config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| Error::config(format!("Failed to create QUIC config: {}", e)))?;

        let mut client_config = QuinnClientConfig::new(Arc::new(quic_config));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(100u32.into());
        transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(Duration::from_secs(10)));

        if self.hy2_config.disable_mtu_discovery {
            transport_config.mtu_discovery_config(None);
        }

        client_config.transport_config(Arc::new(transport_config));
        Ok(client_config)
    }

    async fn get_or_create_connection(&self) -> Result<Arc<Hysteria2Connection>> {
        let mut conn_guard = self.connection.lock().await;

        if let Some(ref conn) = *conn_guard {
            if !conn.is_closed() {
                return Ok(conn.clone());
            }
        }

        let addr = format!("{}:{}", self.hy2_config.server, self.hy2_config.port);
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to resolve Hysteria2 server {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| Error::network(format!("No addresses found for Hysteria2 server {}", addr)))?;

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
        let server_name = self.hy2_config.sni.as_deref().unwrap_or(&self.hy2_config.server);

        let connecting = endpoint.connect_with(client_config, socket_addr, server_name)
            .map_err(|e| Error::network(format!("Failed to connect to Hysteria2 server: {}", e)))?;

        let connection = connecting.await.map_err(|e| {
            Error::network(format!("QUIC connection failed: {}", e))
        })?;

        debug!("Hysteria2 QUIC connection established to {}", socket_addr);

        let hy2_conn = Arc::new(Hysteria2Connection::new(
            connection,
            self.hy2_config.password.clone(),
            self.hy2_config.up_mbps,
            self.hy2_config.down_mbps,
        ));

        hy2_conn.authenticate().await?;

        *endpoint_guard = Some(endpoint);
        *conn_guard = Some(hy2_conn.clone());

        Ok(hy2_conn)
    }

    pub async fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let conn = self.get_or_create_connection().await?;
        let session_id: u32 = rand::random();

        conn.send_udp_packet(session_id, target, data).await?;

        let timeout = Duration::from_secs(30);
        let result = tokio::time::timeout(timeout, conn.recv_udp_packet()).await
            .map_err(|_| Error::network("UDP receive timeout"))?;

        let (_recv_session_id, _recv_target, payload) = result?;
        Ok(payload)
    }
}

#[async_trait::async_trait]
impl OutboundProxy for Hysteria2Outbound {
    async fn connect(&self) -> Result<()> {
        let _conn = self.get_or_create_connection().await?;
        info!(
            "Hysteria2 outbound '{}' connected to {}:{}",
            self.config.tag, self.hy2_config.server, self.hy2_config.port
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
        Some((self.hy2_config.server.clone(), self.hy2_config.port))
    }
    
    fn supports_udp(&self) -> bool {
        true // Hysteria2 always supports UDP
    }
    
    async fn relay_udp_packet(
        &self,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.relay_udp(target, data).await
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
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
            path, host, crate::USER_AGENT
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
                info!("Hysteria2 latency test success: {}ms", elapsed.as_millis());
                Ok(elapsed)
            }
            Ok(Err(e)) => {
                warn!("Hysteria2 latency test failed: {}", e);
                Err(e)
            }
            Err(_) => {
                warn!("Hysteria2 latency test timeout");
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
            "Hysteria2: relaying TCP to {} via {}:{}",
            target, self.hy2_config.server, self.hy2_config.port
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
                    Error::network(format!("Failed to write to Hysteria2: {}", e))
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
                        return Err(Error::network(format!("Failed to read from Hysteria2: {}", e)));
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
    fn test_obfs_type_default() {
        let obfs = ObfsType::default();
        assert_eq!(obfs, ObfsType::None);
    }

    #[test]
    fn test_hysteria2_config_default() {
        let config = Hysteria2Config::default();
        assert_eq!(config.port, 443);
        assert_eq!(config.alpn, vec!["h3".to_string()]);
        assert!(!config.skip_cert_verify);
        assert!(config.up_mbps.is_none());
        assert!(config.down_mbps.is_none());
    }

    #[test]
    fn test_salamander_obfs() {
        let obfs = SalamanderObfs::new("test_password");
        let data = b"hello world";
        let obfuscated = obfs.obfuscate(data);
        let deobfuscated = obfs.deobfuscate(&obfuscated);
        assert_eq!(deobfuscated, data);
    }

    #[test]
    fn test_salamander_obfs_deterministic() {
        let obfs1 = SalamanderObfs::new("same_password");
        let obfs2 = SalamanderObfs::new("same_password");
        let data = b"test data";
        assert_eq!(obfs1.obfuscate(data), obfs2.obfuscate(data));
    }

    #[test]
    fn test_encode_address_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        encode_address(&mut buf, &target).unwrap();

        assert_eq!(buf[0], HY2_ADDR_TYPE_DOMAIN);
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

        assert_eq!(buf[0], HY2_ADDR_TYPE_IPV4);
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

        assert_eq!(buf[0], HY2_ADDR_TYPE_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);
    }

    #[test]
    fn test_parse_address_ipv4() {
        let data = [HY2_ADDR_TYPE_IPV4, 192, 168, 1, 1, 0x1F, 0x90];
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
        let mut data = vec![HY2_ADDR_TYPE_DOMAIN, 11];
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
    fn test_hysteria2_outbound_new() {
        let mut options = std::collections::HashMap::new();
        options.insert("password".to_string(), serde_yaml::Value::String("test_pass".to_string()));
        options.insert("skip-cert-verify".to_string(), serde_yaml::Value::Bool(true));
        options.insert("up".to_string(), serde_yaml::Value::Number(100.into()));
        options.insert("down".to_string(), serde_yaml::Value::Number(200.into()));
        options.insert("obfs".to_string(), serde_yaml::Value::String("salamander".to_string()));
        options.insert("obfs-password".to_string(), serde_yaml::Value::String("obfs_pass".to_string()));

        let config = OutboundConfig {
            tag: "hy2-test".to_string(),
            outbound_type: crate::config::OutboundType::Hysteria2,
            server: Some("hy2.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = Hysteria2Outbound::new(config).unwrap();

        assert_eq!(outbound.tag(), "hy2-test");
        assert_eq!(outbound.hy2_config.server, "hy2.example.com");
        assert_eq!(outbound.hy2_config.port, 443);
        assert!(outbound.hy2_config.skip_cert_verify);
        assert_eq!(outbound.hy2_config.up_mbps, Some(100));
        assert_eq!(outbound.hy2_config.down_mbps, Some(200));
        assert!(matches!(outbound.hy2_config.obfs, ObfsType::Salamander(_)));
    }

    #[test]
    fn test_hysteria2_outbound_missing_password() {
        let config = OutboundConfig {
            tag: "hy2-test".to_string(),
            outbound_type: crate::config::OutboundType::Hysteria2,
            server: Some("hy2.example.com".to_string()),
            port: Some(443),
            options: std::collections::HashMap::new(),
        };

        let result = Hysteria2Outbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_hysteria2_outbound_server_addr() {
        let mut options = std::collections::HashMap::new();
        options.insert("password".to_string(), serde_yaml::Value::String("test_pass".to_string()));

        let config = OutboundConfig {
            tag: "hy2-test".to_string(),
            outbound_type: crate::config::OutboundType::Hysteria2,
            server: Some("hy2.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = Hysteria2Outbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "hy2.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_address_roundtrip_domain() {
        let target = TargetAddr::Domain("test.example.org".to_string(), 8443);
        let mut buf = BytesMut::new();
        encode_address(&mut buf, &target).unwrap();
        let (parsed, _) = parse_address(&buf).unwrap();
        
        match (target, parsed) {
            (TargetAddr::Domain(d1, p1), TargetAddr::Domain(d2, p2)) => {
                assert_eq!(d1, d2);
                assert_eq!(p1, p2);
            }
            _ => panic!("Address type mismatch"),
        }
    }

    #[test]
    fn test_address_roundtrip_ipv4() {
        let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            12345,
        ));
        let target = TargetAddr::Ip(addr);
        let mut buf = BytesMut::new();
        encode_address(&mut buf, &target).unwrap();
        let (parsed, _) = parse_address(&buf).unwrap();
        
        match (target, parsed) {
            (TargetAddr::Ip(a1), TargetAddr::Ip(a2)) => {
                assert_eq!(a1, a2);
            }
            _ => panic!("Address type mismatch"),
        }
    }
}
