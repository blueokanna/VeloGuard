use crate::config::OutboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use crate::tls::SkipServerVerification;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

const VLESS_VERSION: u8 = 0x00;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp = 0x01,
    Udp = 0x02,
    #[allow(dead_code)]
    Mux = 0x03,
}

impl VlessCommand {
    #[allow(dead_code)]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(VlessCommand::Tcp),
            0x02 => Some(VlessCommand::Udp),
            0x03 => Some(VlessCommand::Mux),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessFlow {
    None,
    XtlsRprxVision,
    XtlsRprxVisionUdp443,
}

impl VlessFlow {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "xtls-rprx-vision" | "vision" => VlessFlow::XtlsRprxVision,
            "xtls-rprx-vision-udp443" => VlessFlow::XtlsRprxVisionUdp443,
            _ => VlessFlow::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            VlessFlow::None => "",
            VlessFlow::XtlsRprxVision => "xtls-rprx-vision",
            VlessFlow::XtlsRprxVisionUdp443 => "xtls-rprx-vision-udp443",
        }
    }

    pub fn is_vision(&self) -> bool {
        matches!(self, VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp443)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum VlessAddressType {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

#[allow(dead_code)]
pub struct VlessRequest {
    pub version: u8,
    pub uuid: [u8; 16],
    pub addons_len: u8,
    pub addons: Vec<u8>,
    pub command: VlessCommand,
    pub port: u16,
    pub address_type: VlessAddressType,
    pub address: Vec<u8>,
}

#[allow(dead_code)]
pub struct VlessResponse {
    pub version: u8,
    pub addons_len: u8,
    pub addons: Vec<u8>,
}

pub struct VlessOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    uuid: Uuid,
    uuid_bytes: [u8; 16],
    flow: VlessFlow,
    sni: String,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    udp_enabled: bool,
}

impl VlessOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for VLess"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for VLess"))?;

        let uuid_str = config
            .options
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Missing UUID for VLess"))?;

        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|e| Error::config(format!("Invalid UUID: {}", e)))?;

        let uuid_bytes = *uuid.as_bytes();

        let flow_str = config
            .options
            .get("flow")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let flow = VlessFlow::from_str(flow_str);

        let sni = config
            .options
            .get("sni")
            .or_else(|| config.options.get("servername"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| server.clone());

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
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]);

        // Default UDP to true to support QUIC and other UDP protocols
        let udp_enabled = config
            .options
            .get("udp")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        Ok(Self {
            config,
            server,
            port,
            uuid,
            uuid_bytes,
            flow,
            sni,
            skip_cert_verify,
            alpn,
            udp_enabled,
        })
    }

    fn create_tls_connector(&self) -> Result<TlsConnector> {
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};

        let mut root_store = RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        for cert in certs.certs {
            root_store.add(cert).ok();
        }

        let builder = ClientConfig::builder().with_root_certificates(root_store);

        let mut tls_config = if self.skip_cert_verify {
            let verifier = Arc::new(SkipServerVerification);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        } else {
            builder.with_no_client_auth()
        };

        tls_config.alpn_protocols = self.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        Ok(TlsConnector::from(Arc::new(tls_config)))
    }

    async fn connect_tls(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let addr = format!("{}:{}", self.server, self.port);
        
        // Use protected connection on Android to prevent routing loop
        let stream = crate::socket_protect::connect_protected(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to connect to VLess server {}: {}", addr, e)))?;

        stream.set_nodelay(true).ok();

        let connector = self.create_tls_connector()?;
        let server_name = ServerName::try_from(self.sni.clone())
            .map_err(|_| Error::config(format!("Invalid SNI: {}", self.sni)))?;

        let tls_stream = connector.connect(server_name, stream).await.map_err(|e| {
            Error::network(format!("TLS handshake failed: {}", e))
        })?;

        tracing::debug!(
            "VLess TLS connection established to {} (SNI: {})",
            addr,
            self.sni
        );

        Ok(tls_stream)
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        cmd: VlessCommand,
    ) -> Result<()> {
        let mut buf = Vec::with_capacity(128);

        buf.push(VLESS_VERSION);
        buf.extend_from_slice(&self.uuid_bytes);

        if self.flow.is_vision() {
            let flow_str = self.flow.as_str();
            let flow_addon = build_flow_addon(flow_str);
            buf.push(flow_addon.len() as u8);
            buf.extend_from_slice(&flow_addon);
        } else {
            buf.push(0x00);
        }

        buf.push(cmd as u8);
        buf.extend_from_slice(&target.port().to_be_bytes());
        write_address_to_buf(&mut buf, target)?;

        stream.write_all(&buf).await.map_err(|e| {
            Error::network(format!("Failed to send VLess handshake: {}", e))
        })?;

        stream.flush().await.map_err(|e| {
            Error::network(format!("Failed to flush VLess handshake: {}", e))
        })?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.map_err(|e| {
            Error::network(format!("Failed to read VLess response: {}", e))
        })?;

        if response[0] != VLESS_VERSION {
            return Err(Error::protocol(format!(
                "Invalid VLess response version: expected {}, got {}",
                VLESS_VERSION, response[0]
            )));
        }

        let addons_len = response[1] as usize;
        if addons_len > 0 {
            let mut addons = vec![0u8; addons_len];
            stream.read_exact(&mut addons).await.map_err(|e| {
                Error::network(format!("Failed to read VLess addons: {}", e))
            })?;
        }

        tracing::debug!("VLess handshake completed for target: {}", target);

        Ok(())
    }

    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    pub fn flow(&self) -> VlessFlow {
        self.flow
    }

    pub async fn relay_udp(
        &self,
        _local_socket: &UdpSocket,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this VLess proxy",
            ));
        }

        let mut tls_stream = self.connect_tls().await?;

        self.handshake(&mut tls_stream, target, VlessCommand::Udp)
            .await?;

        let udp_packet = build_udp_packet(target, data)?;
        tls_stream.write_all(&udp_packet).await.map_err(|e| {
            Error::network(format!("Failed to send UDP packet: {}", e))
        })?;
        tls_stream.flush().await.ok();

        tracing::debug!(
            "VLess UDP: sent {} bytes to {} via {}:{}",
            data.len(),
            target,
            self.server,
            self.port
        );

        let timeout = std::time::Duration::from_secs(30);
        let response = tokio::time::timeout(timeout, read_udp_packet(&mut tls_stream))
            .await
            .map_err(|_| Error::network("UDP receive timeout"))?
            .map_err(|e| Error::network(format!("Failed to receive UDP response: {}", e)))?;

        tracing::debug!("VLess UDP: received {} bytes response", response.len());

        Ok(response)
    }
}

#[async_trait::async_trait]
impl OutboundProxy for VlessOutbound {
    async fn connect(&self) -> Result<()> {
        let _tls_stream = self.connect_tls().await?;
        tracing::info!(
            "VLess outbound '{}' can reach {}:{}",
            self.config.tag,
            self.server,
            self.port
        );
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
    
    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }
    
    async fn relay_udp_packet(
        &self,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config("UDP relay is not enabled for this VLESS proxy"));
        }
        // Create a dummy socket for the relay_udp call
        let dummy_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;
        self.relay_udp(&dummy_socket, target, data).await
    }

    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;

        let url = url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() { "/" } else { url.path() };

        let start = Instant::now();

        let mut tls_stream = tokio::time::timeout(timeout, self.connect_tls())
            .await
            .map_err(|_| Error::network("Connection timeout"))?
            .map_err(|e| Error::network(format!("TLS connection failed: {}", e)))?;

        let target = TargetAddr::Domain(host.clone(), url_port);
        self.handshake(&mut tls_stream, &target, VlessCommand::Tcp)
            .await?;

        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
            path, host, crate::USER_AGENT
        );

        tls_stream
            .write_all(http_request.as_bytes())
            .await
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {}", e)))?;

        let result = tokio::time::timeout(timeout, async {
            let mut response = vec![0u8; 1024];
            let n = tls_stream
                .read(&mut response)
                .await
                .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?;

            if n == 0 {
                return Err(Error::network("Empty response"));
            }

            let response_str = String::from_utf8_lossy(&response[..n]);
            if response_str.starts_with("HTTP/") {
                Ok(())
            } else {
                Err(Error::network("Invalid HTTP response"))
            }
        })
        .await;

        match result {
            Ok(Ok(())) => {
                let elapsed = start.elapsed();
                tracing::info!("VLess latency test success: {}ms", elapsed.as_millis());
                Ok(elapsed)
            }
            Ok(Err(e)) => {
                tracing::warn!("VLess latency test failed: {}", e);
                Err(e)
            }
            Err(_) => {
                tracing::warn!("VLess latency test timeout");
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
        let mut tls_stream = self.connect_tls().await?;

        self.handshake(&mut tls_stream, &target, VlessCommand::Tcp)
            .await?;

        tracing::debug!(
            "VLess: relaying TCP to {} via {}:{}",
            target,
            self.server,
            self.port
        );

        let tracker = global_tracker();
        let (mut ri, mut wi) = tokio::io::split(inbound);
        let (mut ro, mut wo) = tokio::io::split(tls_stream);

        let conn_upload = connection.clone();
        let conn_download = connection.clone();

        let client_to_remote = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match ri.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if is_vless_connection_closed(&e) => {
                        tracing::debug!("VLess: client closed connection");
                        break;
                    }
                    Err(e) => return Err(Error::network(format!("Failed to read from inbound: {}", e))),
                };
                
                if let Err(e) = wo.write_all(&buf[..n]).await {
                    if is_vless_connection_closed(&e) {
                        tracing::debug!("VLess: server closed connection");
                        break;
                    }
                    return Err(Error::network(format!("Failed to write to VLess: {}", e)));
                }

                tracker.add_global_upload(n as u64);
                if let Some(ref conn) = conn_upload {
                    conn.add_upload(n as u64);
                }
            }
            wo.shutdown().await.ok();
            Ok::<(), Error>(())
        };

        let remote_to_client = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match ro.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if is_vless_connection_closed(&e) => {
                        tracing::debug!("VLess: server closed connection");
                        break;
                    }
                    Err(e) => return Err(Error::network(format!("Failed to read from VLess: {}", e))),
                };
                
                if let Err(e) = wi.write_all(&buf[..n]).await {
                    if is_vless_connection_closed(&e) {
                        tracing::debug!("VLess: client closed connection");
                        break;
                    }
                    return Err(Error::network(format!("Failed to write to inbound: {}", e)));
                }

                tracker.add_global_download(n as u64);
                if let Some(ref conn) = conn_download {
                    conn.add_download(n as u64);
                }
            }
            wi.shutdown().await.ok();
            Ok::<(), Error>(())
        };

        // Run both directions concurrently
        let (upload_result, download_result) = tokio::join!(client_to_remote, remote_to_client);

        // Handle results - connection close is normal
        match (upload_result, download_result) {
            (Ok(_), Ok(_)) => Ok(()),
            (Ok(_), Err(e)) | (Err(e), Ok(_)) => {
                tracing::debug!("VLess relay partial error: {}", e);
                Ok(())
            }
            (Err(e1), Err(e2)) => {
                tracing::debug!("VLess relay errors: {} / {}", e1, e2);
                Ok(())
            }
        }
    }
}

/// Check if an error indicates a normal connection close for VLess
fn is_vless_connection_closed(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
    )
}

fn write_address_to_buf(buf: &mut Vec<u8>, target: &TargetAddr) -> Result<()> {
    match target {
        TargetAddr::Domain(domain, _) => {
            buf.push(VlessAddressType::Domain as u8);
            if domain.len() > 255 {
                return Err(Error::protocol("Domain name too long"));
            }
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => {
                buf.push(VlessAddressType::Ipv4 as u8);
                buf.extend_from_slice(&v4.ip().octets());
            }
            std::net::SocketAddr::V6(v6) => {
                buf.push(VlessAddressType::Ipv6 as u8);
                buf.extend_from_slice(&v6.ip().octets());
            }
        },
    }
    Ok(())
}

fn build_flow_addon(flow: &str) -> Vec<u8> {
    if flow.is_empty() {
        return Vec::new();
    }

    let mut addon = Vec::new();
    addon.push(0x0a);
    addon.push(flow.len() as u8);
    addon.extend_from_slice(flow.as_bytes());
    addon
}

fn build_udp_packet(target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(data.len() + 64);

    write_address_to_buf(&mut packet, target)?;
    packet.extend_from_slice(&target.port().to_be_bytes());

    let length = data.len() as u16;
    packet.extend_from_slice(&length.to_be_bytes());

    packet.extend_from_slice(data);

    Ok(packet)
}

async fn read_udp_packet<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let atype = stream.read_u8().await.map_err(|e| {
        Error::network(format!("Failed to read address type: {}", e))
    })?;

    match atype {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await.map_err(|e| {
                Error::network(format!("Failed to read IPv4 address: {}", e))
            })?;
        }
        0x02 => {
            let len = stream.read_u8().await.map_err(|e| {
                Error::network(format!("Failed to read domain length: {}", e))
            })? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await.map_err(|e| {
                Error::network(format!("Failed to read domain: {}", e))
            })?;
        }
        0x03 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await.map_err(|e| {
                Error::network(format!("Failed to read IPv6 address: {}", e))
            })?;
        }
        _ => {
            return Err(Error::protocol(format!("Unknown address type: {}", atype)));
        }
    }

    let _port = stream.read_u16().await.map_err(|e| {
        Error::network(format!("Failed to read port: {}", e))
    })?;

    let length = stream.read_u16().await.map_err(|e| {
        Error::network(format!("Failed to read length: {}", e))
    })? as usize;

    let mut data = vec![0u8; length];
    stream.read_exact(&mut data).await.map_err(|e| {
        Error::network(format!("Failed to read UDP data: {}", e))
    })?;

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_command_from_u8() {
        assert_eq!(VlessCommand::from_u8(0x01), Some(VlessCommand::Tcp));
        assert_eq!(VlessCommand::from_u8(0x02), Some(VlessCommand::Udp));
        assert_eq!(VlessCommand::from_u8(0x03), Some(VlessCommand::Mux));
        assert_eq!(VlessCommand::from_u8(0x00), None);
        assert_eq!(VlessCommand::from_u8(0xFF), None);
    }

    #[test]
    fn test_vless_flow_from_str() {
        assert_eq!(VlessFlow::from_str("xtls-rprx-vision"), VlessFlow::XtlsRprxVision);
        assert_eq!(VlessFlow::from_str("vision"), VlessFlow::XtlsRprxVision);
        assert_eq!(VlessFlow::from_str("XTLS-RPRX-VISION"), VlessFlow::XtlsRprxVision);
        assert_eq!(VlessFlow::from_str("xtls-rprx-vision-udp443"), VlessFlow::XtlsRprxVisionUdp443);
        assert_eq!(VlessFlow::from_str(""), VlessFlow::None);
        assert_eq!(VlessFlow::from_str("unknown"), VlessFlow::None);
    }

    #[test]
    fn test_vless_flow_is_vision() {
        assert!(!VlessFlow::None.is_vision());
        assert!(VlessFlow::XtlsRprxVision.is_vision());
        assert!(VlessFlow::XtlsRprxVisionUdp443.is_vision());
    }

    #[test]
    fn test_write_address_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        write_address_to_buf(&mut buf, &target).unwrap();

        assert_eq!(buf[0], VlessAddressType::Domain as u8);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
    }

    #[test]
    fn test_write_address_ipv4() {
        let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            8080,
        ));
        let target = TargetAddr::Ip(addr);
        let mut buf = Vec::new();
        write_address_to_buf(&mut buf, &target).unwrap();

        assert_eq!(buf[0], VlessAddressType::Ipv4 as u8);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_write_address_ipv6() {
        let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            443,
            0,
            0,
        ));
        let target = TargetAddr::Ip(addr);
        let mut buf = Vec::new();
        write_address_to_buf(&mut buf, &target).unwrap();

        assert_eq!(buf[0], VlessAddressType::Ipv6 as u8);
        assert_eq!(buf.len(), 1 + 16);
    }

    #[test]
    fn test_build_flow_addon() {
        let addon = build_flow_addon("xtls-rprx-vision");
        assert_eq!(addon[0], 0x0a);
        assert_eq!(addon[1], 16);
        assert_eq!(&addon[2..], b"xtls-rprx-vision");

        let empty_addon = build_flow_addon("");
        assert!(empty_addon.is_empty());
    }

    #[test]
    fn test_build_udp_packet() {
        let target = TargetAddr::Domain("test.com".to_string(), 53);
        let data = b"hello";
        let packet = build_udp_packet(&target, data).unwrap();

        assert_eq!(packet[0], VlessAddressType::Domain as u8);
        assert_eq!(packet[1], 8);
        assert_eq!(&packet[2..10], b"test.com");

        let port_offset = 10;
        let port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        assert_eq!(port, 53);

        let length_offset = port_offset + 2;
        let length = u16::from_be_bytes([packet[length_offset], packet[length_offset + 1]]);
        assert_eq!(length, 5);

        let data_offset = length_offset + 2;
        assert_eq!(&packet[data_offset..], b"hello");
    }

    #[test]
    fn test_vless_outbound_new() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "flow".to_string(),
            serde_yaml::Value::String("xtls-rprx-vision".to_string()),
        );
        options.insert(
            "sni".to_string(),
            serde_yaml::Value::String("custom.sni.com".to_string()),
        );
        options.insert(
            "skip-cert-verify".to_string(),
            serde_yaml::Value::Bool(true),
        );
        options.insert("udp".to_string(), serde_yaml::Value::Bool(true));

        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::config::OutboundType::Vless,
            server: Some("vless.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VlessOutbound::new(config).unwrap();

        assert_eq!(outbound.tag(), "vless-test");
        assert_eq!(outbound.server, "vless.example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.sni, "custom.sni.com");
        assert!(outbound.skip_cert_verify);
        assert!(outbound.is_udp_enabled());
        assert_eq!(outbound.flow(), VlessFlow::XtlsRprxVision);
    }

    #[test]
    fn test_vless_outbound_missing_uuid() {
        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::config::OutboundType::Vless,
            server: Some("vless.example.com".to_string()),
            port: Some(443),
            options: std::collections::HashMap::new(),
        };

        let result = VlessOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vless_outbound_missing_server() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::config::OutboundType::Vless,
            server: None,
            port: Some(443),
            options,
        };

        let result = VlessOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vless_outbound_default_sni() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::config::OutboundType::Vless,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VlessOutbound::new(config).unwrap();
        assert_eq!(outbound.sni, "server.example.com");
    }

    #[test]
    fn test_vless_outbound_server_addr() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::config::OutboundType::Vless,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VlessOutbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "server.example.com");
        assert_eq!(port, 443);
    }
}
