use crate::config::OutboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use crate::tls::SkipServerVerification;
use sha2::{Digest, Sha224};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

const CRLF: &[u8] = b"\r\n";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

impl TrojanCommand {
    #[allow(dead_code)]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(TrojanCommand::Connect),
            0x03 => Some(TrojanCommand::UdpAssociate),
            _ => None,
        }
    }
}

pub struct TrojanOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    password: String,
    password_hash: [u8; 56],
    sni: String,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    udp_enabled: bool,
}

impl TrojanOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for Trojan"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for Trojan"))?;

        let password = config
            .options
            .get("password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        if password.is_empty() {
            return Err(Error::config("Missing password for Trojan"));
        }

        let sni = config
            .options
            .get("sni")
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

        let udp_enabled = config
            .options
            .get("udp")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let password_hash = compute_password_hash(&password);

        Ok(Self {
            config,
            server,
            port,
            password,
            password_hash,
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
        let stream = TcpStream::connect(&addr).await.map_err(|e| {
            Error::network(format!("Failed to connect to Trojan server {}: {}", addr, e))
        })?;

        stream.set_nodelay(true).ok();

        let connector = self.create_tls_connector()?;
        let server_name = ServerName::try_from(self.sni.clone())
            .map_err(|_| Error::config(format!("Invalid SNI: {}", self.sni)))?;

        let tls_stream = connector.connect(server_name, stream).await.map_err(|e| {
            Error::network(format!("TLS handshake failed: {}", e))
        })?;

        tracing::debug!(
            "Trojan TLS connection established to {} (SNI: {})",
            addr,
            self.sni
        );

        Ok(tls_stream)
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        cmd: TrojanCommand,
    ) -> Result<()> {
        let mut buf = Vec::with_capacity(128);

        buf.extend_from_slice(&self.password_hash);
        buf.extend_from_slice(CRLF);
        buf.push(cmd as u8);

        write_address_to_buf(&mut buf, target)?;

        buf.extend_from_slice(CRLF);

        stream.write_all(&buf).await.map_err(|e| {
            Error::network(format!("Failed to send Trojan handshake: {}", e))
        })?;

        stream.flush().await.map_err(|e| {
            Error::network(format!("Failed to flush Trojan handshake: {}", e))
        })?;

        tracing::debug!("Trojan handshake sent for target: {}", target);

        Ok(())
    }

    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    pub async fn relay_udp(
        &self,
        _local_socket: &UdpSocket,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this Trojan proxy",
            ));
        }

        let mut tls_stream = self.connect_tls().await?;

        self.handshake(&mut tls_stream, target, TrojanCommand::UdpAssociate)
            .await?;

        let udp_packet = build_udp_packet(target, data)?;
        tls_stream.write_all(&udp_packet).await.map_err(|e| {
            Error::network(format!("Failed to send UDP packet: {}", e))
        })?;
        tls_stream.flush().await.ok();

        tracing::debug!(
            "Trojan UDP: sent {} bytes to {} via {}:{}",
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

        tracing::debug!("Trojan UDP: received {} bytes response", response.len());

        Ok(response)
    }
}

#[async_trait::async_trait]
impl OutboundProxy for TrojanOutbound {
    async fn connect(&self) -> Result<()> {
        let _tls_stream = self.connect_tls().await?;
        tracing::info!(
            "Trojan outbound '{}' can reach {}:{}",
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
        self.handshake(&mut tls_stream, &target, TrojanCommand::Connect)
            .await?;

        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: VeloGuard/1.0\r\n\r\n",
            path, host
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
                tracing::info!("Trojan latency test success: {}ms", elapsed.as_millis());
                Ok(elapsed)
            }
            Ok(Err(e)) => {
                tracing::warn!("Trojan latency test failed: {}", e);
                Err(e)
            }
            Err(_) => {
                tracing::warn!("Trojan latency test timeout");
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

        self.handshake(&mut tls_stream, &target, TrojanCommand::Connect)
            .await?;

        tracing::debug!(
            "Trojan: relaying TCP to {} via {}:{}",
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
                let n = ri.read(&mut buf).await.map_err(|e| {
                    Error::network(format!("Failed to read from inbound: {}", e))
                })?;
                if n == 0 {
                    break;
                }
                wo.write_all(&buf[..n]).await.map_err(|e| {
                    Error::network(format!("Failed to write to Trojan: {}", e))
                })?;

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
                let n = ro.read(&mut buf).await.map_err(|e| {
                    Error::network(format!("Failed to read from Trojan: {}", e))
                })?;
                if n == 0 {
                    break;
                }
                wi.write_all(&buf[..n]).await.map_err(|e| {
                    Error::network(format!("Failed to write to inbound: {}", e))
                })?;

                tracker.add_global_download(n as u64);
                if let Some(ref conn) = conn_download {
                    conn.add_download(n as u64);
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
                if err_str.contains("connection")
                    || err_str.contains("reset")
                    || err_str.contains("broken")
                {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
}

fn compute_password_hash(password: &str) -> [u8; 56] {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hex_str = hex::encode(result);
    let mut hash = [0u8; 56];
    hash.copy_from_slice(hex_str.as_bytes());
    hash
}

fn write_address_to_buf(buf: &mut Vec<u8>, target: &TargetAddr) -> Result<()> {
    match target {
        TargetAddr::Domain(domain, port) => {
            buf.push(0x03);
            if domain.len() > 255 {
                return Err(Error::protocol("Domain name too long"));
            }
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                buf.push(0x04);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
    }
    Ok(())
}

fn build_udp_packet(target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(data.len() + 64);

    write_address_to_buf(&mut packet, target)?;

    let length = data.len() as u16;
    packet.extend_from_slice(&length.to_be_bytes());

    packet.extend_from_slice(CRLF);

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
            let _port = stream.read_u16().await.map_err(|e| {
                Error::network(format!("Failed to read port: {}", e))
            })?;
        }
        0x03 => {
            let len = stream.read_u8().await.map_err(|e| {
                Error::network(format!("Failed to read domain length: {}", e))
            })? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await.map_err(|e| {
                Error::network(format!("Failed to read domain: {}", e))
            })?;
            let _port = stream.read_u16().await.map_err(|e| {
                Error::network(format!("Failed to read port: {}", e))
            })?;
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await.map_err(|e| {
                Error::network(format!("Failed to read IPv6 address: {}", e))
            })?;
            let _port = stream.read_u16().await.map_err(|e| {
                Error::network(format!("Failed to read port: {}", e))
            })?;
        }
        _ => {
            return Err(Error::protocol(format!("Unknown address type: {}", atype)));
        }
    }

    let length = stream.read_u16().await.map_err(|e| {
        Error::network(format!("Failed to read length: {}", e))
    })? as usize;

    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await.map_err(|e| {
        Error::network(format!("Failed to read CRLF: {}", e))
    })?;

    if crlf != CRLF {
        return Err(Error::protocol("Invalid CRLF in UDP packet"));
    }

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
    fn test_password_hash() {
        let password = "test_password";
        let hash = compute_password_hash(password);

        assert_eq!(hash.len(), 56);

        let hash_str = std::str::from_utf8(&hash).unwrap();
        assert!(hash_str.chars().all(|c| c.is_ascii_hexdigit()));

        let hash2 = compute_password_hash(password);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_password_hash_known_value() {
        let password = "password123";
        let hash = compute_password_hash(password);
        let hash_str = std::str::from_utf8(&hash).unwrap();

        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let expected = hex::encode(hasher.finalize());

        assert_eq!(hash_str, expected);
    }

    #[test]
    fn test_trojan_command_from_u8() {
        assert_eq!(TrojanCommand::from_u8(0x01), Some(TrojanCommand::Connect));
        assert_eq!(
            TrojanCommand::from_u8(0x03),
            Some(TrojanCommand::UdpAssociate)
        );
        assert_eq!(TrojanCommand::from_u8(0x00), None);
        assert_eq!(TrojanCommand::from_u8(0x02), None);
        assert_eq!(TrojanCommand::from_u8(0xFF), None);
    }

    #[test]
    fn test_write_address_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        write_address_to_buf(&mut buf, &target).unwrap();

        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &[0x01, 0xBB]);
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

        assert_eq!(buf[0], 0x01);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(&buf[5..7], &[0x1F, 0x90]);
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

        assert_eq!(buf[0], 0x04);
        assert_eq!(buf.len(), 1 + 16 + 2);
    }

    #[test]
    fn test_build_udp_packet() {
        let target = TargetAddr::Domain("test.com".to_string(), 53);
        let data = b"hello";
        let packet = build_udp_packet(&target, data).unwrap();

        assert_eq!(packet[0], 0x03);
        assert_eq!(packet[1], 8);
        assert_eq!(&packet[2..10], b"test.com");
        assert_eq!(&packet[10..12], &53u16.to_be_bytes());

        let length = u16::from_be_bytes([packet[12], packet[13]]);
        assert_eq!(length, 5);

        assert_eq!(&packet[14..16], CRLF);

        assert_eq!(&packet[16..], b"hello");
    }

    #[test]
    fn test_trojan_outbound_new() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "password".to_string(),
            serde_yaml::Value::String("test_pass".to_string()),
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
            tag: "trojan-test".to_string(),
            outbound_type: crate::config::OutboundType::Trojan,
            server: Some("trojan.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = TrojanOutbound::new(config).unwrap();

        assert_eq!(outbound.tag(), "trojan-test");
        assert_eq!(outbound.server, "trojan.example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.sni, "custom.sni.com");
        assert!(outbound.skip_cert_verify);
        assert!(outbound.is_udp_enabled());
    }

    #[test]
    fn test_trojan_outbound_missing_password() {
        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::config::OutboundType::Trojan,
            server: Some("trojan.example.com".to_string()),
            port: Some(443),
            options: std::collections::HashMap::new(),
        };

        let result = TrojanOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_trojan_outbound_missing_server() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "password".to_string(),
            serde_yaml::Value::String("test".to_string()),
        );

        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::config::OutboundType::Trojan,
            server: None,
            port: Some(443),
            options,
        };

        let result = TrojanOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_trojan_outbound_default_sni() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "password".to_string(),
            serde_yaml::Value::String("test".to_string()),
        );

        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::config::OutboundType::Trojan,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = TrojanOutbound::new(config).unwrap();
        assert_eq!(outbound.sni, "server.example.com");
    }

    #[test]
    fn test_trojan_outbound_server_addr() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "password".to_string(),
            serde_yaml::Value::String("test".to_string()),
        );

        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::config::OutboundType::Trojan,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = TrojanOutbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "server.example.com");
        assert_eq!(port, 443);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_domain() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{0,62}(\\.[a-z][a-z0-9]{0,62}){0,3}"
            .prop_filter("domain must be <= 255 bytes", |s| s.len() <= 255)
    }

    fn arb_port() -> impl Strategy<Value = u16> {
        1u16..=65535u16
    }

    fn arb_ipv4() -> impl Strategy<Value = std::net::Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| std::net::Ipv4Addr::new(a, b, c, d))
    }

    fn arb_ipv6() -> impl Strategy<Value = std::net::Ipv6Addr> {
        (
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
        )
            .prop_map(|(a, b, c, d, e, f, g, h)| std::net::Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn arb_target_addr() -> impl Strategy<Value = TargetAddr> {
        prop_oneof![
            (arb_domain(), arb_port()).prop_map(|(d, p)| TargetAddr::Domain(d, p)),
            (arb_ipv4(), arb_port()).prop_map(|(ip, p)| TargetAddr::Ip(std::net::SocketAddr::V4(
                std::net::SocketAddrV4::new(ip, p)
            ))),
            (arb_ipv6(), arb_port()).prop_map(|(ip, p)| TargetAddr::Ip(std::net::SocketAddr::V6(
                std::net::SocketAddrV6::new(ip, p, 0, 0)
            ))),
        ]
    }

    fn arb_password() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9!@#$%^&*]{1,64}"
    }

    fn arb_udp_data() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..1024)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_password_hash_deterministic(password in arb_password()) {
            let hash1 = compute_password_hash(&password);
            let hash2 = compute_password_hash(&password);
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_password_hash_length(password in arb_password()) {
            let hash = compute_password_hash(&password);
            prop_assert_eq!(hash.len(), 56);
        }

        #[test]
        fn prop_password_hash_hex_chars(password in arb_password()) {
            let hash = compute_password_hash(&password);
            let hash_str = std::str::from_utf8(&hash).unwrap();
            prop_assert!(hash_str.chars().all(|c| c.is_ascii_hexdigit()));
        }

        #[test]
        fn prop_address_encoding_domain(domain in arb_domain(), port in arb_port()) {
            let target = TargetAddr::Domain(domain.clone(), port);
            let mut buf = Vec::new();
            write_address_to_buf(&mut buf, &target).unwrap();

            prop_assert_eq!(buf[0], 0x03);
            prop_assert_eq!(buf[1] as usize, domain.len());
            prop_assert_eq!(&buf[2..2 + domain.len()], domain.as_bytes());

            let port_bytes = &buf[2 + domain.len()..];
            let decoded_port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
            prop_assert_eq!(decoded_port, port);
        }

        #[test]
        fn prop_address_encoding_ipv4(ip in arb_ipv4(), port in arb_port()) {
            let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));
            let target = TargetAddr::Ip(addr);
            let mut buf = Vec::new();
            write_address_to_buf(&mut buf, &target).unwrap();

            prop_assert_eq!(buf[0], 0x01);
            prop_assert_eq!(&buf[1..5], &ip.octets());

            let decoded_port = u16::from_be_bytes([buf[5], buf[6]]);
            prop_assert_eq!(decoded_port, port);
        }

        #[test]
        fn prop_address_encoding_ipv6(ip in arb_ipv6(), port in arb_port()) {
            let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0));
            let target = TargetAddr::Ip(addr);
            let mut buf = Vec::new();
            write_address_to_buf(&mut buf, &target).unwrap();

            prop_assert_eq!(buf[0], 0x04);
            prop_assert_eq!(&buf[1..17], &ip.octets());

            let decoded_port = u16::from_be_bytes([buf[17], buf[18]]);
            prop_assert_eq!(decoded_port, port);
        }

        #[test]
        fn prop_udp_packet_structure(target in arb_target_addr(), data in arb_udp_data()) {
            let packet = build_udp_packet(&target, &data).unwrap();

            let addr_len = match &target {
                TargetAddr::Domain(d, _) => 1 + 1 + d.len() + 2,
                TargetAddr::Ip(std::net::SocketAddr::V4(_)) => 1 + 4 + 2,
                TargetAddr::Ip(std::net::SocketAddr::V6(_)) => 1 + 16 + 2,
            };

            let expected_len = addr_len + 2 + 2 + data.len();
            prop_assert_eq!(packet.len(), expected_len);

            let length_offset = addr_len;
            let length = u16::from_be_bytes([packet[length_offset], packet[length_offset + 1]]);
            prop_assert_eq!(length as usize, data.len());

            let crlf_offset = length_offset + 2;
            prop_assert_eq!(&packet[crlf_offset..crlf_offset + 2], CRLF);

            let data_offset = crlf_offset + 2;
            prop_assert_eq!(&packet[data_offset..], &data[..]);
        }

        #[test]
        fn prop_different_passwords_different_hashes(
            password1 in arb_password(),
            password2 in arb_password()
        ) {
            prop_assume!(password1 != password2);
            let hash1 = compute_password_hash(&password1);
            let hash2 = compute_password_hash(&password2);
            prop_assert_ne!(hash1, hash2);
        }
    }
}
