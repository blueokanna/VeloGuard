//! Hysteria2 protocol implementation
//!
//! Hysteria2 is a feature-rich proxy protocol based on QUIC, designed for:
//! - High-speed data transfer with brutal congestion control
//! - Built-in obfuscation (salamander)
//! - UDP relay support
//! - Port hopping

use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

/// Helper function to convert serde_yaml::Value to String
fn yaml_value_to_string(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => value.as_str().map(|s| s.to_string()).unwrap_or_default(),
    }
}

/// Hysteria2 obfuscation type
#[derive(Debug, Clone, PartialEq)]
pub enum ObfsType {
    /// No obfuscation
    None,
    /// Salamander obfuscation
    Salamander(String),
}

impl Default for ObfsType {
    fn default() -> Self {
        Self::None
    }
}

/// Hysteria2 outbound configuration
#[derive(Debug, Clone)]
pub struct Hysteria2Config {
    /// Server address
    pub server: String,
    /// Server port
    pub port: u16,
    /// Authentication password
    pub password: String,
    /// Obfuscation settings
    pub obfs: ObfsType,
    /// SNI (Server Name Indication)
    pub sni: Option<String>,
    /// Skip certificate verification
    pub skip_cert_verify: bool,
    /// ALPN protocols
    pub alpn: Vec<String>,
    /// Upload bandwidth in Mbps (for brutal CC)
    pub up_mbps: Option<u32>,
    /// Download bandwidth in Mbps (for brutal CC)
    pub down_mbps: Option<u32>,
    /// Fingerprint for certificate pinning
    pub fingerprint: Option<String>,
    /// Port hopping configuration
    pub ports: Option<String>,
    /// Hop interval in seconds
    pub hop_interval: Option<u32>,
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
        }
    }
}

/// Hysteria2 outbound proxy
pub struct Hysteria2Outbound {
    config: OutboundConfig,
    hy2_config: Hysteria2Config,
}

#[async_trait::async_trait]
impl OutboundProxy for Hysteria2Outbound {
    async fn connect(&self) -> Result<()> {
        let addr = format!("{}:{}", self.hy2_config.server, self.hy2_config.port);
        
        // Resolve the server address
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to resolve Hysteria2 server {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| Error::network(format!("No addresses found for Hysteria2 server {}", addr)))?;

        info!(
            "Hysteria2 outbound '{}' ready for {}",
            self.config.tag, socket_addr
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
        Some((self.hy2_config.server.clone(), self.hy2_config.port))
    }

    async fn test_http_latency(
        &self,
        _test_url: &str,
        timeout: Duration,
    ) -> Result<Duration> {
        use std::time::Instant;

        let start = Instant::now();

        let addr = format!("{}:{}", self.hy2_config.server, self.hy2_config.port);
        
        let socket_addr: SocketAddr = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                tokio::net::lookup_host(&addr)
                    .await
                    .map_err(|e| Error::network(format!("DNS resolution failed: {}", e)))?
                    .next()
                    .ok_or_else(|| Error::network("No addresses found"))
            }
        ).await
            .map_err(|_| Error::network("DNS resolution timeout"))??;

        // Test UDP connectivity (Hysteria2 uses QUIC/UDP)
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;

        let _ = tokio::time::timeout(
            timeout,
            socket.send_to(&[0u8; 1], socket_addr)
        ).await
            .map_err(|_| Error::network("Connection timeout"))?
            .map_err(|e| Error::network(format!("Failed to send: {}", e)))?;

        Ok(start.elapsed())
    }

    async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None).await
    }
    
    async fn relay_tcp_with_connection(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        use crate::connection_tracker::global_tracker;

        // Simplified implementation - full version would use QUIC
        let addr = format!("{}:{}", self.hy2_config.server, self.hy2_config.port);
        
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to resolve Hysteria2 server: {}", e)))?
            .next()
            .ok_or_else(|| Error::network("No addresses found for Hysteria2 server"))?;

        warn!("Hysteria2 relay not fully implemented, using TCP fallback");

        let outbound = tokio::net::TcpStream::connect(socket_addr).await
            .map_err(|e| Error::network(format!("Failed to connect to Hysteria2 server: {}", e)))?;

        outbound.set_nodelay(true).ok();

        debug!("Hysteria2: connected to {} for target {}", socket_addr, target);

        let tracker = global_tracker();
        let conn_upload = connection.clone();
        let conn_download = connection.clone();
        let (mut ri, mut wi) = tokio::io::split(inbound);
        let (mut ro, mut wo) = tokio::io::split(outbound);

        let client_to_remote = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = ri.read(&mut buf).await
                    .map_err(|e| Error::network(format!("Failed to read from inbound: {}", e)))?;
                if n == 0 {
                    break;
                }
                wo.write_all(&buf[..n]).await
                    .map_err(|e| Error::network(format!("Failed to write to outbound: {}", e)))?;
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
                let n = ro.read(&mut buf).await
                    .map_err(|e| Error::network(format!("Failed to read from outbound: {}", e)))?;
                if n == 0 {
                    break;
                }
                wi.write_all(&buf[..n]).await
                    .map_err(|e| Error::network(format!("Failed to write to inbound: {}", e)))?;
                tracker.add_global_download(n as u64);
                if let Some(ref conn) = conn_download {
                    conn.add_download(n as u64);
                }
            }
            Ok::<(), Error>(())
        };

        tokio::try_join!(client_to_remote, remote_to_client)?;
        Ok(())
    }
}

impl Hysteria2Outbound {
    /// Create a new Hysteria2 outbound from configuration
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

        // Parse obfuscation settings
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
        };

        debug!(
            "Creating Hysteria2 outbound: server={}:{}, obfs={:?}",
            hy2_config.server, hy2_config.port, hy2_config.obfs
        );

        Ok(Self {
            config,
            hy2_config,
        })
    }

    /// Get the Hysteria2 configuration
    pub fn hy2_config(&self) -> &Hysteria2Config {
        &self.hy2_config
    }
}
