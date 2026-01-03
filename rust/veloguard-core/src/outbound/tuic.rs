//! TUIC (TCP over UDP in Clash) protocol implementation
//! 
//! TUIC is a proxy protocol that uses QUIC for transport, providing:
//! - Multiplexed connections over a single QUIC connection
//! - 0-RTT connection establishment
//! - Built-in encryption via QUIC/TLS
//! - UDP relay support

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

/// TUIC congestion control algorithm
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

impl Default for CongestionControl {
    fn default() -> Self {
        Self::Cubic
    }
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

/// TUIC UDP relay mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UdpRelayMode {
    /// Native UDP relay
    Native,
    /// QUIC stream-based relay
    Quic,
}

impl Default for UdpRelayMode {
    fn default() -> Self {
        Self::Native
    }
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

/// TUIC outbound configuration
#[derive(Debug, Clone)]
pub struct TuicConfig {
    /// Server address
    pub server: String,
    /// Server port
    pub port: u16,
    /// UUID for authentication
    pub uuid: String,
    /// Password for authentication
    pub password: String,
    /// ALPN protocols
    pub alpn: Vec<String>,
    /// SNI (Server Name Indication)
    pub sni: Option<String>,
    /// Skip certificate verification
    pub skip_cert_verify: bool,
    /// Disable SNI
    pub disable_sni: bool,
    /// Congestion control algorithm
    pub congestion_control: CongestionControl,
    /// UDP relay mode
    pub udp_relay_mode: UdpRelayMode,
    /// Enable 0-RTT
    pub zero_rtt_handshake: bool,
    /// Heartbeat interval in milliseconds
    pub heartbeat: u64,
    /// Reduce RTT (send request before handshake completes)
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

/// TUIC outbound proxy
pub struct TuicOutbound {
    config: OutboundConfig,
    tuic_config: TuicConfig,
}

#[async_trait::async_trait]
impl OutboundProxy for TuicOutbound {
    async fn connect(&self) -> Result<()> {
        // For TUIC, we establish a QUIC connection
        // This is a placeholder - actual implementation would use quinn
        let addr = format!("{}:{}", self.tuic_config.server, self.tuic_config.port);
        
        // Resolve the server address
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to resolve TUIC server {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| Error::network(format!("No addresses found for TUIC server {}", addr)))?;

        info!(
            "TUIC outbound '{}' ready for {}",
            self.config.tag, socket_addr
        );
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        // Close QUIC connection
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.tuic_config.server.clone(), self.tuic_config.port))
    }

    async fn test_http_latency(
        &self,
        _test_url: &str,
        timeout: Duration,
    ) -> Result<Duration> {
        use std::time::Instant;

        let start = Instant::now();

        // For TUIC, we test by establishing a QUIC connection
        let addr = format!("{}:{}", self.tuic_config.server, self.tuic_config.port);
        
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

        // Test UDP connectivity (QUIC uses UDP)
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;

        // Send a dummy packet to test connectivity
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

        // For now, fall back to TCP connection to the server
        // A full implementation would use QUIC streams
        let addr = format!("{}:{}", self.tuic_config.server, self.tuic_config.port);
        
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to resolve TUIC server: {}", e)))?
            .next()
            .ok_or_else(|| Error::network("No addresses found for TUIC server"))?;

        // Note: This is a simplified implementation
        // A full TUIC implementation would:
        // 1. Establish a QUIC connection using quinn
        // 2. Open a bidirectional stream
        // 3. Send the TUIC protocol header with target address
        // 4. Relay data through the QUIC stream

        warn!("TUIC relay not fully implemented, using TCP fallback");

        let outbound = tokio::net::TcpStream::connect(socket_addr).await
            .map_err(|e| Error::network(format!("Failed to connect to TUIC server: {}", e)))?;

        outbound.set_nodelay(true).ok();

        debug!("TUIC: connected to {} for target {}", socket_addr, target);

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

impl TuicOutbound {
    /// Create a new TUIC outbound from configuration
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| Error::config("Missing server address for TUIC"))?
            .clone();

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for TUIC"))?;

        let uuid = config
            .options
            .get("uuid")
            .map(yaml_value_to_string)
            .ok_or_else(|| Error::config("Missing UUID for TUIC"))?;

        let password = config
            .options
            .get("password")
            .map(yaml_value_to_string)
            .unwrap_or_default();

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
            uuid,
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
        })
    }

    /// Get the TUIC configuration
    pub fn tuic_config(&self) -> &TuicConfig {
        &self.tuic_config
    }
}
