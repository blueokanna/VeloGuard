use flutter_rust_bridge::frb;
use serde::{Deserialize, Serialize};

/// FFI-safe configuration structure
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VeloGuardConfig {
    /// General settings
    pub general: GeneralConfig,

    /// DNS configuration
    pub dns: DnsConfig,

    /// Inbound configurations
    pub inbounds: Vec<InboundConfig>,

    /// Outbound configurations
    pub outbounds: Vec<OutboundConfig>,

    /// Routing rules
    pub rules: Vec<RuleConfig>,
}

/// General configuration for FFI
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub port: u16,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub authentication: Option<Vec<AuthenticationConfig>>,
    pub allow_lan: bool,
    pub bind_address: String,
    pub mode: String,
    pub log_level: String,
    pub ipv6: bool,
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub secret: Option<String>,
}

/// DNS configuration for FFI
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enable: bool,
    pub listen: String,
    pub nameservers: Vec<String>,
    pub fallback: Vec<String>,
    pub enhanced_mode: String,
}

/// Inbound configuration for FFI
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    pub inbound_type: String,
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub options: String, // JSON string for complex options
}

/// Outbound configuration for FFI
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub outbound_type: String,
    pub tag: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub options: String, // JSON string for complex options
}

/// Routing rule configuration for FFI
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub rule_type: String,
    pub payload: String,
    pub outbound: String,
    pub process_name: Option<String>,
}

/// Authentication configuration for FFI
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationConfig {
    pub username: String,
    pub password: String,
}

/// Proxy status information
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub inbound_count: u32,
    pub outbound_count: u32,
    pub connection_count: u32,
    pub memory_usage: u64,
    pub uptime: u64,
}

/// Traffic statistics
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub upload: u64,
    pub download: u64,
    pub upload_speed: u64,
    pub download_speed: u64,
}

/// Connection information
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub host: String,
    pub destination: String,
    pub upload: u64,
    pub download: u64,
    pub start_time: u64,
    pub rule: String,
    pub chains: Vec<String>,
}

/// System information
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub platform: String,
    pub version: String,
    pub memory_total: u64,
    pub memory_used: u64,
    pub cpu_cores: u32,
    pub cpu_threads: u32,
    pub cpu_name: String,
    pub cpu_usage: f64,
}

/// Latency test result
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyTestResult {
    pub proxy_name: String,
    pub latency_ms: Option<u32>,
    pub success: bool,
    pub error: Option<String>,
}

/// Active connection for tracking
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveConnection {
    pub id: String,
    pub inbound_tag: String,
    pub outbound_tag: String,
    pub host: String,
    pub destination_ip: Option<String>,
    pub destination_port: u16,
    pub protocol: String,
    pub network: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub start_time: u64,
    pub rule: String,
    pub rule_payload: String,
    pub process_name: Option<String>,
}

/// TUN mode status
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunStatus {
    pub enabled: bool,
    pub interface_name: Option<String>,
    pub mtu: Option<u32>,
    pub error: Option<String>,
}


// ============== QUIC Proxy Types ==============

/// QUIC proxy configuration for FFI
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicProxyConfig {
    /// Server address (host:port)
    pub server: String,
    /// Server port
    pub port: u16,
    /// Password for authentication
    pub password: String,
    /// Cipher type (aes-256-gcm, chacha20-poly1305, etc.)
    pub cipher: String,
    /// SNI server name for camouflage
    pub server_name: Option<String>,
    /// ALPN protocols
    pub alpn: Option<Vec<String>>,
    /// Skip certificate verification
    pub skip_cert_verify: bool,
    /// Enable 0-RTT
    pub zero_rtt: bool,
    /// Enable UDP relay
    pub udp_relay: bool,
    /// Congestion control (cubic, bbr, newreno)
    pub congestion_control: Option<String>,
    /// Idle timeout in seconds
    pub idle_timeout: Option<u32>,
}

/// QUIC connection status
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConnectionStatus {
    pub connected: bool,
    pub server: String,
    pub rtt_ms: Option<u32>,
    pub zero_rtt_accepted: bool,
    pub streams_count: u32,
    pub error: Option<String>,
}
