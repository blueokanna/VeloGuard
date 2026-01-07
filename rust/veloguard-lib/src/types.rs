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
    pub tcp_concurrent: bool,
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

// ============== Design Document Compliant DTO Types ==============

/// Traffic statistics DTO (Design Document Compliant)
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStatsDto {
    pub upload: u64,
    pub download: u64,
    pub total_upload: u64,
    pub total_download: u64,
    pub connection_count: u32,
    pub uptime_secs: u64,
}

/// Connection DTO (Design Document Compliant)
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDto {
    pub id: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub dst_domain: Option<String>,
    pub protocol: String,
    pub outbound: String,
    pub upload: u64,
    pub download: u64,
    pub start_time: i64,
    pub rule: Option<String>,
}

/// Proxy info DTO (Design Document Compliant)
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInfoDto {
    pub tag: String,
    pub protocol_type: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub latency_ms: Option<u64>,
    pub alive: bool,
}

/// Proxy group DTO (Design Document Compliant)
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyGroupDto {
    pub tag: String,
    pub group_type: String,
    pub proxies: Vec<String>,
    pub selected: String,
}

/// Proxy latency DTO (Design Document Compliant)
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyLatencyDto {
    pub tag: String,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Rule DTO (Design Document Compliant)
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDto {
    pub rule_type: String,
    pub payload: String,
    pub outbound: String,
    pub matched_count: u64,
}

/// DNS config DTO (Design Document Compliant)
#[frb]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfigDto {
    pub enable: bool,
    pub listen: String,
    pub enhanced_mode: String,
    pub nameservers: Vec<String>,
    pub fallback: Vec<String>,
}


// ============== From Trait Implementations for DTO Types ==============

impl TrafficStatsDto {
    /// Create a new TrafficStatsDto with default values
    pub fn new() -> Self {
        Self {
            upload: 0,
            download: 0,
            total_upload: 0,
            total_download: 0,
            connection_count: 0,
            uptime_secs: 0,
        }
    }

    /// Create from upload/download values
    pub fn from_traffic(upload: u64, download: u64, connection_count: u32, uptime_secs: u64) -> Self {
        Self {
            upload,
            download,
            total_upload: upload,
            total_download: download,
            connection_count,
            uptime_secs,
        }
    }
}

impl Default for TrafficStatsDto {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionDto {
    /// Create a new ConnectionDto
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        src_addr: String,
        dst_addr: String,
        dst_domain: Option<String>,
        protocol: String,
        outbound: String,
        upload: u64,
        download: u64,
        start_time: i64,
        rule: Option<String>,
    ) -> Self {
        Self {
            id,
            src_addr,
            dst_addr,
            dst_domain,
            protocol,
            outbound,
            upload,
            download,
            start_time,
            rule,
        }
    }
}

impl ProxyInfoDto {
    /// Create a new ProxyInfoDto
    pub fn new(
        tag: String,
        protocol_type: String,
        server: Option<String>,
        port: Option<u16>,
    ) -> Self {
        Self {
            tag,
            protocol_type,
            server,
            port,
            latency_ms: None,
            alive: true,
        }
    }

    /// Set latency
    pub fn with_latency(mut self, latency_ms: Option<u64>) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    /// Set alive status
    pub fn with_alive(mut self, alive: bool) -> Self {
        self.alive = alive;
        self
    }
}

impl ProxyGroupDto {
    /// Create a new ProxyGroupDto
    pub fn new(
        tag: String,
        group_type: String,
        proxies: Vec<String>,
        selected: String,
    ) -> Self {
        Self {
            tag,
            group_type,
            proxies,
            selected,
        }
    }
}

impl ProxyLatencyDto {
    /// Create a successful latency result
    pub fn success(tag: String, latency_ms: u64) -> Self {
        Self {
            tag,
            latency_ms: Some(latency_ms),
            error: None,
        }
    }

    /// Create a failed latency result
    pub fn failure(tag: String, error: String) -> Self {
        Self {
            tag,
            latency_ms: None,
            error: Some(error),
        }
    }
}

impl RuleDto {
    /// Create a new RuleDto
    pub fn new(
        rule_type: String,
        payload: String,
        outbound: String,
    ) -> Self {
        Self {
            rule_type,
            payload,
            outbound,
            matched_count: 0,
        }
    }

    /// Set matched count
    pub fn with_matched_count(mut self, count: u64) -> Self {
        self.matched_count = count;
        self
    }
}

impl DnsConfigDto {
    /// Create a new DnsConfigDto
    pub fn new(
        enable: bool,
        listen: String,
        enhanced_mode: String,
        nameservers: Vec<String>,
        fallback: Vec<String>,
    ) -> Self {
        Self {
            enable,
            listen,
            enhanced_mode,
            nameservers,
            fallback,
        }
    }
}

impl Default for DnsConfigDto {
    fn default() -> Self {
        Self {
            enable: false,
            listen: "127.0.0.1:53".to_string(),
            enhanced_mode: "normal".to_string(),
            nameservers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            fallback: vec!["8.8.4.4".to_string(), "1.0.0.1".to_string()],
        }
    }
}


// ============== Conversion from veloguard-core types ==============

/// Convert from TrackedConnection to ConnectionDto
impl ConnectionDto {
    /// Create from a TrackedConnection reference
    pub fn from_tracked_connection(conn: &veloguard_core::connection_tracker::TrackedConnection) -> Self {
        Self {
            id: conn.id.clone(),
            src_addr: format!("{}:{}", conn.host, conn.destination_port),
            dst_addr: conn.destination_ip.clone().unwrap_or_default(),
            dst_domain: Some(conn.host.clone()),
            protocol: conn.protocol.clone(),
            outbound: conn.outbound_tag.clone(),
            upload: conn.get_upload(),
            download: conn.get_download(),
            start_time: conn.start_timestamp as i64,
            rule: Some(conn.rule.clone()),
        }
    }
}


/// Convert from OutboundConfig to ProxyInfoDto
impl ProxyInfoDto {
    /// Create from an OutboundConfig reference
    pub fn from_outbound_config(config: &veloguard_core::OutboundConfig) -> Self {
        Self {
            tag: config.tag.clone(),
            protocol_type: format!("{:?}", config.outbound_type).to_lowercase(),
            server: config.server.clone(),
            port: config.port,
            latency_ms: None,
            alive: true,
        }
    }
}

/// Convert from OutboundConfig to ProxyGroupDto (for group types)
impl ProxyGroupDto {
    /// Create from an OutboundConfig reference (for group types only)
    pub fn from_outbound_config(config: &veloguard_core::OutboundConfig) -> Option<Self> {
        let group_type = match config.outbound_type {
            veloguard_core::OutboundType::Selector => "selector",
            veloguard_core::OutboundType::Urltest => "url-test",
            veloguard_core::OutboundType::Fallback => "fallback",
            veloguard_core::OutboundType::Loadbalance => "load-balance",
            veloguard_core::OutboundType::Relay => "relay",
            _ => return None, // Not a group type
        };

        // Get proxies list from options
        let proxies: Vec<String> = config.options
            .get("proxies")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Get selected proxy (first one by default)
        let selected = proxies.first().cloned().unwrap_or_default();

        Some(Self {
            tag: config.tag.clone(),
            group_type: group_type.to_string(),
            proxies,
            selected,
        })
    }
}


/// Convert from RuleConfig to RuleDto
impl RuleDto {
    /// Create from a RuleConfig reference
    pub fn from_rule_config(config: &veloguard_core::RuleConfig) -> Self {
        Self {
            rule_type: format!("{:?}", config.rule_type).to_lowercase(),
            payload: config.payload.clone(),
            outbound: config.outbound.clone(),
            matched_count: 0, // Matched count is tracked separately
        }
    }
}

/// Convert from DnsConfig to DnsConfigDto
impl DnsConfigDto {
    /// Create from a DnsConfig reference
    pub fn from_dns_config(config: &veloguard_core::DnsConfig) -> Self {
        Self {
            enable: config.enable,
            listen: config.listen.clone(),
            enhanced_mode: format!("{:?}", config.enhanced_mode).to_lowercase(),
            nameservers: config.nameservers.clone(),
            fallback: config.fallback.clone(),
        }
    }
}
