pub mod validator;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

impl Config {
    pub fn validate(&self) -> crate::error::Result<()> {
        crate::config::validator::ConfigValidator::validate(self)
    }

    pub fn new_validated(
        general: GeneralConfig,
        dns: DnsConfig,
        inbounds: Vec<InboundConfig>,
        outbounds: Vec<OutboundConfig>,
        rules: Vec<RuleConfig>,
    ) -> crate::error::Result<Self> {
        let config = Self {
            general,
            dns,
            inbounds,
            outbounds,
            rules,
        };
        config.validate()?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub authentication: Option<Vec<AuthenticationConfig>>,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub log_level: LogLevel,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub tcp_concurrent: bool,
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub secret: Option<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            socks_port: None,
            redir_port: None,
            tproxy_port: None,
            mixed_port: None,
            authentication: None,
            allow_lan: false,
            bind_address: default_bind_address(),
            mode: Mode::default(),
            log_level: LogLevel::default(),
            ipv6: false,
            tcp_concurrent: false,
            external_controller: None,
            external_ui: None,
            secret: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_dns_listen")]
    pub listen: String,
    #[serde(default)]
    pub nameservers: Vec<String>,
    #[serde(default)]
    pub fallback: Vec<String>,
    #[serde(default)]
    pub enhanced_mode: DnsMode,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: default_dns_listen(),
            nameservers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            fallback: vec!["8.8.4.4".to_string(), "1.0.0.1".to_string()],
            enhanced_mode: DnsMode::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    #[serde(rename = "type")]
    pub inbound_type: InboundType,
    pub tag: String,
    #[serde(default = "default_bind_address")]
    pub listen: String,
    pub port: u16,
    #[serde(flatten)]
    pub options: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    #[serde(rename = "type")]
    pub outbound_type: OutboundType,
    pub tag: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    #[serde(flatten)]
    pub options: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub payload: String,
    pub outbound: String,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationConfig {
    pub username: String,
    pub password: String,
}

/// Proxy mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

/// Log level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    #[default]
    Info,
    Warning,
    Error,
    Debug,
    Silent,
}

/// DNS mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    #[default]
    Normal,
    FakeIp,
}

/// Inbound protocol types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InboundType {
    Http,
    Socks5,
    Mixed,
    Redir,
    Tproxy,
    Tun,
    Vmess,
    Vless,
    Shadowsocks,
    Trojan,
    #[serde(alias = "dokodemo-door", alias = "dokodemo")]
    Dokodemo,
}

/// Outbound protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundType {
    Direct,
    Reject,
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Wireguard,
    Socks5,
    Http,
    #[serde(alias = "tuic")]
    Tuic,
    #[serde(alias = "hysteria2", alias = "hy2")]
    Hysteria2,
    #[serde(alias = "quic", alias = "shadowquic")]
    Quic,
    // Proxy group types
    #[serde(alias = "select")]
    Selector,
    #[serde(alias = "url-test")]
    Urltest,
    Fallback,
    #[serde(alias = "load-balance")]
    Loadbalance,
    Relay,
}

/// Rule types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    Geoip,
    IpCidr,
    SrcIpCidr,
    SrcPort,
    DstPort,
    ProcessName,
    RuleSet,
    Match,
}

fn default_port() -> u16 {
    7890
}

fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_dns_listen() -> String {
    "127.0.0.1:53".to_string()
}
