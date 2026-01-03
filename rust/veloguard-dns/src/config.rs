//! DNS configuration

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// DNS server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Enable DNS server
    pub enable: bool,

    /// Listen address for UDP DNS server
    pub listen: SocketAddr,

    /// Enable TCP DNS server
    pub tcp_enable: bool,

    /// Enable DoH (DNS over HTTPS) server
    pub doh_enable: bool,

    /// DoH listen address
    pub doh_listen: Option<SocketAddr>,

    /// Enable DoT (DNS over TLS) server
    pub dot_enable: bool,

    /// DoT listen address
    pub dot_listen: Option<SocketAddr>,

    /// TLS certificate path (for DoH/DoT server)
    pub tls_cert: Option<String>,

    /// TLS key path (for DoH/DoT server)
    pub tls_key: Option<String>,

    /// Enable Fake-IP mode
    pub fake_ip: bool,

    /// Fake-IP range (CIDR)
    pub fake_ip_range: String,

    /// Domains to exclude from Fake-IP
    pub fake_ip_filter: Vec<String>,

    /// Default upstream DNS servers
    pub nameservers: Vec<String>,

    /// Fallback DNS servers (used when primary fails or for anti-spoofing)
    pub fallback: Vec<String>,

    /// Domains that should use fallback DNS
    pub fallback_filter: FallbackFilter,

    /// DNS cache size
    pub cache_size: usize,

    /// Minimum TTL for cached records (seconds)
    pub min_ttl: u64,

    /// Maximum TTL for cached records (seconds)
    pub max_ttl: u64,

    /// Query timeout
    pub timeout: Duration,

    /// Hosts file entries
    pub hosts: std::collections::HashMap<String, IpAddr>,

    /// Enable EDNS Client Subnet
    pub edns_client_subnet: bool,

    /// Client subnet to use (if edns_client_subnet is enabled)
    pub client_subnet: Option<String>,

    /// Prefer IPv4 over IPv6
    pub prefer_ipv4: bool,

    /// Enable DNS over proxy (route DNS through proxy)
    pub proxy_dns: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: true,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5353),
            tcp_enable: true,
            doh_enable: false,
            doh_listen: None,
            dot_enable: false,
            dot_listen: None,
            tls_cert: None,
            tls_key: None,
            fake_ip: false,
            fake_ip_range: "198.18.0.0/16".to_string(),
            fake_ip_filter: vec![
                "*.lan".to_string(),
                "*.local".to_string(),
                "*.localhost".to_string(),
                "localhost".to_string(),
            ],
            nameservers: vec![
                "https://dns.google/dns-query".to_string(),
                "https://cloudflare-dns.com/dns-query".to_string(),
                "tls://dns.google".to_string(),
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
            ],
            fallback: vec![
                "https://dns.google/dns-query".to_string(),
                "tls://8.8.8.8".to_string(),
            ],
            fallback_filter: FallbackFilter::default(),
            cache_size: 10000,
            min_ttl: 60,
            max_ttl: 86400,
            timeout: Duration::from_secs(5),
            hosts: std::collections::HashMap::new(),
            edns_client_subnet: false,
            client_subnet: None,
            prefer_ipv4: true,
            proxy_dns: false,
        }
    }
}

/// Fallback filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FallbackFilter {
    /// Enable GeoIP-based fallback
    pub geoip: bool,

    /// GeoIP country codes that should NOT use fallback
    pub geoip_code: Vec<String>,

    /// Enable IP CIDR-based fallback
    pub ipcidr: Vec<String>,

    /// Domains that should use fallback
    pub domain: Vec<String>,
}

impl Default for FallbackFilter {
    fn default() -> Self {
        Self {
            geoip: true,
            geoip_code: vec!["CN".to_string()],
            ipcidr: vec![
                // Bogon IP ranges that indicate DNS pollution
                "240.0.0.0/4".to_string(),
                "0.0.0.0/8".to_string(),
                "127.0.0.0/8".to_string(),
            ],
            domain: vec![
                // Common domains that need fallback
                "+.google.com".to_string(),
                "+.youtube.com".to_string(),
                "+.facebook.com".to_string(),
                "+.twitter.com".to_string(),
            ],
        }
    }
}

/// Upstream DNS server configuration
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Server address
    pub address: String,

    /// Protocol type
    pub protocol: UpstreamProtocol,

    /// Server name for TLS (SNI)
    pub server_name: Option<String>,

    /// Custom port
    pub port: Option<u16>,

    /// Path for DoH
    pub path: Option<String>,
}

/// Upstream DNS protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// Plain UDP DNS
    Udp,
    /// Plain TCP DNS
    Tcp,
    /// DNS over TLS
    DoT,
    /// DNS over HTTPS
    DoH,
    /// DNS over QUIC
    DoQ,
}

impl UpstreamConfig {
    /// Parse upstream DNS server string
    /// Formats:
    /// - "8.8.8.8" or "8.8.8.8:53" -> UDP
    /// - "tcp://8.8.8.8" or "tcp://8.8.8.8:53" -> TCP
    /// - "tls://dns.google" or "tls://8.8.8.8:853" -> DoT
    /// - "https://dns.google/dns-query" -> DoH
    /// - "quic://dns.adguard.com" -> DoQ
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with("https://") {
            // DoH
            let url = url::Url::parse(s).ok()?;
            Some(Self {
                address: url.host_str()?.to_string(),
                protocol: UpstreamProtocol::DoH,
                server_name: Some(url.host_str()?.to_string()),
                port: url.port(),
                path: Some(url.path().to_string()),
            })
        } else if s.starts_with("tls://") {
            // DoT
            let rest = s.strip_prefix("tls://")?;
            let (host, port) = Self::parse_host_port(rest, 853);
            Some(Self {
                address: host.clone(),
                protocol: UpstreamProtocol::DoT,
                server_name: Some(host),
                port: Some(port),
                path: None,
            })
        } else if s.starts_with("tcp://") {
            // TCP
            let rest = s.strip_prefix("tcp://")?;
            let (host, port) = Self::parse_host_port(rest, 53);
            Some(Self {
                address: host,
                protocol: UpstreamProtocol::Tcp,
                server_name: None,
                port: Some(port),
                path: None,
            })
        } else if s.starts_with("quic://") {
            // DoQ
            let rest = s.strip_prefix("quic://")?;
            let (host, port) = Self::parse_host_port(rest, 853);
            Some(Self {
                address: host.clone(),
                protocol: UpstreamProtocol::DoQ,
                server_name: Some(host),
                port: Some(port),
                path: None,
            })
        } else {
            // Plain UDP
            let (host, port) = Self::parse_host_port(s, 53);
            Some(Self {
                address: host,
                protocol: UpstreamProtocol::Udp,
                server_name: None,
                port: Some(port),
                path: None,
            })
        }
    }

    fn parse_host_port(s: &str, default_port: u16) -> (String, u16) {
        if let Some((host, port_str)) = s.rsplit_once(':') {
            if let Ok(port) = port_str.parse() {
                return (host.to_string(), port);
            }
        }
        (s.to_string(), default_port)
    }

    /// Get the socket address for this upstream
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let port = self.port.unwrap_or(match self.protocol {
            UpstreamProtocol::Udp | UpstreamProtocol::Tcp => 53,
            UpstreamProtocol::DoT | UpstreamProtocol::DoQ => 853,
            UpstreamProtocol::DoH => 443,
        });

        // Try to parse as IP address first
        if let Ok(ip) = self.address.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, port));
        }

        // For domain names, we need to resolve them first
        // This is handled by the DNS client
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_upstream() {
        // UDP
        let cfg = UpstreamConfig::parse("8.8.8.8").unwrap();
        assert_eq!(cfg.protocol, UpstreamProtocol::Udp);
        assert_eq!(cfg.address, "8.8.8.8");
        assert_eq!(cfg.port, Some(53));

        // UDP with port
        let cfg = UpstreamConfig::parse("8.8.8.8:5353").unwrap();
        assert_eq!(cfg.port, Some(5353));

        // TCP
        let cfg = UpstreamConfig::parse("tcp://8.8.8.8").unwrap();
        assert_eq!(cfg.protocol, UpstreamProtocol::Tcp);

        // DoT
        let cfg = UpstreamConfig::parse("tls://dns.google").unwrap();
        assert_eq!(cfg.protocol, UpstreamProtocol::DoT);
        assert_eq!(cfg.server_name, Some("dns.google".to_string()));
        assert_eq!(cfg.port, Some(853));

        // DoH
        let cfg = UpstreamConfig::parse("https://dns.google/dns-query").unwrap();
        assert_eq!(cfg.protocol, UpstreamProtocol::DoH);
        assert_eq!(cfg.address, "dns.google");
        assert_eq!(cfg.path, Some("/dns-query".to_string()));
    }
}
