use crate::config::{Config, Mode, RuleConfig, RuleType};
use crate::error::{Error, Result};
use crate::geoip::GeoIpManager;
use crate::rule_provider::RuleProviderManager;
use ipnet::IpNet;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use tokio::sync::RwLock;

static RUNTIME_PROXY_MODE: AtomicI32 = AtomicI32::new(0);

pub fn set_runtime_proxy_mode(mode: i32) {
    tracing::info!("Setting runtime proxy mode to {}", mode);
    RUNTIME_PROXY_MODE.store(mode, Ordering::SeqCst);
}

pub fn get_runtime_proxy_mode() -> i32 {
    RUNTIME_PROXY_MODE.load(Ordering::SeqCst)
}

pub struct Router {
    config: Arc<RwLock<Config>>,
    rules: RwLock<Vec<CompiledRule>>,
    geoip_manager: GeoIpManager,
    rule_provider_manager: RuleProviderManager,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rule_type: RuleType,
    pattern: String,
    outbound: String,
    #[allow(dead_code)]
    process_name: Option<String>,
    regex: Option<Regex>,
}

impl Router {
    pub async fn new(config: Arc<RwLock<Config>>) -> Result<Self> {
        let rules = Self::compile_rules(&config.read().await.rules)?;
        let geoip_manager = GeoIpManager::new();
        let rule_provider_manager = RuleProviderManager::new();

        Ok(Self {
            config,
            rules: RwLock::new(rules),
            geoip_manager,
            rule_provider_manager,
        })
    }

    pub async fn load_geoip_database(&self, path: &str) -> Result<()> {
        self.geoip_manager.load_database(path).await
    }

    pub async fn load_geoip_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        self.geoip_manager.load_database_from_bytes(data).await
    }

    pub fn rule_provider_manager(&self) -> &RuleProviderManager {
        &self.rule_provider_manager
    }

    pub async fn match_outbound(
        &self,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process_name: Option<&str>,
    ) -> String {
        // First, check if this is a private/local address that should always be direct
        // This ensures LAN devices (printers, NAS, routers) are always accessible
        if Self::is_private_address(domain, ip) {
            tracing::debug!("Private address detected: domain={:?}, ip={:?} -> DIRECT", domain, ip);
            return "DIRECT".to_string();
        }
        
        let config = self.config.read().await;
        
        // Build a set of valid outbound tags for validation (case-insensitive)
        let valid_outbounds: std::collections::HashSet<String> = 
            config.outbounds.iter().map(|o| o.tag.to_lowercase()).collect();
        
        // Helper to find the actual tag name (preserving case)
        let find_actual_tag = |tag: &str| -> String {
            let tag_lower = tag.to_lowercase();
            for outbound in &config.outbounds {
                if outbound.tag.to_lowercase() == tag_lower {
                    return outbound.tag.clone();
                }
            }
            tag.to_string()
        };
        
        let runtime_mode = get_runtime_proxy_mode();
        // 0 = use config mode, 1 = global, 2 = direct, 3 = rule
        let effective_mode = match runtime_mode {
            1 => Mode::Global,
            2 => Mode::Direct,
            3 => Mode::Rule,
            _ => config.general.mode, // 0 or any other value uses config mode
        };
        
        tracing::info!(
            "[Router] Routing request: domain={:?}, ip={:?}, port={:?}, runtime_mode={}, config_mode={:?}, effective_mode={:?}",
            domain, ip, port, runtime_mode, config.general.mode, effective_mode
        );
        
        if matches!(effective_mode, Mode::Global) {
            // In Global mode, prefer proxy groups first (Selector, Urltest, etc.)
            for outbound in &config.outbounds {
                let tag_lower = outbound.tag.to_lowercase();
                // Skip built-in DIRECT and REJECT
                if tag_lower == "direct" || tag_lower == "reject" {
                    continue;
                }
                // Prefer proxy groups first
                if matches!(outbound.outbound_type, 
                    crate::config::OutboundType::Selector |
                    crate::config::OutboundType::Urltest |
                    crate::config::OutboundType::Fallback |
                    crate::config::OutboundType::Loadbalance
                ) {
                    tracing::info!("[Router] Global mode: routing '{}' to proxy group '{}'", 
                        domain.unwrap_or("<ip>"), outbound.tag);
                    return outbound.tag.clone();
                }
            }
            // No proxy group found, use first real proxy
            for outbound in &config.outbounds {
                let tag_lower = outbound.tag.to_lowercase();
                // Skip DIRECT, REJECT, and group types
                if tag_lower == "direct" || tag_lower == "reject" {
                    continue;
                }
                // Use first available proxy (VMess, Trojan, SS, etc.)
                if matches!(outbound.outbound_type,
                    crate::config::OutboundType::Vmess |
                    crate::config::OutboundType::Vless |
                    crate::config::OutboundType::Trojan |
                    crate::config::OutboundType::Shadowsocks |
                    crate::config::OutboundType::Socks5 |
                    crate::config::OutboundType::Http |
                    crate::config::OutboundType::Wireguard |
                    crate::config::OutboundType::Tuic |
                    crate::config::OutboundType::Hysteria2
                ) {
                    tracing::info!("[Router] Global mode: routing '{}' to proxy '{}'", 
                        domain.unwrap_or("<ip>"), outbound.tag);
                    return outbound.tag.clone();
                }
            }
            // Fallback to DIRECT if no proxy available
            tracing::warn!("[Router] Global mode: no proxy available, falling back to DIRECT");
            return find_actual_tag("DIRECT");
        }
        
        if matches!(effective_mode, Mode::Direct) {
            tracing::debug!("Direct mode: routing to DIRECT");
            return find_actual_tag("DIRECT");
        }
        
        let rules = self.rules.read().await;
        
        tracing::debug!("[Router] Rule mode: checking {} rules for domain={:?}", rules.len(), domain);

        for rule in rules.iter() {
            if self.matches_rule(rule, domain, ip, port, process_name).await {
                // Validate that the outbound exists (case-insensitive)
                if valid_outbounds.contains(&rule.outbound.to_lowercase()) {
                    let actual_tag = find_actual_tag(&rule.outbound);
                    tracing::info!(
                        "[Router] Rule matched: {:?} '{}' -> '{}' for domain={:?}",
                        rule.rule_type, rule.pattern, actual_tag, domain
                    );
                    return actual_tag;
                } else {
                    // Outbound doesn't exist, log error and continue to next rule
                    tracing::error!(
                        "[Router] Rule references non-existent outbound '{}', skipping. \
                        Please check your config.yaml and ensure all outbounds referenced in rules are defined.",
                        rule.outbound
                    );
                    // Continue to next rule instead of returning DIRECT immediately
                    continue;
                }
            }
        }

        // No rule matched - in Rule mode, use the first proxy group or DIRECT
        let default_outbound = if matches!(effective_mode, Mode::Rule) {
            // In rule mode, prefer to go through proxy for unmatched traffic
            // unless explicitly configured otherwise
            config.outbounds.iter()
                .find(|o| matches!(o.outbound_type,
                    crate::config::OutboundType::Selector |
                    crate::config::OutboundType::Urltest |
                    crate::config::OutboundType::Fallback |
                    crate::config::OutboundType::Loadbalance
                ))
                .map(|o| o.tag.clone())
                .unwrap_or_else(|| "DIRECT".to_string())
        } else {
            "DIRECT".to_string()
        };
        
        tracing::info!("[Router] No rule matched for domain={:?}, using default: {}", domain, default_outbound);
        default_outbound
    }
    
    /// Check if the address is a private/local address that should always be direct
    /// This includes:
    /// - Localhost domains (localhost, *.local, *.lan, etc.)
    /// - Private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    /// - Loopback (127.0.0.0/8, ::1)
    /// - Link-local (169.254.0.0/16, fe80::/10)
    /// - Multicast (224.0.0.0/4, ff00::/8)
    /// - Broadcast (255.255.255.255)
    /// - Unique local IPv6 (fc00::/7)
    fn is_private_address(domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        // Check domain for localhost patterns
        if let Some(domain) = domain {
            let domain_lower = domain.to_lowercase();
            
            // Exact matches
            if domain_lower == "localhost" 
                || domain_lower == "localhost.localdomain"
                || domain_lower == "ip6-localhost"
                || domain_lower == "ip6-loopback"
            {
                return true;
            }
            
            // Suffix matches for local domains
            if domain_lower.ends_with(".localhost")
                || domain_lower.ends_with(".local")
                || domain_lower.ends_with(".lan")
                || domain_lower.ends_with(".internal")
                || domain_lower.ends_with(".home")
                || domain_lower.ends_with(".home.arpa")
                || domain_lower.ends_with(".localdomain")
                || domain_lower.ends_with(".intranet")
                || domain_lower.ends_with(".corp")
                || domain_lower.ends_with(".private")
            {
                return true;
            }
            
            // Check if domain looks like an IP address in private range
            if let Ok(ip) = domain_lower.parse::<IpAddr>() {
                return Self::is_private_ip(ip);
            }
        }
        
        // Check IP for private ranges
        if let Some(ip) = ip {
            return Self::is_private_ip(ip);
        }
        
        false
    }
    
    /// Check if an IP address is in a private/local range
    #[inline]
    pub fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                
                // Loopback: 127.0.0.0/8
                if octets[0] == 127 {
                    return true;
                }
                
                // Private: 10.0.0.0/8
                if octets[0] == 10 {
                    return true;
                }
                
                // Private: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
                if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                    return true;
                }
                
                // Private: 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return true;
                }
                
                // Link-local: 169.254.0.0/16
                if octets[0] == 169 && octets[1] == 254 {
                    return true;
                }
                
                // Multicast: 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
                if octets[0] >= 224 && octets[0] <= 239 {
                    return true;
                }
                
                // Broadcast: 255.255.255.255/32
                if octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255 {
                    return true;
                }
                
                // Current network (only valid as source): 0.0.0.0/8
                if octets[0] == 0 {
                    return true;
                }
                
                // CGNAT (Carrier-grade NAT): 100.64.0.0/10
                if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
                    return true;
                }
                
                // Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                    || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                    || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                {
                    return true;
                }
                
                // Benchmarking: 198.18.0.0/15
                // NOTE: We intentionally DO NOT treat 198.18.0.0/15 as private because
                // this range is used for Fake-IP DNS resolution. Fake-IP addresses
                // should be routed through the proxy, not directly.
                // The original benchmarking range check has been removed to support Fake-IP.
                // if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
                //     return true;
                // }
                
                false
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                
                // Loopback: ::1/128
                if ipv6.is_loopback() {
                    return true;
                }
                
                // Unspecified: ::/128
                if ipv6.is_unspecified() {
                    return true;
                }
                
                // Link-local: fe80::/10
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return true;
                }
                
                // Unique local: fc00::/7 (fc00:: - fdff::)
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return true;
                }
                
                // Multicast: ff00::/8
                if (segments[0] & 0xff00) == 0xff00 {
                    return true;
                }
                
                // IPv4-mapped IPv6: ::ffff:0:0/96
                if segments[0] == 0 && segments[1] == 0 && segments[2] == 0 
                    && segments[3] == 0 && segments[4] == 0 && segments[5] == 0xffff 
                {
                    // Check if the mapped IPv4 is private
                    let ipv4 = std::net::Ipv4Addr::new(
                        (segments[6] >> 8) as u8,
                        (segments[6] & 0xff) as u8,
                        (segments[7] >> 8) as u8,
                        (segments[7] & 0xff) as u8,
                    );
                    return Self::is_private_ip(IpAddr::V4(ipv4));
                }
                
                // Site-local (deprecated but still used): fec0::/10
                if (segments[0] & 0xffc0) == 0xfec0 {
                    return true;
                }
                
                false
            }
        }
    }

    pub async fn reload(&self) -> Result<()> {
        let config = self.config.read().await;
        let new_rules = Self::compile_rules(&config.rules)?;
        let mut rules = self.rules.write().await;
        *rules = new_rules;
        Ok(())
    }

    fn compile_rules(rules: &[RuleConfig]) -> Result<Vec<CompiledRule>> {
        let mut compiled = Vec::new();

        for rule in rules {
            let regex = if rule.rule_type == RuleType::DomainRegex {
                Some(Regex::new(&rule.payload).map_err(|e| {
                    Error::config(format!("Invalid regex pattern: {}", e))
                })?)
            } else {
                None
            };

            compiled.push(CompiledRule {
                rule_type: rule.rule_type,
                pattern: rule.payload.clone(),
                outbound: rule.outbound.clone(),
                process_name: rule.process_name.clone(),
                regex,
            });
        }

        Ok(compiled)
    }

    async fn matches_rule(
        &self,
        rule: &CompiledRule,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process_name: Option<&str>,
    ) -> bool {
        match rule.rule_type {
            RuleType::Domain => {
                if let Some(domain) = domain {
                    domain.to_lowercase() == rule.pattern.to_lowercase()
                } else {
                    false
                }
            }
            RuleType::DomainSuffix => {
                if let Some(domain) = domain {
                    let domain_lower = domain.to_lowercase();
                    let pattern_lower = rule.pattern.to_lowercase();
                    domain_lower == pattern_lower || 
                    domain_lower.ends_with(&format!(".{}", pattern_lower))
                } else {
                    false
                }
            }
            RuleType::DomainKeyword => {
                if let Some(domain) = domain {
                    domain.to_lowercase().contains(&rule.pattern.to_lowercase())
                } else {
                    false
                }
            }
            RuleType::DomainRegex => {
                if let Some(domain) = domain {
                    if let Some(regex) = &rule.regex {
                        regex.is_match(domain)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            RuleType::IpCidr => {
                if let Some(ip) = ip {
                    Self::matches_cidr(&rule.pattern, ip)
                } else {
                    false
                }
            }
            RuleType::SrcIpCidr => {
                if let Some(ip) = ip {
                    Self::matches_cidr(&rule.pattern, ip)
                } else {
                    false
                }
            }
            RuleType::Geoip => {
                if let Some(ip) = ip {
                    self.geoip_manager.matches_country(&rule.pattern, ip).await
                } else {
                    false
                }
            }
            RuleType::SrcPort | RuleType::DstPort => {
                if let Some(port) = port {
                    Self::matches_port_range(&rule.pattern, port)
                } else {
                    false
                }
            }
            RuleType::ProcessName => {
                if let Some(process) = process_name {
                    self.matches_process_name(&rule.pattern, process)
                } else {
                    false
                }
            }
            RuleType::RuleSet => {
                self.rule_provider_manager
                    .matches(&rule.pattern, domain, ip)
                    .await
            }
            RuleType::Match => true,
        }
    }

    fn matches_cidr(cidr_str: &str, ip: IpAddr) -> bool {
        match cidr_str.parse::<IpNet>() {
            Ok(network) => network.contains(&ip),
            Err(_) => false,
        }
    }

    fn matches_port_range(pattern: &str, port: u16) -> bool {
        for part in pattern.split(',') {
            let part = part.trim();
            if part.contains('-') {
                if let Some((start, end)) = part.split_once('-') {
                    if let (Ok(start), Ok(end)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                        if port >= start && port <= end {
                            return true;
                        }
                    }
                }
            } else if let Ok(single_port) = part.parse::<u16>() {
                if port == single_port {
                    return true;
                }
            }
        }
        false
    }

    fn matches_process_name(&self, pattern: &str, process_name: &str) -> bool {
        let pattern_lower = pattern.to_lowercase();
        let process_lower = process_name.to_lowercase();
        
        if pattern_lower == process_lower {
            return true;
        }
        
        if let Some(name) = process_name.rsplit(['/', '\\']).next() {
            if name.to_lowercase() == pattern_lower {
                return true;
            }
        }
        
        if let Some(name_without_ext) = pattern_lower.strip_suffix(".exe") {
            if process_lower == name_without_ext {
                return true;
            }
            if let Some(proc_name) = process_name.rsplit(['/', '\\']).next() {
                if proc_name.to_lowercase() == name_without_ext {
                    return true;
                }
            }
        }
        
        if let Some(proc_without_ext) = process_lower.strip_suffix(".exe") {
            if proc_without_ext == pattern_lower {
                return true;
            }
        }
        
        false
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_matches_cidr_ipv4() {
        assert!(Router::matches_cidr("192.168.0.0/16", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(Router::matches_cidr("192.168.0.0/16", IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
        assert!(!Router::matches_cidr("192.168.0.0/16", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_matches_cidr_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(Router::matches_cidr("2001:db8::/32", ip));
        
        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1));
        assert!(!Router::matches_cidr("2001:db8::/32", ip2));
    }

    #[test]
    fn test_matches_port_range_single() {
        assert!(Router::matches_port_range("80", 80));
        assert!(!Router::matches_port_range("80", 443));
    }

    #[test]
    fn test_matches_port_range_range() {
        assert!(Router::matches_port_range("80-443", 80));
        assert!(Router::matches_port_range("80-443", 200));
        assert!(Router::matches_port_range("80-443", 443));
        assert!(!Router::matches_port_range("80-443", 79));
        assert!(!Router::matches_port_range("80-443", 444));
    }

    #[test]
    fn test_matches_port_range_multiple() {
        assert!(Router::matches_port_range("80,443,8080", 80));
        assert!(Router::matches_port_range("80,443,8080", 443));
        assert!(Router::matches_port_range("80,443,8080", 8080));
        assert!(!Router::matches_port_range("80,443,8080", 8081));
    }

    #[test]
    fn test_matches_port_range_mixed() {
        assert!(Router::matches_port_range("80,443-445,8080", 80));
        assert!(Router::matches_port_range("80,443-445,8080", 444));
        assert!(Router::matches_port_range("80,443-445,8080", 8080));
        assert!(!Router::matches_port_range("80,443-445,8080", 446));
    }

    #[test]
    fn test_matches_process_name_exact() {
        let router = Router {
            config: std::sync::Arc::new(RwLock::new(Config::default())),
            rules: RwLock::new(Vec::new()),
            geoip_manager: GeoIpManager::new(),
            rule_provider_manager: RuleProviderManager::new(),
        };
        
        assert!(router.matches_process_name("chrome", "chrome"));
        assert!(router.matches_process_name("Chrome", "chrome"));
    }

    #[test]
    fn test_matches_process_name_with_path() {
        let router = Router {
            config: std::sync::Arc::new(RwLock::new(Config::default())),
            rules: RwLock::new(Vec::new()),
            geoip_manager: GeoIpManager::new(),
            rule_provider_manager: RuleProviderManager::new(),
        };
        
        assert!(router.matches_process_name("chrome", "/usr/bin/chrome"));
        assert!(router.matches_process_name("chrome", "C:\\Program Files\\chrome"));
    }

    #[test]
    fn test_matches_process_name_with_exe() {
        let router = Router {
            config: std::sync::Arc::new(RwLock::new(Config::default())),
            rules: RwLock::new(Vec::new()),
            geoip_manager: GeoIpManager::new(),
            rule_provider_manager: RuleProviderManager::new(),
        };
        
        assert!(router.matches_process_name("chrome.exe", "chrome"));
        assert!(router.matches_process_name("chrome", "chrome.exe"));
    }
    
    #[test]
    fn test_is_private_address_localhost() {
        // Domain-based localhost
        assert!(Router::is_private_address(Some("localhost"), None));
        assert!(Router::is_private_address(Some("LOCALHOST"), None));
        assert!(Router::is_private_address(Some("localhost.localdomain"), None));
        assert!(Router::is_private_address(Some("test.localhost"), None));
        assert!(Router::is_private_address(Some("myhost.local"), None));
        assert!(Router::is_private_address(Some("router.lan"), None));
        
        // Not localhost
        assert!(!Router::is_private_address(Some("google.com"), None));
        assert!(!Router::is_private_address(Some("localhost.com"), None));
    }
    
    #[test]
    fn test_is_private_address_ipv4() {
        // Loopback
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))));
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255)))));
        
        // Private 10.x.x.x
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))));
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)))));
        
        // Private 172.16-31.x.x
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)))));
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255)))));
        assert!(!Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(172, 15, 0, 1)))));
        assert!(!Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1)))));
        
        // Private 192.168.x.x
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))));
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255)))));
        
        // Link-local
        assert!(Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)))));
        
        // Public IPs should not be private
        assert!(!Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
        assert!(!Router::is_private_address(None, Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))));
    }
    
    #[test]
    fn test_is_private_address_ipv6() {
        // Loopback
        assert!(Router::is_private_address(None, Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))));
        
        // Unspecified
        assert!(Router::is_private_address(None, Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)))));
        
        // Link-local fe80::/10
        assert!(Router::is_private_address(None, Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))));
        
        // Unique local fc00::/7
        assert!(Router::is_private_address(None, Some(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)))));
        assert!(Router::is_private_address(None, Some(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)))));
        
        // Public IPv6 should not be private
        assert!(!Router::is_private_address(None, Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)))));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    #[allow(dead_code)]
    fn arb_ipv6() -> impl Strategy<Value = Ipv6Addr> {
        (
            any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(),
            any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(),
        )
            .prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn arb_domain() -> impl Strategy<Value = String> {
        "[a-z]{1,10}(\\.[a-z]{2,5}){1,3}"
    }

    fn arb_port() -> impl Strategy<Value = u16> {
        1u16..=65535u16
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_domain_exact_match_is_case_insensitive(
            domain in arb_domain()
        ) {
            let lower = domain.to_lowercase();
            let upper = domain.to_uppercase();
            
            let rule = CompiledRule {
                rule_type: RuleType::Domain,
                pattern: lower.clone(),
                outbound: "proxy".to_string(),
                process_name: None,
                regex: None,
            };
            
            let router = Router {
                config: std::sync::Arc::new(RwLock::new(Config::default())),
                rules: RwLock::new(vec![rule]),
                geoip_manager: GeoIpManager::new(),
                rule_provider_manager: RuleProviderManager::new(),
            };
            
            let rt = tokio::runtime::Runtime::new().unwrap();
            let matches_lower = rt.block_on(async {
                router.matches_rule(
                    &router.rules.read().await[0],
                    Some(&lower),
                    None,
                    None,
                    None,
                ).await
            });
            let matches_upper = rt.block_on(async {
                router.matches_rule(
                    &router.rules.read().await[0],
                    Some(&upper),
                    None,
                    None,
                    None,
                ).await
            });
            
            prop_assert!(matches_lower);
            prop_assert!(matches_upper);
        }

        #[test]
        fn prop_domain_suffix_matches_subdomain(
            base_domain in "[a-z]{3,8}\\.[a-z]{2,4}",
            subdomain in "[a-z]{1,5}"
        ) {
            let full_domain = format!("{}.{}", subdomain, base_domain);
            
            let rule = CompiledRule {
                rule_type: RuleType::DomainSuffix,
                pattern: base_domain.clone(),
                outbound: "proxy".to_string(),
                process_name: None,
                regex: None,
            };
            
            let router = Router {
                config: std::sync::Arc::new(RwLock::new(Config::default())),
                rules: RwLock::new(vec![rule]),
                geoip_manager: GeoIpManager::new(),
                rule_provider_manager: RuleProviderManager::new(),
            };
            
            let rt = tokio::runtime::Runtime::new().unwrap();
            let matches = rt.block_on(async {
                router.matches_rule(
                    &router.rules.read().await[0],
                    Some(&full_domain),
                    None,
                    None,
                    None,
                ).await
            });
            
            prop_assert!(matches, "Domain suffix {} should match {}", base_domain, full_domain);
        }

        #[test]
        fn prop_domain_keyword_matches_containing_domain(
            keyword in "[a-z]{3,6}",
            prefix in "[a-z]{0,3}",
            suffix in "[a-z]{0,3}\\.[a-z]{2,4}"
        ) {
            let domain = format!("{}{}{}", prefix, keyword, suffix);
            
            let rule = CompiledRule {
                rule_type: RuleType::DomainKeyword,
                pattern: keyword.clone(),
                outbound: "proxy".to_string(),
                process_name: None,
                regex: None,
            };
            
            let router = Router {
                config: std::sync::Arc::new(RwLock::new(Config::default())),
                rules: RwLock::new(vec![rule]),
                geoip_manager: GeoIpManager::new(),
                rule_provider_manager: RuleProviderManager::new(),
            };
            
            let rt = tokio::runtime::Runtime::new().unwrap();
            let matches = rt.block_on(async {
                router.matches_rule(
                    &router.rules.read().await[0],
                    Some(&domain),
                    None,
                    None,
                    None,
                ).await
            });
            
            prop_assert!(matches, "Keyword {} should match domain {}", keyword, domain);
        }

        #[test]
        fn prop_ip_cidr_contains_network_ips(
            base_ip in arb_ipv4(),
            prefix_len in 16u8..=30u8,
            offset in 0u32..256u32
        ) {
            let base_octets = base_ip.octets();
            let base_u32 = u32::from_be_bytes(base_octets);
            
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            let network_base = base_u32 & mask;
            
            let network_size = 1u32 << (32 - prefix_len);
            let test_offset = offset % network_size;
            let test_ip_u32 = network_base.wrapping_add(test_offset);
            let test_ip = Ipv4Addr::from(test_ip_u32);
            
            let network_ip = Ipv4Addr::from(network_base);
            let cidr = format!("{}/{}", network_ip, prefix_len);
            
            let matches = Router::matches_cidr(&cidr, IpAddr::V4(test_ip));
            prop_assert!(matches, "IP {} should be in CIDR {}", test_ip, cidr);
        }

        #[test]
        fn prop_port_in_range_matches(
            start in 1u16..32000u16,
            range_size in 1u16..1000u16
        ) {
            let end = start.saturating_add(range_size).min(65535);
            let pattern = format!("{}-{}", start, end);
            
            for port in start..=end.min(start + 10) {
                prop_assert!(
                    Router::matches_port_range(&pattern, port),
                    "Port {} should match range {}", port, pattern
                );
            }
        }

        #[test]
        fn prop_port_outside_range_does_not_match(
            start in 100u16..32000u16,
            range_size in 10u16..1000u16
        ) {
            let end = start.saturating_add(range_size).min(65534);
            let pattern = format!("{}-{}", start, end);
            
            if start > 1 {
                prop_assert!(
                    !Router::matches_port_range(&pattern, start - 1),
                    "Port {} should not match range {}", start - 1, pattern
                );
            }
            
            if end < 65535 {
                prop_assert!(
                    !Router::matches_port_range(&pattern, end + 1),
                    "Port {} should not match range {}", end + 1, pattern
                );
            }
        }

        #[test]
        fn prop_match_rule_always_matches(
            domain in proptest::option::of(arb_domain()),
            ip in proptest::option::of(arb_ipv4().prop_map(IpAddr::V4)),
            port in proptest::option::of(arb_port())
        ) {
            let rule = CompiledRule {
                rule_type: RuleType::Match,
                pattern: String::new(),
                outbound: "proxy".to_string(),
                process_name: None,
                regex: None,
            };
            
            let router = Router {
                config: std::sync::Arc::new(RwLock::new(Config::default())),
                rules: RwLock::new(vec![rule]),
                geoip_manager: GeoIpManager::new(),
                rule_provider_manager: RuleProviderManager::new(),
            };
            
            let rt = tokio::runtime::Runtime::new().unwrap();
            let matches = rt.block_on(async {
                router.matches_rule(
                    &router.rules.read().await[0],
                    domain.as_deref(),
                    ip,
                    port,
                    None,
                ).await
            });
            
            prop_assert!(matches, "MATCH rule should always match");
        }

        #[test]
        fn prop_rules_match_in_priority_order(
            domain in "[a-z]{5,10}\\.[a-z]{2,4}"
        ) {
            let rules = vec![
                RuleConfig {
                    rule_type: RuleType::Domain,
                    payload: domain.clone(),
                    outbound: "first".to_string(),
                    process_name: None,
                },
                RuleConfig {
                    rule_type: RuleType::DomainSuffix,
                    payload: domain.split('.').last().unwrap_or("com").to_string(),
                    outbound: "second".to_string(),
                    process_name: None,
                },
                RuleConfig {
                    rule_type: RuleType::Match,
                    payload: String::new(),
                    outbound: "fallback".to_string(),
                    process_name: None,
                },
            ];
            
            let config = Config {
                rules: rules.clone(),
                outbounds: vec![
                    crate::config::OutboundConfig {
                        outbound_type: crate::config::OutboundType::Direct,
                        tag: "first".to_string(),
                        server: None,
                        port: None,
                        options: std::collections::HashMap::new(),
                    },
                ],
                ..Default::default()
            };
            
            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(async {
                let router = Router::new(std::sync::Arc::new(RwLock::new(config))).await.unwrap();
                router.match_outbound(Some(&domain), None, None, None).await
            });
            
            prop_assert_eq!(result, "first", "First matching rule should be used");
        }
    }
}
