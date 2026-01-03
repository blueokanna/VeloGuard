use crate::config::{Config, Mode, RuleConfig, RuleType};
use crate::error::{Error, Result};
use ipnet::IpNet;
use maxminddb::{geoip2, Reader};
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use tokio::sync::RwLock;

/// Global proxy mode override (for Android/OHOS runtime mode switching)
/// 0 = use config mode, 1 = global, 2 = direct, 3 = rule
static RUNTIME_PROXY_MODE: AtomicI32 = AtomicI32::new(0);

/// Set the runtime proxy mode
/// mode: 0 = use config, 1 = global, 2 = direct, 3 = rule
pub fn set_runtime_proxy_mode(mode: i32) {
    tracing::info!("Setting runtime proxy mode to {}", mode);
    RUNTIME_PROXY_MODE.store(mode, Ordering::SeqCst);
}

/// Get the current runtime proxy mode
pub fn get_runtime_proxy_mode() -> i32 {
    RUNTIME_PROXY_MODE.load(Ordering::SeqCst)
}

/// Router for matching traffic to outbound proxies
pub struct Router {
    config: Arc<RwLock<Config>>,
    rules: RwLock<Vec<CompiledRule>>,
    geoip_reader: Option<Reader<Vec<u8>>>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rule_type: RuleType,
    pattern: String,
    outbound: String,
    process_name: Option<String>,
    regex: Option<Regex>,
}

impl Router {
    /// Create a new router
    pub async fn new(config: Arc<RwLock<Config>>) -> Result<Self> {
        let rules = Self::compile_rules(&config.read().await.rules)?;
        // TODO: Load GeoIP database from config path
        let geoip_reader = None; // For now, disable GeoIP

        Ok(Self {
            config,
            rules: RwLock::new(rules),
            geoip_reader,
        })
    }

    /// Match a request to an outbound tag
    pub async fn match_outbound(
        &self,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process_name: Option<&str>,
    ) -> String {
        let config = self.config.read().await;
        
        // Check runtime proxy mode first (for Android/OHOS dynamic mode switching)
        let runtime_mode = get_runtime_proxy_mode();
        let effective_mode = match runtime_mode {
            1 => Mode::Global,  // Global mode
            2 => Mode::Direct,  // Direct mode
            3 => Mode::Rule,    // Rule mode
            _ => config.general.mode,  // Use config mode
        };
        
        // Handle Global mode - route all traffic through first proxy group or proxy
        if matches!(effective_mode, Mode::Global) {
            // Find the first selector/proxy group, or first non-direct/reject outbound
            for outbound in &config.outbounds {
                let tag_lower = outbound.tag.to_lowercase();
                // Skip DIRECT and REJECT
                if tag_lower == "direct" || tag_lower == "reject" {
                    continue;
                }
                // Prefer proxy groups (selector, urltest, etc.)
                if matches!(outbound.outbound_type, 
                    crate::config::OutboundType::Selector |
                    crate::config::OutboundType::Urltest |
                    crate::config::OutboundType::Fallback |
                    crate::config::OutboundType::Loadbalance
                ) {
                    tracing::debug!("Global mode: routing to proxy group '{}'", outbound.tag);
                    return outbound.tag.clone();
                }
            }
            // If no proxy group found, use first actual proxy
            for outbound in &config.outbounds {
                let tag_lower = outbound.tag.to_lowercase();
                if tag_lower != "direct" && tag_lower != "reject" {
                    tracing::debug!("Global mode: routing to proxy '{}'", outbound.tag);
                    return outbound.tag.clone();
                }
            }
            // Fallback to DIRECT if no proxy found
            return "DIRECT".to_string();
        }
        
        // Handle Direct mode - route all traffic directly
        if matches!(effective_mode, Mode::Direct) {
            tracing::debug!("Direct mode: routing to DIRECT");
            return "DIRECT".to_string();
        }
        
        // Rule mode - check rules in order
        let rules = self.rules.read().await;

        // Check rules in order
        for rule in rules.iter() {
            if self.matches_rule(rule, domain, ip, port, process_name) {
                return rule.outbound.clone();
            }
        }

        // Default to first outbound or "direct"
        config
            .outbounds
            .first()
            .map(|o| o.tag.clone())
            .unwrap_or_else(|| "direct".to_string())
    }

    /// Reload routing rules
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

    fn matches_rule(
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
                    // Domain suffix matching: domain equals pattern OR ends with .pattern
                    // e.g., pattern "youtube.com" matches "youtube.com" and "www.youtube.com"
                    // but NOT "notyoutube.com"
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
                // Note: Source IP matching requires additional context
                // For now, treat as regular IP CIDR matching
                if let Some(ip) = ip {
                    Self::matches_cidr(&rule.pattern, ip)
                } else {
                    false
                }
            }
            RuleType::Geoip => {
                if let Some(ip) = ip {
                    self.matches_geoip(&rule.pattern, ip)
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
                    rule.process_name.as_ref() == Some(&process.to_string())
                } else {
                    false
                }
            }
            RuleType::RuleSet => {
                // TODO: Implement rule-set matching
                // For now, skip rule-set rules
                false
            }
            RuleType::Match => true, // Match all
        }
    }

    /// Check if an IP address matches a CIDR pattern
    fn matches_cidr(cidr_str: &str, ip: IpAddr) -> bool {
        match cidr_str.parse::<IpNet>() {
            Ok(network) => network.contains(&ip),
            Err(_) => false,
        }
    }

    /// Check if a port matches a port range pattern
    fn matches_port_range(pattern: &str, port: u16) -> bool {
        // Support formats: "80", "80-443", "80,443,8080"
        for part in pattern.split(',') {
            let part = part.trim();
            if part.contains('-') {
                // Range format: "80-443"
                if let Some((start, end)) = part.split_once('-') {
                    if let (Ok(start), Ok(end)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                        if port >= start && port <= end {
                            return true;
                        }
                    }
                }
            } else {
                // Single port format: "80"
                if let Ok(single_port) = part.parse::<u16>() {
                    if port == single_port {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if an IP address matches a GeoIP country code
    fn matches_geoip(&self, country_code: &str, ip: IpAddr) -> bool {
        if let Some(reader) = &self.geoip_reader {
            if let Ok(lookup_result) = reader.lookup(ip) {
                if let Ok(Some(country_data)) = lookup_result.decode::<geoip2::Country>() {
                    // country_data.country is a Country struct
                    if let Some(iso_code) = country_data.country.iso_code {
                        return iso_code.to_uppercase() == country_code.to_uppercase();
                    }
                }
            }
        }

        // Fallback: basic country code matching for common cases
        // This is a simplified implementation - in production you'd use a real GeoIP database
        self.basic_geoip_lookup(country_code, ip)
    }

    /// Basic GeoIP lookup for common IP ranges (simplified implementation)
    fn basic_geoip_lookup(&self, country_code: &str, _ip: IpAddr) -> bool {
        // This is a placeholder implementation
        // In a real implementation, you'd load a GeoIP database
        // For now, return false for all queries
        let _ = country_code;
        false
    }
}
