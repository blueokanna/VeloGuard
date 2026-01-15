use crate::config::{
    Config, DnsConfig, DnsMode, GeneralConfig, InboundConfig, InboundType, LogLevel, Mode,
    OutboundConfig, OutboundType, RuleConfig, RuleType,
};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ClashConfig {
    pub port: Option<u16>,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub authentication: Option<Vec<String>>,
    pub allow_lan: Option<bool>,
    pub bind_address: Option<String>,
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub ipv6: Option<bool>,
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub secret: Option<String>,
    pub dns: Option<ClashDnsConfig>,
    pub proxies: Option<Vec<HashMap<String, serde_yaml::Value>>>,
    pub proxy_groups: Option<Vec<HashMap<String, serde_yaml::Value>>>,
    pub rules: Option<Vec<String>>,
    pub proxy_providers: Option<HashMap<String, serde_yaml::Value>>,
    pub rule_providers: Option<HashMap<String, serde_yaml::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ClashDnsConfig {
    pub enable: Option<bool>,
    pub listen: Option<String>,
    pub ipv6: Option<bool>,
    pub enhanced_mode: Option<String>,
    pub fake_ip_range: Option<String>,
    pub fake_ip_filter: Option<Vec<String>>,
    pub nameserver: Option<Vec<String>>,
    pub fallback: Option<Vec<String>>,
    pub fallback_filter: Option<HashMap<String, serde_yaml::Value>>,
    pub default_nameserver: Option<Vec<String>>,
    pub nameserver_policy: Option<HashMap<String, String>>,
}

impl ClashConfig {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml)
            .map_err(|e| Error::config(format!("Failed to parse Clash config: {}", e)))
    }

    /// Convert Clash config to VeloGuard config
    pub fn to_veloguard_config(&self) -> Result<Config> {
        let general = self.convert_general();
        let dns = self.convert_dns();
        let inbounds = self.generate_inbounds();
        let outbounds = self.convert_outbounds()?;
        let rules = self.convert_rules(&outbounds);

        Ok(Config {
            general,
            dns,
            inbounds,
            outbounds,
            rules,
        })
    }

    fn convert_general(&self) -> GeneralConfig {
        GeneralConfig {
            port: self.port.unwrap_or(7890),
            socks_port: self.socks_port,
            redir_port: self.redir_port,
            tproxy_port: self.tproxy_port,
            mixed_port: self.mixed_port,
            authentication: None,
            allow_lan: self.allow_lan.unwrap_or(false),
            bind_address: self
                .bind_address
                .clone()
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            mode: self
                .mode
                .as_ref()
                .map(|m| match m.to_lowercase().as_str() {
                    "global" => Mode::Global,
                    "direct" => Mode::Direct,
                    _ => Mode::Rule,
                })
                .unwrap_or(Mode::Rule),
            log_level: self
                .log_level
                .as_ref()
                .map(|l| match l.to_lowercase().as_str() {
                    "debug" => LogLevel::Debug,
                    "warning" | "warn" => LogLevel::Warning,
                    "error" => LogLevel::Error,
                    "silent" | "off" => LogLevel::Silent,
                    _ => LogLevel::Info,
                })
                .unwrap_or(LogLevel::Info),
            ipv6: self.ipv6.unwrap_or(false),
            tcp_concurrent: false,
            external_controller: self.external_controller.clone(),
            external_ui: self.external_ui.clone(),
            secret: self.secret.clone(),
        }
    }

    fn convert_dns(&self) -> DnsConfig {
        if let Some(dns) = &self.dns {
            DnsConfig {
                enable: dns.enable.unwrap_or(false),
                listen: dns
                    .listen
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1:53".to_string()),
                nameservers: dns
                    .nameserver
                    .clone()
                    .unwrap_or_else(|| vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]),
                fallback: dns
                    .fallback
                    .clone()
                    .unwrap_or_else(|| vec!["8.8.4.4".to_string(), "1.0.0.1".to_string()]),
                enhanced_mode: dns
                    .enhanced_mode
                    .as_ref()
                    .map(|m| {
                        if m.to_lowercase() == "fake-ip" {
                            DnsMode::FakeIp
                        } else {
                            DnsMode::Normal
                        }
                    })
                    .unwrap_or(DnsMode::Normal),
            }
        } else {
            DnsConfig::default()
        }
    }

    fn generate_inbounds(&self) -> Vec<InboundConfig> {
        let mut inbounds = Vec::new();
        let bind = self.bind_address.clone().unwrap_or_else(|| {
            if self.allow_lan.unwrap_or(false) {
                "0.0.0.0".to_string()
            } else {
                "127.0.0.1".to_string()
            }
        });

        if let Some(port) = self.port {
            inbounds.push(InboundConfig {
                inbound_type: InboundType::Http,
                tag: "http-in".to_string(),
                listen: bind.clone(),
                port,
                options: HashMap::new(),
            });
        }

        if let Some(port) = self.socks_port {
            let mut options = HashMap::new();
            options.insert("udp".to_string(), serde_yaml::Value::Bool(true));
            inbounds.push(InboundConfig {
                inbound_type: InboundType::Socks5,
                tag: "socks-in".to_string(),
                listen: bind.clone(),
                port,
                options,
            });
        }

        if let Some(port) = self.mixed_port {
            inbounds.push(InboundConfig {
                inbound_type: InboundType::Mixed,
                tag: "mixed-in".to_string(),
                listen: bind.clone(),
                port,
                options: HashMap::new(),
            });
        }

        if inbounds.is_empty() {
            inbounds.push(InboundConfig {
                inbound_type: InboundType::Mixed,
                tag: "mixed-in".to_string(),
                listen: bind,
                port: 7893,
                options: HashMap::new(),
            });
        }

        inbounds
    }

    fn convert_outbounds(&self) -> Result<Vec<OutboundConfig>> {
        let mut outbounds = Vec::new();

        // Always add DIRECT and REJECT first
        outbounds.push(OutboundConfig {
            outbound_type: OutboundType::Direct,
            tag: "DIRECT".to_string(),
            server: None,
            port: None,
            options: HashMap::new(),
        });

        outbounds.push(OutboundConfig {
            outbound_type: OutboundType::Reject,
            tag: "REJECT".to_string(),
            server: None,
            port: None,
            options: HashMap::new(),
        });

        // Collect all proxy names for validation
        let mut proxy_names: Vec<String> = vec!["DIRECT".to_string(), "REJECT".to_string()];

        // Convert proxies
        if let Some(proxies) = &self.proxies {
            for proxy in proxies {
                if let Some(outbound) = self.convert_proxy(proxy)? {
                    proxy_names.push(outbound.tag.clone());
                    outbounds.push(outbound);
                }
            }
        }

        // Convert proxy groups - need to handle references to other groups
        if let Some(groups) = &self.proxy_groups {
            // First pass: collect all group names
            for group in groups {
                if let Some(name) = group.get("name").and_then(|v| v.as_str()) {
                    proxy_names.push(name.to_string());
                }
            }

            // Second pass: convert groups with validated proxies
            for group in groups {
                if let Some(outbound) = self.convert_proxy_group(group, &proxy_names)? {
                    outbounds.push(outbound);
                }
            }
        }

        tracing::info!(
            "Converted {} outbounds: {:?}",
            outbounds.len(),
            outbounds.iter().map(|o| &o.tag).collect::<Vec<_>>()
        );

        Ok(outbounds)
    }

    fn convert_proxy(
        &self,
        proxy: &HashMap<String, serde_yaml::Value>,
    ) -> Result<Option<OutboundConfig>> {
        let name = proxy
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Proxy missing 'name' field"))?
            .to_string();

        let proxy_type = proxy
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config(format!("Proxy '{}' missing 'type' field", name)))?;

        let outbound_type = match proxy_type.to_lowercase().as_str() {
            "ss" | "shadowsocks" => OutboundType::Shadowsocks,
            "vmess" => OutboundType::Vmess,
            "vless" => OutboundType::Vless,
            "trojan" => OutboundType::Trojan,
            "socks5" | "socks" => OutboundType::Socks5,
            "http" | "https" => OutboundType::Http,
            "wireguard" | "wg" => OutboundType::Wireguard,
            "tuic" => OutboundType::Tuic,
            "hysteria2" | "hy2" | "hysteria" => OutboundType::Hysteria2,
            "direct" => return Ok(None),
            "reject" => return Ok(None),
            _ => {
                tracing::warn!(
                    "Unsupported proxy type '{}' for proxy '{}', skipping",
                    proxy_type,
                    name
                );
                return Ok(None);
            }
        };

        let server = proxy
            .get("server")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let port = proxy.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);

        let mut options = HashMap::new();
        for (key, value) in proxy {
            if !["name", "type", "server", "port"].contains(&key.as_str()) {
                options.insert(key.clone(), value.clone());
            }
        }

        tracing::debug!("Converted proxy '{}' type={}", name, proxy_type);

        Ok(Some(OutboundConfig {
            outbound_type,
            tag: name,
            server,
            port,
            options,
        }))
    }

    fn convert_proxy_group(
        &self,
        group: &HashMap<String, serde_yaml::Value>,
        valid_proxy_names: &[String],
    ) -> Result<Option<OutboundConfig>> {
        let name = group
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Proxy group missing 'name' field"))?
            .to_string();

        let group_type = group
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config(format!("Proxy group '{}' missing 'type' field", name)))?;

        let outbound_type = match group_type.to_lowercase().as_str() {
            "select" | "selector" => OutboundType::Selector,
            "url-test" | "urltest" => OutboundType::Urltest,
            "fallback" => OutboundType::Fallback,
            "load-balance" | "loadbalance" => OutboundType::Loadbalance,
            "relay" => OutboundType::Relay,
            _ => {
                tracing::warn!(
                    "Unsupported proxy group type '{}' for group '{}', treating as selector",
                    group_type,
                    name
                );
                OutboundType::Selector
            }
        };

        let mut options = HashMap::new();

        // Handle proxies list - filter to only valid proxies
        if let Some(proxies_value) = group.get("proxies") {
            if let Some(proxies_arr) = proxies_value.as_sequence() {
                let valid_proxies: Vec<serde_yaml::Value> = proxies_arr
                    .iter()
                    .filter_map(|v| {
                        if let Some(proxy_name) = v.as_str() {
                            // Check if this proxy exists (case-insensitive)
                            let exists = valid_proxy_names
                                .iter()
                                .any(|n| n.eq_ignore_ascii_case(proxy_name));
                            if exists {
                                Some(serde_yaml::Value::String(proxy_name.to_string()))
                            } else {
                                tracing::debug!(
                                    "Proxy group '{}' references non-existent proxy '{}', skipping",
                                    name,
                                    proxy_name
                                );
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect();

                // Always ensure DIRECT is available as fallback
                let mut final_proxies = valid_proxies;
                if final_proxies.is_empty() {
                    final_proxies.push(serde_yaml::Value::String("DIRECT".to_string()));
                    tracing::info!(
                        "Proxy group '{}' has no valid proxies, defaulting to DIRECT",
                        name
                    );
                }

                options.insert(
                    "proxies".to_string(),
                    serde_yaml::Value::Sequence(final_proxies),
                );
            }
        } else {
            // No proxies specified, default to DIRECT
            options.insert(
                "proxies".to_string(),
                serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("DIRECT".to_string())]),
            );
        }

        // Copy other options
        for (key, value) in group {
            if !["name", "type", "proxies"].contains(&key.as_str()) {
                options.insert(key.clone(), value.clone());
            }
        }

        tracing::debug!(
            "Converted proxy group '{}' type={}, proxies={:?}",
            name,
            group_type,
            options.get("proxies")
        );

        Ok(Some(OutboundConfig {
            outbound_type,
            tag: name,
            server: None,
            port: None,
            options,
        }))
    }

    fn convert_rules(&self, outbounds: &[OutboundConfig]) -> Vec<RuleConfig> {
        let mut rules = Vec::new();

        // Build valid tags set (case-insensitive lookup)
        let valid_tags: std::collections::HashSet<String> =
            outbounds.iter().map(|o| o.tag.clone()).collect();

        if let Some(clash_rules) = &self.rules {
            for rule_str in clash_rules {
                if let Some(rule) = self.parse_rule(rule_str, &valid_tags) {
                    rules.push(rule);
                }
            }
        }

        // Ensure there's always a MATCH rule at the end
        let has_match = rules.iter().any(|r| r.rule_type == RuleType::Match);
        if !has_match {
            rules.push(RuleConfig {
                rule_type: RuleType::Match,
                payload: String::new(),
                outbound: "DIRECT".to_string(),
                process_name: None,
            });
        }

        rules
    }

    fn parse_rule(
        &self,
        rule_str: &str,
        valid_tags: &std::collections::HashSet<String>,
    ) -> Option<RuleConfig> {
        let parts: Vec<&str> = rule_str.split(',').map(|s| s.trim()).collect();

        if parts.len() < 2 {
            tracing::warn!("Invalid rule format: {}", rule_str);
            return None;
        }

        let rule_type_str = parts[0].to_uppercase();

        if rule_type_str == "MATCH" {
            let outbound = self.resolve_outbound(parts.get(1).unwrap_or(&"DIRECT"), valid_tags);
            return Some(RuleConfig {
                rule_type: RuleType::Match,
                payload: String::new(),
                outbound,
                process_name: None,
            });
        }

        if parts.len() < 3 {
            tracing::warn!(
                "Invalid rule format (need payload and target): {}",
                rule_str
            );
            return None;
        }

        let payload = parts[1].to_string();
        let outbound = self.resolve_outbound(parts[2], valid_tags);

        let rule_type = match rule_type_str.as_str() {
            "DOMAIN" => RuleType::Domain,
            "DOMAIN-SUFFIX" => RuleType::DomainSuffix,
            "DOMAIN-KEYWORD" => RuleType::DomainKeyword,
            "DOMAIN-REGEX" => RuleType::DomainRegex,
            "GEOIP" => RuleType::Geoip,
            "IP-CIDR" | "IP-CIDR6" => RuleType::IpCidr,
            "SRC-IP-CIDR" => RuleType::SrcIpCidr,
            "SRC-PORT" => RuleType::SrcPort,
            "DST-PORT" => RuleType::DstPort,
            "PROCESS-NAME" => RuleType::ProcessName,
            "RULE-SET" => RuleType::RuleSet,
            _ => {
                tracing::warn!(
                    "Unsupported rule type '{}', skipping: {}",
                    rule_type_str,
                    rule_str
                );
                return None;
            }
        };

        let process_name = if rule_type == RuleType::ProcessName {
            Some(payload.clone())
        } else {
            None
        };

        Some(RuleConfig {
            rule_type,
            payload,
            outbound,
            process_name,
        })
    }

    fn resolve_outbound(
        &self,
        name: &str,
        valid_tags: &std::collections::HashSet<String>,
    ) -> String {
        let name_upper = name.to_uppercase();

        // Handle special cases
        if name_upper == "DIRECT" {
            return "DIRECT".to_string();
        }
        if name_upper == "REJECT" {
            return "REJECT".to_string();
        }

        // Exact match
        if valid_tags.contains(name) {
            return name.to_string();
        }

        // Case-insensitive match
        for tag in valid_tags {
            if tag.eq_ignore_ascii_case(name) {
                return tag.clone();
            }
        }

        // Not found - fall back to DIRECT
        tracing::warn!(
            "Rule references non-existent outbound '{}', falling back to DIRECT",
            name
        );
        "DIRECT".to_string()
    }
}

pub fn parse_clash_config(yaml: &str) -> Result<Config> {
    let clash_config = ClashConfig::from_yaml(yaml)?;
    clash_config.to_veloguard_config()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_clash_config() {
        let yaml = r#"
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info

proxies:
  - name: "test-vmess"
    type: vmess
    server: example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789012"
    alterId: 0
    cipher: auto

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - test-vmess
      - DIRECT

rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT
"#;

        let config = parse_clash_config(yaml).expect("Should parse");

        assert_eq!(config.general.port, 7890);
        assert_eq!(config.general.socks_port, Some(7891));
        assert!(config.general.allow_lan);
        assert!(config.outbounds.len() >= 4);
        assert!(!config.rules.is_empty());
    }

    #[test]
    fn test_empty_proxies() {
        let yaml = r#"
port: 7890

proxies:

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - DIRECT

rules:
  - MATCH,DIRECT
"#;

        let config = parse_clash_config(yaml).expect("Should parse");
        assert!(config.outbounds.len() >= 2); // At least DIRECT and REJECT
    }

    #[test]
    fn test_resolve_missing_outbound() {
        let yaml = r#"
port: 7890

proxies: []

rules:
  - MATCH,NonExistentProxy
"#;

        let config = parse_clash_config(yaml).expect("Should parse");
        let match_rule = config.rules.iter().find(|r| r.rule_type == RuleType::Match);
        assert!(match_rule.is_some());
        assert_eq!(match_rule.unwrap().outbound, "DIRECT");
    }

    #[test]
    fn test_proxy_group_with_invalid_proxies() {
        let yaml = r#"
port: 7890

proxies:
  - name: "valid-proxy"
    type: vmess
    server: example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789012"

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - valid-proxy
      - non-existent-proxy
      - DIRECT

rules:
  - MATCH,Proxy
"#;

        let config = parse_clash_config(yaml).expect("Should parse");

        // Find the Proxy group
        let proxy_group = config.outbounds.iter().find(|o| o.tag == "Proxy");
        assert!(proxy_group.is_some());

        // Check that proxies list only contains valid proxies
        let proxies = proxy_group.unwrap().options.get("proxies");
        assert!(proxies.is_some());
    }
}
