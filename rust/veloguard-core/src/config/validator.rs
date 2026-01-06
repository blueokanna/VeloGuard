use crate::config::*;
use crate::error::{Error, Result};

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate the entire configuration
    pub fn validate(config: &Config) -> Result<()> {
        Self::validate_general(&config.general)?;
        Self::validate_dns(&config.dns)?;
        Self::validate_inbounds(&config.inbounds)?;
        Self::validate_outbounds(&config.outbounds)?;
        Self::validate_rules(&config.rules)?;
        Self::validate_cross_references(config)?;
        Ok(())
    }

    /// Validate general configuration
    fn validate_general(general: &GeneralConfig) -> Result<()> {
        // Validate port ranges
        if general.port == 0 {
            return Err(Error::config("Invalid port: must be between 1 and 65535"));
        }

        if let Some(socks_port) = general.socks_port {
            if socks_port == 0 {
                return Err(Error::config("Invalid socks_port: must be between 1 and 65535"));
            }
        }

        if let Some(redir_port) = general.redir_port {
            if redir_port == 0 {
                return Err(Error::config("Invalid redir_port: must be between 1 and 65535"));
            }
        }

        if let Some(tproxy_port) = general.tproxy_port {
            if tproxy_port == 0 {
                return Err(Error::config("Invalid tproxy_port: must be between 1 and 65535"));
            }
        }

        if let Some(mixed_port) = general.mixed_port {
            if mixed_port == 0 {
                return Err(Error::config("Invalid mixed_port: must be between 1 and 65535"));
            }
        }

        // Validate bind address
        if general.bind_address.is_empty() {
            return Err(Error::config("bind_address cannot be empty"));
        }

        // Validate IPv6 setting doesn't conflict with bind address
        if !general.ipv6 && general.bind_address.contains(':') && !general.bind_address.starts_with('[') {
            return Err(Error::config("IPv6 bind address requires ipv6 to be enabled"));
        }

        Ok(())
    }

    /// Validate DNS configuration
    fn validate_dns(dns: &DnsConfig) -> Result<()> {
        if dns.enable {
            // Validate listen address format
            if dns.listen.is_empty() {
                return Err(Error::config("DNS listen address cannot be empty"));
            }

            for nameserver in &dns.nameservers {
                if nameserver.is_empty() {
                    return Err(Error::config("Nameserver cannot be empty"));
                }
            }

            // Validate fallback nameservers
            for nameserver in &dns.fallback {
                if nameserver.is_empty() {
                    return Err(Error::config("Fallback nameserver cannot be empty"));
                }
            }
        }

        Ok(())
    }

    /// Validate inbound configurations
    fn validate_inbounds(inbounds: &[InboundConfig]) -> Result<()> {
        if inbounds.is_empty() {
            return Err(Error::config("At least one inbound must be configured"));
        }

        let mut tags = std::collections::HashSet::new();

        for inbound in inbounds {
            // Check for duplicate tags
            if !tags.insert(&inbound.tag) {
                return Err(Error::config(format!("Duplicate inbound tag: {}", inbound.tag)));
            }

            // Validate tag
            if inbound.tag.is_empty() {
                return Err(Error::config("Inbound tag cannot be empty"));
            }

            // Validate listen address
            if inbound.listen.is_empty() {
                return Err(Error::config(format!("Inbound {} listen address cannot be empty", inbound.tag)));
            }

            // Validate port
            if inbound.port == 0 {
                return Err(Error::config(format!("Inbound {} has invalid port", inbound.tag)));
            }

            // Type-specific validation
            match inbound.inbound_type {
                InboundType::Http | InboundType::Socks5 | InboundType::Mixed => {
                    // These types are supported
                }
                InboundType::Redir | InboundType::Tproxy => {
                    // These require specific platform support
                    #[cfg(not(target_os = "linux"))]
                    {
                        return Err(Error::config(format!(
                            "Inbound type {:?} is only supported on Linux",
                            inbound.inbound_type
                        )));
                    }
                }
                InboundType::Tun => {
                }
            }
        }

        Ok(())
    }

    /// Validate outbound configurations
    fn validate_outbounds(outbounds: &[OutboundConfig]) -> Result<()> {
        if outbounds.is_empty() {
            return Err(Error::config("At least one outbound must be configured"));
        }

        let mut tags = std::collections::HashSet::new();
        let mut has_direct = false;

        for outbound in outbounds {
            // Check for duplicate tags
            if !tags.insert(&outbound.tag) {
                return Err(Error::config(format!("Duplicate outbound tag: {}", outbound.tag)));
            }

            // Validate tag
            if outbound.tag.is_empty() {
                return Err(Error::config("Outbound tag cannot be empty"));
            }

            // Check for direct outbound
            if outbound.outbound_type == OutboundType::Direct {
                has_direct = true;
            }

            // Type-specific validation
            match outbound.outbound_type {
                OutboundType::Direct | OutboundType::Reject => {
                    // Direct and Reject don't need server/port
                }
                OutboundType::Socks5 | OutboundType::Http => {
                    if outbound.server.is_none() {
                        return Err(Error::config(format!(
                            "Outbound {} requires server address",
                            outbound.tag
                        )));
                    }
                    if outbound.port.is_none() {
                        return Err(Error::config(format!(
                            "Outbound {} requires server port",
                            outbound.tag
                        )));
                    }
                }
                OutboundType::Shadowsocks | OutboundType::Vmess | OutboundType::Vless | OutboundType::Trojan | OutboundType::Wireguard | OutboundType::Tuic | OutboundType::Hysteria2 | OutboundType::Quic => {
                    if outbound.server.is_none() {
                        return Err(Error::config(format!(
                            "Outbound {} requires server address",
                            outbound.tag
                        )));
                    }
                    if outbound.port.is_none() {
                        return Err(Error::config(format!(
                            "Outbound {} requires server port",
                            outbound.tag
                        )));
                    }
                }
                // Proxy group types don't need server/port
                OutboundType::Selector | OutboundType::Urltest | 
                OutboundType::Fallback | OutboundType::Loadbalance | OutboundType::Relay => {
                    // Proxy groups reference other outbounds, no server needed
                }
            }
        }

        // Ensure there's at least one direct outbound
        if !has_direct {
            return Err(Error::config("At least one direct outbound must be configured"));
        }

        Ok(())
    }

    /// Validate routing rules
    fn validate_rules(rules: &[RuleConfig]) -> Result<()> {
        for rule in rules {
            // Validate rule type
            match rule.rule_type {
                RuleType::Domain | RuleType::DomainSuffix | RuleType::DomainKeyword | RuleType::DomainRegex => {
                    if rule.payload.is_empty() {
                        return Err(Error::config("Domain rule payload cannot be empty"));
                    }
                }
                RuleType::IpCidr | RuleType::SrcIpCidr => {
                    if rule.payload.is_empty() {
                        return Err(Error::config("IP CIDR rule payload cannot be empty"));
                    }
                }
                RuleType::Geoip => {
                    if rule.payload.is_empty() {
                        return Err(Error::config("GeoIP rule payload cannot be empty"));
                    }
                }
                RuleType::SrcPort | RuleType::DstPort => {
                    if rule.payload.is_empty() {
                        return Err(Error::config("Port rule payload cannot be empty"));
                    }
                }
                RuleType::ProcessName => {
                    if rule.payload.is_empty() {
                        return Err(Error::config("Process name rule payload cannot be empty"));
                    }
                    // Process name rules should have process_name set
                    if rule.process_name.is_none() {
                        return Err(Error::config("Process name rule requires process_name field"));
                    }
                }
                RuleType::RuleSet => {
                    // Rule-set rules reference external rule files
                    if rule.payload.is_empty() {
                        return Err(Error::config("Rule-set rule payload cannot be empty"));
                    }
                }
                RuleType::Match => {
                    // Match rule doesn't need payload
                }
            }

            // Validate outbound tag
            if rule.outbound.is_empty() {
                return Err(Error::config("Rule outbound cannot be empty"));
            }
        }

        Ok(())
    }

    /// Validate cross-references between configuration sections
    fn validate_cross_references(config: &Config) -> Result<()> {
        // Collect all outbound tags
        let outbound_tags: std::collections::HashSet<_> = config.outbounds.iter()
            .map(|o| o.tag.as_str())
            .collect();

        // Check that all rule outbound references exist
        for rule in &config.rules {
            if !outbound_tags.contains(rule.outbound.as_str()) {
                return Err(Error::config(format!(
                    "Rule references non-existent outbound: {}",
                    rule.outbound
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = Config {
            general: GeneralConfig::default(),
            dns: DnsConfig::default(),
            inbounds: vec![InboundConfig {
                inbound_type: InboundType::Http,
                tag: "http-in".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 7890,
                options: Default::default(),
            }],
            outbounds: vec![
                OutboundConfig {
                    outbound_type: OutboundType::Direct,
                    tag: "direct".to_string(),
                    server: None,
                    port: None,
                    options: Default::default(),
                },
                OutboundConfig {
                    outbound_type: OutboundType::Socks5,
                    tag: "proxy".to_string(),
                    server: Some("127.0.0.1".to_string()),
                    port: Some(1080),
                    options: Default::default(),
                },
            ],
            rules: vec![RuleConfig {
                rule_type: RuleType::Match,
                payload: "".to_string(),
                outbound: "direct".to_string(),
                process_name: None,
            }],
        };

        assert!(ConfigValidator::validate(&config).is_ok());
    }

    #[test]
    fn test_invalid_config_no_inbound() {
        let config = Config {
            general: GeneralConfig::default(),
            dns: DnsConfig::default(),
            inbounds: vec![],
            outbounds: vec![OutboundConfig {
                outbound_type: OutboundType::Direct,
                tag: "direct".to_string(),
                server: None,
                port: None,
                options: Default::default(),
            }],
            rules: vec![],
        };

        assert!(ConfigValidator::validate(&config).is_err());
    }

    #[test]
    fn test_invalid_config_no_direct_outbound() {
        let config = Config {
            general: GeneralConfig::default(),
            dns: DnsConfig::default(),
            inbounds: vec![InboundConfig {
                inbound_type: InboundType::Http,
                tag: "http-in".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 7890,
                options: Default::default(),
            }],
            outbounds: vec![OutboundConfig {
                outbound_type: OutboundType::Socks5,
                tag: "proxy".to_string(),
                server: Some("127.0.0.1".to_string()),
                port: Some(1080),
                options: Default::default(),
            }],
            rules: vec![],
        };

        assert!(ConfigValidator::validate(&config).is_err());
    }
}
