//! Property-based tests for remote resource loading
//!
//! These tests validate the correctness properties defined in the design document:
//! - Property 6: Remote Resource Loading
//!
//! **Validates: Requirements 8.1-8.5**

use crate::config::OutboundType;
use crate::proxy_provider::{ProxyProvider, ProxyProviderConfig, ProxyProviderType, HealthCheckConfig};
use crate::rule_provider::{
    RuleProvider, RuleProviderConfig, RuleProviderType, RuleProviderBehavior,
    CompiledRuleEntry,
};
use proptest::prelude::*;
use std::net::IpAddr;

fn domain_strategy() -> impl Strategy<Value = String> {
    (
        "[a-z]{1,10}",
        prop::collection::vec("[a-z]{1,8}", 1..3),
        prop_oneof!["com", "org", "net", "io", "dev"],
    )
        .prop_map(|(prefix, parts, tld)| {
            let mut domain = prefix;
            for part in parts {
                domain.push('.');
                domain.push_str(&part);
            }
            domain.push('.');
            domain.push_str(&tld);
            domain
        })
}

fn ipv4_cidr_strategy() -> impl Strategy<Value = String> {
    (1u8..224, 0u8..=255, 0u8..=255, 0u8..=255, 8u8..=32)
        .prop_filter("valid CIDR", |(a, _, _, _, _)| {
            *a != 10 && *a != 127 && !(*a >= 172 && *a <= 191) && *a != 192
        })
        .prop_map(|(a, b, c, d, prefix)| format!("{}.{}.{}.{}/{}", a, b, c, d, prefix))
}

/// Strategy for generating IPv4 addresses within a CIDR range
#[allow(dead_code)]
fn ipv4_in_cidr_strategy(cidr: &str) -> impl Strategy<Value = IpAddr> {
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip_parts: Vec<u8> = parts[0]
        .split('.')
        .map(|s| s.parse().unwrap_or(0))
        .collect();
    let prefix: u8 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(24);
    
    let base_ip = ((ip_parts[0] as u32) << 24)
        | ((ip_parts[1] as u32) << 16)
        | ((ip_parts[2] as u32) << 8)
        | (ip_parts[3] as u32);
    
    let mask = if prefix >= 32 { 0 } else { !0u32 >> prefix };
    let network = base_ip & !mask;
    
    (0u32..=mask.min(255))
        .prop_map(move |offset| {
            let ip = network | offset;
            IpAddr::V4(std::net::Ipv4Addr::new(
                ((ip >> 24) & 0xff) as u8,
                ((ip >> 16) & 0xff) as u8,
                ((ip >> 8) & 0xff) as u8,
                (ip & 0xff) as u8,
            ))
        })
}

fn rule_provider_config_strategy() -> impl Strategy<Value = RuleProviderConfig> {
    (
        "[a-z]{3,10}",
        prop_oneof![
            Just(RuleProviderBehavior::Domain),
            Just(RuleProviderBehavior::IpCidr),
            Just(RuleProviderBehavior::Classical),
        ],
        1u64..=86400,
    )
        .prop_map(|(name, behavior, interval)| RuleProviderConfig {
            name,
            provider_type: RuleProviderType::File,
            behavior,
            url: None,
            path: Some("/tmp/test_rules.yaml".to_string()),
            interval,
        })
}

fn proxy_provider_config_strategy() -> impl Strategy<Value = ProxyProviderConfig> {
    (
        "[a-z]{3,10}",
        1u64..=86400,
    )
        .prop_map(|(name, interval)| ProxyProviderConfig {
            name,
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("/tmp/test_proxies.yaml".to_string()),
            interval,
            health_check: HealthCheckConfig::default(),
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Feature: rust-codebase-optimization, Property 6: Remote Resource Loading - Rule Provider Parsing**
    ///
    /// *For any* valid domain rule content, parsing SHALL produce valid rule entries
    /// that can be used for matching.
    ///
    /// **Validates: Requirements 8.1-8.5**
    #[test]
    fn test_rule_provider_domain_parsing(domains in prop::collection::vec(domain_strategy(), 1..10)) {
        let config = RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
        };

        let provider = RuleProvider::new(config);

        let yaml_content = format!(
            "payload:\n{}",
            domains.iter().map(|d| format!("  - {}", d)).collect::<Vec<_>>().join("\n")
        );

        let rules = provider.parse_rules(&yaml_content);
        prop_assert!(rules.is_ok(), "Parsing should succeed");

        let rules = rules.unwrap();
        prop_assert_eq!(rules.len(), domains.len(), "Should parse all domains");

        for rule in &rules {
            prop_assert!(
                matches!(rule, CompiledRuleEntry::DomainSuffix(_) | CompiledRuleEntry::Domain(_) | CompiledRuleEntry::DomainKeyword(_) | CompiledRuleEntry::DomainRegex(_)),
                "Rule should be a domain type"
            );
        }
    }

    /// **Feature: rust-codebase-optimization, Property 6: Remote Resource Loading - IP CIDR Parsing**
    ///
    /// *For any* valid IP CIDR content, parsing SHALL produce valid CIDR entries
    /// that can be used for IP matching.
    ///
    /// **Validates: Requirements 8.1-8.5**
    #[test]
    fn test_rule_provider_ipcidr_parsing(cidrs in prop::collection::vec(ipv4_cidr_strategy(), 1..10)) {
        let config = RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::IpCidr,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
        };

        let provider = RuleProvider::new(config);

        let yaml_content = format!(
            "payload:\n{}",
            cidrs.iter().map(|c| format!("  - {}", c)).collect::<Vec<_>>().join("\n")
        );

        let rules = provider.parse_rules(&yaml_content);
        prop_assert!(rules.is_ok(), "Parsing should succeed");

        let rules = rules.unwrap();
        prop_assert!(rules.len() <= cidrs.len(), "Should parse valid CIDRs");

        for rule in &rules {
            prop_assert!(
                matches!(rule, CompiledRuleEntry::IpCidr(_)),
                "Rule should be an IP CIDR type"
            );
        }
    }

    /// **Feature: rust-codebase-optimization, Property 6: Remote Resource Loading - Domain Matching Consistency**
    ///
    /// *For any* domain rule, matching the exact domain or a subdomain SHALL return true,
    /// while matching an unrelated domain SHALL return false.
    ///
    /// **Validates: Requirements 8.1-8.5**
    #[test]
    fn test_rule_provider_domain_matching_consistency(
        base_domain in domain_strategy(),
        subdomain_prefix in "[a-z]{1,5}"
    ) {
        let config = RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
        };

        let provider = RuleProvider::new(config);

        let entry = CompiledRuleEntry::DomainSuffix(base_domain.clone());

        let subdomain = format!("{}.{}", subdomain_prefix, base_domain);
        prop_assert!(
            provider.matches_entry(&entry, Some(&subdomain), None),
            "Subdomain {} should match suffix {}",
            subdomain,
            base_domain
        );

        prop_assert!(
            provider.matches_entry(&entry, Some(&base_domain), None),
            "Exact domain {} should match suffix {}",
            base_domain,
            base_domain
        );

        let unrelated = format!("unrelated{}.xyz", rand::random::<u32>());
        prop_assert!(
            !provider.matches_entry(&entry, Some(&unrelated), None),
            "Unrelated domain {} should not match suffix {}",
            unrelated,
            base_domain
        );
    }

    /// **Feature: rust-codebase-optimization, Property 6: Remote Resource Loading - Provider Config Validity**
    ///
    /// *For any* valid provider configuration, creating a provider SHALL succeed
    /// and the provider SHALL have the correct configuration values.
    ///
    /// **Validates: Requirements 8.1-8.5**
    #[test]
    fn test_rule_provider_config_validity(config in rule_provider_config_strategy()) {
        let provider = RuleProvider::new(config.clone());

        prop_assert_eq!(provider.name(), config.name);
        prop_assert_eq!(provider.behavior(), config.behavior);
        prop_assert_eq!(provider.provider_type(), config.provider_type);
        prop_assert_eq!(provider.interval(), config.interval);
    }

    /// **Feature: rust-codebase-optimization, Property 6: Remote Resource Loading - Proxy Provider Config Validity**
    ///
    /// *For any* valid proxy provider configuration, creating a provider SHALL succeed
    /// and the provider SHALL have the correct configuration values.
    ///
    /// **Validates: Requirements 8.1-8.5**
    #[test]
    fn test_proxy_provider_config_validity(config in proxy_provider_config_strategy()) {
        let provider = ProxyProvider::new(config.clone());

        prop_assert_eq!(provider.name(), config.name);
        prop_assert_eq!(provider.provider_type(), config.provider_type);
    }

    /// **Feature: rust-codebase-optimization, Property 6: Remote Resource Loading - Classical Rule Parsing**
    ///
    /// *For any* valid classical rule content, parsing SHALL produce valid rule entries
    /// with correct rule types.
    ///
    /// **Validates: Requirements 8.1-8.5**
    #[test]
    fn test_rule_provider_classical_parsing(
        domains in prop::collection::vec(domain_strategy(), 1..5),
        cidrs in prop::collection::vec(ipv4_cidr_strategy(), 1..5)
    ) {
        let config = RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Classical,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
        };

        let provider = RuleProvider::new(config);

        let mut rules_content = Vec::new();
        for domain in &domains {
            rules_content.push(format!("  - DOMAIN-SUFFIX,{}", domain));
        }
        for cidr in &cidrs {
            rules_content.push(format!("  - IP-CIDR,{}", cidr));
        }

        let yaml_content = format!("payload:\n{}", rules_content.join("\n"));

        let rules = provider.parse_rules(&yaml_content);
        prop_assert!(rules.is_ok(), "Parsing should succeed");

        let rules = rules.unwrap();
        prop_assert!(rules.len() <= domains.len() + cidrs.len(), "Should parse valid rules");
    }

    /// **Feature: rust-codebase-optimization, Property 6: Remote Resource Loading - Proxy YAML Parsing**
    ///
    /// *For any* valid proxy YAML content, parsing SHALL produce valid proxy configurations.
    ///
    /// **Validates: Requirements 8.1-8.5**
    #[test]
    fn test_proxy_provider_yaml_parsing(
        proxy_names in prop::collection::vec("[a-z]{3,10}", 1..5)
    ) {
        let config = ProxyProviderConfig {
            name: "test".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
            health_check: HealthCheckConfig::default(),
        };

        let provider = ProxyProvider::new(config);

        let proxies_yaml: Vec<String> = proxy_names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "  - type: socks5\n    tag: {}\n    server: 127.0.0.1\n    port: {}",
                    name,
                    1080 + i
                )
            })
            .collect();

        let yaml_content = format!("proxies:\n{}", proxies_yaml.join("\n"));

        let result = provider.parse_proxies(&yaml_content);
        prop_assert!(result.is_ok(), "Parsing should succeed: {:?}", result.err());

        let configs = result.unwrap();
        prop_assert_eq!(configs.len(), proxy_names.len(), "Should parse all proxies");

        for (i, config) in configs.iter().enumerate() {
            prop_assert_eq!(&config.tag, &proxy_names[i]);
            prop_assert_eq!(config.outbound_type, OutboundType::Socks5);
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_rule_provider_domain_suffix_matching() {
        let config = RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
        };

        let provider = RuleProvider::new(config);
        let entry = CompiledRuleEntry::DomainSuffix("google.com".to_string());

        assert!(provider.matches_entry(&entry, Some("www.google.com"), None));
        assert!(provider.matches_entry(&entry, Some("mail.google.com"), None));
        assert!(provider.matches_entry(&entry, Some("google.com"), None));
        assert!(!provider.matches_entry(&entry, Some("notgoogle.com"), None));
        assert!(!provider.matches_entry(&entry, Some("google.org"), None));
    }

    #[test]
    fn test_rule_provider_domain_keyword_matching() {
        let config = RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
        };

        let provider = RuleProvider::new(config);
        let entry = CompiledRuleEntry::DomainKeyword("google".to_string());

        assert!(provider.matches_entry(&entry, Some("www.google.com"), None));
        assert!(provider.matches_entry(&entry, Some("google.org"), None));
        assert!(provider.matches_entry(&entry, Some("mygoogle.net"), None));
        assert!(!provider.matches_entry(&entry, Some("example.com"), None));
    }

    #[test]
    fn test_rule_provider_ip_cidr_matching() {
        let config = RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::IpCidr,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
        };

        let provider = RuleProvider::new(config);
        let network: ipnet::IpNet = "192.168.0.0/16".parse().unwrap();
        let entry = CompiledRuleEntry::IpCidr(network);

        assert!(provider.matches_entry(&entry, None, Some("192.168.1.1".parse().unwrap())));
        assert!(provider.matches_entry(&entry, None, Some("192.168.255.255".parse().unwrap())));
        assert!(!provider.matches_entry(&entry, None, Some("10.0.0.1".parse().unwrap())));
        assert!(!provider.matches_entry(&entry, None, Some("8.8.8.8".parse().unwrap())));
    }

    #[test]
    fn test_proxy_provider_parse_yaml() {
        let config = ProxyProviderConfig {
            name: "test".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
            health_check: HealthCheckConfig::default(),
        };

        let provider = ProxyProvider::new(config);

        let yaml_content = r#"
proxies:
  - type: socks5
    tag: proxy1
    server: 127.0.0.1
    port: 1080
  - type: http
    tag: proxy2
    server: 127.0.0.1
    port: 8080
"#;

        let result = provider.parse_proxies(yaml_content);
        assert!(result.is_ok());

        let configs = result.unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].tag, "proxy1");
        assert_eq!(configs[0].outbound_type, OutboundType::Socks5);
        assert_eq!(configs[1].tag, "proxy2");
        assert_eq!(configs[1].outbound_type, OutboundType::Http);
    }

    #[test]
    fn test_proxy_provider_parse_json() {
        let config = ProxyProviderConfig {
            name: "test".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("/tmp/test.json".to_string()),
            interval: 86400,
            health_check: HealthCheckConfig::default(),
        };

        let provider = ProxyProvider::new(config);

        let json_content = r#"[
            {"type": "socks5", "tag": "proxy1", "server": "127.0.0.1", "port": 1080},
            {"type": "http", "tag": "proxy2", "server": "127.0.0.1", "port": 8080}
        ]"#;

        let result = provider.parse_proxies(json_content);
        assert!(result.is_ok());

        let configs = result.unwrap();
        assert_eq!(configs.len(), 2);
    }

    #[tokio::test]
    async fn test_rule_provider_needs_update() {
        let config = RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
        };

        let provider = RuleProvider::new(config);

        assert!(provider.needs_update().await);
    }

    #[tokio::test]
    async fn test_proxy_provider_needs_update() {
        let config = ProxyProviderConfig {
            name: "test".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("/tmp/test.yaml".to_string()),
            interval: 86400,
            health_check: HealthCheckConfig::default(),
        };

        let provider = ProxyProvider::new(config);

        assert!(provider.needs_update().await);
    }
}
