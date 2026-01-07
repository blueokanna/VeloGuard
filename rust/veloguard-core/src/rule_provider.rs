use crate::error::{Error, Result};
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleProviderType {
    Http,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleProviderBehavior {
    Domain,
    #[serde(alias = "ipcidr")]
    IpCidr,
    Classical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProviderConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: RuleProviderType,
    pub behavior: RuleProviderBehavior,
    pub url: Option<String>,
    pub path: Option<String>,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    86400
}

#[derive(Debug, Clone)]
pub enum CompiledRuleEntry {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(Regex),
    IpCidr(IpNet),
    Classical {
        rule_type: ClassicalRuleType,
        pattern: String,
        regex: Option<Regex>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicalRuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    IpCidr,
    SrcIpCidr,
}

pub struct RuleProvider {
    config: RuleProviderConfig,
    rules: RwLock<Vec<CompiledRuleEntry>>,
    last_update: RwLock<Option<Instant>>,
}

impl RuleProvider {
    pub fn new(config: RuleProviderConfig) -> Self {
        Self {
            config,
            rules: RwLock::new(Vec::new()),
            last_update: RwLock::new(None),
        }
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn behavior(&self) -> RuleProviderBehavior {
        self.config.behavior
    }

    pub async fn load(&self) -> Result<()> {
        let content = match self.config.provider_type {
            RuleProviderType::File => self.load_from_file().await?,
            RuleProviderType::Http => self.load_from_http().await?,
        };

        let rules = self.parse_rules(&content)?;
        
        let mut rules_guard = self.rules.write().await;
        *rules_guard = rules;
        
        let mut last_update = self.last_update.write().await;
        *last_update = Some(Instant::now());
        
        tracing::info!(
            "Rule provider '{}' loaded {} rules",
            self.config.name,
            rules_guard.len()
        );
        
        Ok(())
    }

    async fn load_from_file(&self) -> Result<String> {
        let path = self.config.path.as_ref().ok_or_else(|| {
            Error::config("File rule provider requires 'path' field")
        })?;
        
        tokio::fs::read_to_string(path).await.map_err(|e| {
            Error::config(format!("Failed to read rule file '{}': {}", path, e))
        })
    }

    async fn load_from_http(&self) -> Result<String> {
        let url = self.config.url.as_ref().ok_or_else(|| {
            Error::config("HTTP rule provider requires 'url' field")
        })?;

        if let Some(path) = &self.config.path {
            if Path::new(path).exists() {
                if let Ok(content) = tokio::fs::read_to_string(path).await {
                    return Ok(content);
                }
            }
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::network(format!("Failed to create HTTP client: {}", e)))?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::network(format!("Failed to fetch rules from '{}': {}", url, e)))?;

        if !response.status().is_success() {
            return Err(Error::network(format!(
                "HTTP request failed with status: {}",
                response.status()
            )));
        }

        let content = response
            .text()
            .await
            .map_err(|e| Error::network(format!("Failed to read response body: {}", e)))?;

        if let Some(path) = &self.config.path {
            if let Some(parent) = Path::new(path).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            let _ = tokio::fs::write(path, &content).await;
        }

        Ok(content)
    }

    pub fn parse_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        match self.config.behavior {
            RuleProviderBehavior::Domain => self.parse_domain_rules(content),
            RuleProviderBehavior::IpCidr => self.parse_ipcidr_rules(content),
            RuleProviderBehavior::Classical => self.parse_classical_rules(content),
        }
    }

    fn parse_domain_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        let mut rules = Vec::new();
        
        if let Ok(yaml_content) = serde_yaml::from_str::<serde_yaml::Value>(content) {
            if let Some(payload) = yaml_content.get("payload").and_then(|v| v.as_sequence()) {
                for item in payload {
                    if let Some(domain) = item.as_str() {
                        rules.push(self.parse_domain_entry(domain));
                    }
                }
                return Ok(rules);
            }
        }
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            rules.push(self.parse_domain_entry(line));
        }
        
        Ok(rules)
    }

    fn parse_domain_entry(&self, entry: &str) -> CompiledRuleEntry {
        let entry = entry.trim_start_matches('+').trim_start_matches('.');
        
        if let Some(keyword) = entry.strip_prefix("keyword:") {
            CompiledRuleEntry::DomainKeyword(keyword.to_string())
        } else if let Some(pattern) = entry.strip_prefix("regexp:") {
            if let Ok(regex) = Regex::new(pattern) {
                CompiledRuleEntry::DomainRegex(regex)
            } else {
                CompiledRuleEntry::Domain(entry.to_string())
            }
        } else if let Some(pattern) = entry.strip_prefix("regex:") {
            if let Ok(regex) = Regex::new(pattern) {
                CompiledRuleEntry::DomainRegex(regex)
            } else {
                CompiledRuleEntry::Domain(entry.to_string())
            }
        } else if let Some(domain) = entry.strip_prefix("full:") {
            CompiledRuleEntry::Domain(domain.to_string())
        } else {
            CompiledRuleEntry::DomainSuffix(entry.to_string())
        }
    }

    fn parse_ipcidr_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        let mut rules = Vec::new();
        
        if let Ok(yaml_content) = serde_yaml::from_str::<serde_yaml::Value>(content) {
            if let Some(payload) = yaml_content.get("payload").and_then(|v| v.as_sequence()) {
                for item in payload {
                    if let Some(cidr) = item.as_str() {
                        if let Ok(network) = cidr.parse::<IpNet>() {
                            rules.push(CompiledRuleEntry::IpCidr(network));
                        }
                    }
                }
                return Ok(rules);
            }
        }
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Ok(network) = line.parse::<IpNet>() {
                rules.push(CompiledRuleEntry::IpCidr(network));
            }
        }
        
        Ok(rules)
    }

    fn parse_classical_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        let mut rules = Vec::new();
        
        if let Ok(yaml_content) = serde_yaml::from_str::<serde_yaml::Value>(content) {
            if let Some(payload) = yaml_content.get("payload").and_then(|v| v.as_sequence()) {
                for item in payload {
                    if let Some(rule_str) = item.as_str() {
                        if let Some(entry) = self.parse_classical_entry(rule_str) {
                            rules.push(entry);
                        }
                    }
                }
                return Ok(rules);
            }
        }
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some(entry) = self.parse_classical_entry(line) {
                rules.push(entry);
            }
        }
        
        Ok(rules)
    }

    fn parse_classical_entry(&self, entry: &str) -> Option<CompiledRuleEntry> {
        let parts: Vec<&str> = entry.splitn(2, ',').collect();
        if parts.len() < 2 {
            return None;
        }
        
        let rule_type_str = parts[0].trim().to_uppercase();
        let pattern = parts[1].trim().to_string();
        
        match rule_type_str.as_str() {
            "DOMAIN" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::Domain,
                pattern,
                regex: None,
            }),
            "DOMAIN-SUFFIX" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::DomainSuffix,
                pattern,
                regex: None,
            }),
            "DOMAIN-KEYWORD" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::DomainKeyword,
                pattern,
                regex: None,
            }),
            "DOMAIN-REGEX" => {
                let regex = Regex::new(&pattern).ok();
                Some(CompiledRuleEntry::Classical {
                    rule_type: ClassicalRuleType::DomainRegex,
                    pattern,
                    regex,
                })
            }
            "IP-CIDR" | "IP-CIDR6" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::IpCidr,
                pattern,
                regex: None,
            }),
            "SRC-IP-CIDR" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::SrcIpCidr,
                pattern,
                regex: None,
            }),
            _ => None,
        }
    }

    pub async fn matches(&self, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        let rules = self.rules.read().await;
        
        for rule in rules.iter() {
            if self.matches_entry(rule, domain, ip) {
                return true;
            }
        }
        
        false
    }

    pub fn matches_entry(&self, entry: &CompiledRuleEntry, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        match entry {
            CompiledRuleEntry::Domain(pattern) => {
                domain.is_some_and(|d| d.eq_ignore_ascii_case(pattern))
            }
            CompiledRuleEntry::DomainSuffix(pattern) => {
                domain.is_some_and(|d| {
                    let d_lower = d.to_lowercase();
                    let p_lower = pattern.to_lowercase();
                    d_lower == p_lower || d_lower.ends_with(&format!(".{}", p_lower))
                })
            }
            CompiledRuleEntry::DomainKeyword(pattern) => {
                domain.is_some_and(|d| {
                    d.to_lowercase().contains(&pattern.to_lowercase())
                })
            }
            CompiledRuleEntry::DomainRegex(regex) => {
                domain.is_some_and(|d| regex.is_match(d))
            }
            CompiledRuleEntry::IpCidr(network) => {
                ip.is_some_and(|addr| network.contains(&addr))
            }
            CompiledRuleEntry::Classical { rule_type, pattern, regex } => {
                self.matches_classical(rule_type, pattern, regex.as_ref(), domain, ip)
            }
        }
    }

    fn matches_classical(
        &self,
        rule_type: &ClassicalRuleType,
        pattern: &str,
        regex: Option<&Regex>,
        domain: Option<&str>,
        ip: Option<IpAddr>,
    ) -> bool {
        match rule_type {
            ClassicalRuleType::Domain => {
                domain.is_some_and(|d| d.eq_ignore_ascii_case(pattern))
            }
            ClassicalRuleType::DomainSuffix => {
                domain.is_some_and(|d| {
                    let d_lower = d.to_lowercase();
                    let p_lower = pattern.to_lowercase();
                    d_lower == p_lower || d_lower.ends_with(&format!(".{}", p_lower))
                })
            }
            ClassicalRuleType::DomainKeyword => {
                domain.is_some_and(|d| {
                    d.to_lowercase().contains(&pattern.to_lowercase())
                })
            }
            ClassicalRuleType::DomainRegex => {
                if let Some(regex) = regex {
                    domain.is_some_and(|d| regex.is_match(d))
                } else {
                    false
                }
            }
            ClassicalRuleType::IpCidr | ClassicalRuleType::SrcIpCidr => {
                if let Ok(network) = pattern.parse::<IpNet>() {
                    ip.is_some_and(|addr| network.contains(&addr))
                } else {
                    false
                }
            }
        }
    }

    pub async fn update(&self) -> Result<()> {
        self.load().await
    }

    pub async fn needs_update(&self) -> bool {
        let last_update = self.last_update.read().await;
        match *last_update {
            Some(time) => time.elapsed() > Duration::from_secs(self.config.interval),
            None => true,
        }
    }

    pub async fn update_if_needed(&self) -> Result<bool> {
        if self.needs_update().await {
            self.update().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn provider_type(&self) -> RuleProviderType {
        self.config.provider_type
    }

    pub fn interval(&self) -> u64 {
        self.config.interval
    }

    pub async fn rule_count(&self) -> usize {
        self.rules.read().await.len()
    }

    pub async fn last_update_time(&self) -> Option<Instant> {
        *self.last_update.read().await
    }
}

pub struct RuleProviderManager {
    providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
}

impl RuleProviderManager {
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_provider(&self, config: RuleProviderConfig) -> Result<()> {
        let name = config.name.clone();
        let provider = Arc::new(RuleProvider::new(config));
        provider.load().await?;
        
        let mut providers = self.providers.write().await;
        providers.insert(name, provider);
        
        Ok(())
    }

    pub async fn remove_provider(&self, name: &str) {
        let mut providers = self.providers.write().await;
        providers.remove(name);
    }

    pub async fn get_provider(&self, name: &str) -> Option<Arc<RuleProvider>> {
        let providers = self.providers.read().await;
        providers.get(name).cloned()
    }

    pub async fn matches(&self, provider_name: &str, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        let providers = self.providers.read().await;
        if let Some(provider) = providers.get(provider_name) {
            provider.matches(domain, ip).await
        } else {
            false
        }
    }

    pub async fn update_all(&self) -> Vec<Result<bool>> {
        let providers = self.providers.read().await;
        let mut results = Vec::new();
        
        for provider in providers.values() {
            results.push(provider.update_if_needed().await);
        }
        
        results
    }

    pub async fn reload_provider(&self, name: &str) -> Result<()> {
        let providers = self.providers.read().await;
        if let Some(provider) = providers.get(name) {
            provider.load().await
        } else {
            Err(Error::config(format!("Rule provider '{}' not found", name)))
        }
    }

    pub async fn get_all_providers(&self) -> Vec<Arc<RuleProvider>> {
        let providers = self.providers.read().await;
        providers.values().cloned().collect()
    }

    pub async fn provider_count(&self) -> usize {
        self.providers.read().await.len()
    }

    pub async fn get_provider_names(&self) -> Vec<String> {
        let providers = self.providers.read().await;
        providers.keys().cloned().collect()
    }
}

impl Default for RuleProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RuleProviderManager {
    fn clone(&self) -> Self {
        Self {
            providers: Arc::clone(&self.providers),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_entry_suffix() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });
        
        let entry = provider.parse_domain_entry("google.com");
        assert!(matches!(entry, CompiledRuleEntry::DomainSuffix(_)));
    }

    #[test]
    fn test_parse_domain_entry_full() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });
        
        let entry = provider.parse_domain_entry("full:www.google.com");
        assert!(matches!(entry, CompiledRuleEntry::Domain(_)));
    }

    #[test]
    fn test_parse_domain_entry_keyword() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });
        
        let entry = provider.parse_domain_entry("keyword:google");
        assert!(matches!(entry, CompiledRuleEntry::DomainKeyword(_)));
    }

    #[test]
    fn test_matches_domain_suffix() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });
        
        let entry = CompiledRuleEntry::DomainSuffix("google.com".to_string());
        assert!(provider.matches_entry(&entry, Some("www.google.com"), None));
        assert!(provider.matches_entry(&entry, Some("google.com"), None));
        assert!(!provider.matches_entry(&entry, Some("notgoogle.com"), None));
    }

    #[test]
    fn test_matches_ip_cidr() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::IpCidr,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });
        
        let network: IpNet = "192.168.0.0/16".parse().unwrap();
        let entry = CompiledRuleEntry::IpCidr(network);
        
        assert!(provider.matches_entry(&entry, None, Some("192.168.1.1".parse().unwrap())));
        assert!(!provider.matches_entry(&entry, None, Some("10.0.0.1".parse().unwrap())));
    }
}
