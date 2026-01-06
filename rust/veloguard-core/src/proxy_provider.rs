use crate::config::{OutboundConfig, OutboundType};
use crate::error::{Error, Result};
use crate::outbound::{
    DirectOutbound, HttpOutbound, Hysteria2Outbound, OutboundProxy, RejectOutbound,
    ShadowsocksOutbound, Socks5Outbound, TrojanOutbound, TuicOutbound, VlessOutbound,
    VmessOutbound, WireguardOutbound,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProviderType {
    Http,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyProviderConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: ProxyProviderType,
    pub url: Option<String>,
    pub path: Option<String>,
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default)]
    pub health_check: HealthCheckConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default = "default_health_check_enabled")]
    pub enable: bool,
    #[serde(default = "default_health_check_url")]
    pub url: String,
    #[serde(default = "default_health_check_interval")]
    pub interval: u64,
    #[serde(default = "default_health_check_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub lazy: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enable: default_health_check_enabled(),
            url: default_health_check_url(),
            interval: default_health_check_interval(),
            timeout: default_health_check_timeout(),
            lazy: false,
        }
    }
}

fn default_interval() -> u64 {
    3600
}

fn default_health_check_enabled() -> bool {
    true
}

fn default_health_check_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}

fn default_health_check_interval() -> u64 {
    300
}

fn default_health_check_timeout() -> u64 {
    5000
}

#[derive(Debug, Clone)]
pub struct ProxyInfo {
    pub tag: String,
    pub proxy_type: OutboundType,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub latency_ms: Option<u64>,
    pub alive: bool,
}

pub struct ProxyProvider {
    config: ProxyProviderConfig,
    proxies: RwLock<Vec<Arc<dyn OutboundProxy>>>,
    proxy_configs: RwLock<Vec<OutboundConfig>>,
    last_update: RwLock<Option<Instant>>,
    last_health_check: RwLock<Option<Instant>>,
    health_results: RwLock<HashMap<String, ProxyHealthResult>>,
}

#[derive(Debug, Clone)]
pub struct ProxyHealthResult {
    pub alive: bool,
    pub latency_ms: Option<u64>,
    pub last_check: Instant,
    pub error: Option<String>,
}

impl ProxyProvider {
    pub fn new(config: ProxyProviderConfig) -> Self {
        Self {
            config,
            proxies: RwLock::new(Vec::new()),
            proxy_configs: RwLock::new(Vec::new()),
            last_update: RwLock::new(None),
            last_health_check: RwLock::new(None),
            health_results: RwLock::new(HashMap::new()),
        }
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn provider_type(&self) -> ProxyProviderType {
        self.config.provider_type
    }

    pub async fn load(&self) -> Result<()> {
        let content = match self.config.provider_type {
            ProxyProviderType::File => self.load_from_file().await?,
            ProxyProviderType::Http => self.load_from_http().await?,
        };

        let proxy_configs = self.parse_proxies(&content)?;
        let proxies = self.create_proxies(&proxy_configs)?;

        let mut configs_guard = self.proxy_configs.write().await;
        *configs_guard = proxy_configs;

        let mut proxies_guard = self.proxies.write().await;
        *proxies_guard = proxies;

        let mut last_update = self.last_update.write().await;
        *last_update = Some(Instant::now());

        tracing::info!(
            "Proxy provider '{}' loaded {} proxies",
            self.config.name,
            proxies_guard.len()
        );

        Ok(())
    }

    async fn load_from_file(&self) -> Result<String> {
        let path = self.config.path.as_ref().ok_or_else(|| {
            Error::config("File proxy provider requires 'path' field")
        })?;

        tokio::fs::read_to_string(path).await.map_err(|e| {
            Error::config(format!("Failed to read proxy file '{}': {}", path, e))
        })
    }

    async fn load_from_http(&self) -> Result<String> {
        let url = self.config.url.as_ref().ok_or_else(|| {
            Error::config("HTTP proxy provider requires 'url' field")
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
            .map_err(|e| Error::network(format!("Failed to fetch proxies from '{}': {}", url, e)))?;

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

    pub fn parse_proxies(&self, content: &str) -> Result<Vec<OutboundConfig>> {
        #[derive(Deserialize)]
        struct ProxyFile {
            proxies: Option<Vec<OutboundConfig>>,
        }

        if let Ok(yaml_content) = serde_yaml::from_str::<ProxyFile>(content) {
            if let Some(proxies) = yaml_content.proxies {
                return Ok(proxies);
            }
        }

        if let Ok(proxies) = serde_yaml::from_str::<Vec<OutboundConfig>>(content) {
            return Ok(proxies);
        }

        if let Ok(json_proxies) = serde_json::from_str::<Vec<OutboundConfig>>(content) {
            return Ok(json_proxies);
        }

        Err(Error::parse("Failed to parse proxy provider content"))
    }

    fn create_proxies(&self, configs: &[OutboundConfig]) -> Result<Vec<Arc<dyn OutboundProxy>>> {
        let mut proxies: Vec<Arc<dyn OutboundProxy>> = Vec::new();

        for config in configs {
            let proxy: Option<Arc<dyn OutboundProxy>> = match config.outbound_type {
                OutboundType::Direct => Some(Arc::new(DirectOutbound::new(config.clone()))),
                OutboundType::Reject => Some(Arc::new(RejectOutbound::new(config.clone()))),
                OutboundType::Socks5 => {
                    match Socks5Outbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create SOCKS5 proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                OutboundType::Http => {
                    match HttpOutbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create HTTP proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                OutboundType::Shadowsocks => {
                    match ShadowsocksOutbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create Shadowsocks proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                OutboundType::Vmess => {
                    match VmessOutbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create VMess proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                OutboundType::Vless => {
                    match VlessOutbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create VLess proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                OutboundType::Trojan => {
                    match TrojanOutbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create Trojan proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                OutboundType::Wireguard => {
                    match WireguardOutbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create WireGuard proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                OutboundType::Tuic => {
                    match TuicOutbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create TUIC proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                OutboundType::Hysteria2 => {
                    match Hysteria2Outbound::new(config.clone()) {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            tracing::warn!("Failed to create Hysteria2 proxy '{}': {}", config.tag, e);
                            None
                        }
                    }
                }
                _ => {
                    tracing::warn!(
                        "Unsupported proxy type '{:?}' in provider",
                        config.outbound_type
                    );
                    None
                }
            };

            if let Some(p) = proxy {
                proxies.push(p);
            }
        }

        Ok(proxies)
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

    pub async fn health_check(&self) -> Result<()> {
        if !self.config.health_check.enable {
            return Ok(());
        }

        let proxies = self.proxies.read().await;
        let url = &self.config.health_check.url;
        let timeout = Duration::from_millis(self.config.health_check.timeout);

        let mut results = HashMap::new();

        for proxy in proxies.iter() {
            let tag = proxy.tag().to_string();
            let result = match proxy.test_http_latency(url, timeout).await {
                Ok(latency) => ProxyHealthResult {
                    alive: true,
                    latency_ms: Some(latency.as_millis() as u64),
                    last_check: Instant::now(),
                    error: None,
                },
                Err(e) => ProxyHealthResult {
                    alive: false,
                    latency_ms: None,
                    last_check: Instant::now(),
                    error: Some(e.to_string()),
                },
            };

            tracing::debug!(
                "Health check for '{}': alive={}, latency={:?}ms",
                tag,
                result.alive,
                result.latency_ms
            );

            results.insert(tag, result);
        }

        let mut health_results = self.health_results.write().await;
        *health_results = results;

        let mut last_health_check = self.last_health_check.write().await;
        *last_health_check = Some(Instant::now());

        Ok(())
    }

    pub async fn needs_health_check(&self) -> bool {
        if !self.config.health_check.enable {
            return false;
        }

        let last_check = self.last_health_check.read().await;
        match *last_check {
            Some(time) => {
                time.elapsed() > Duration::from_secs(self.config.health_check.interval)
            }
            None => !self.config.health_check.lazy,
        }
    }

    pub async fn health_check_if_needed(&self) -> Result<bool> {
        if self.needs_health_check().await {
            self.health_check().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn get_proxies(&self) -> Vec<Arc<dyn OutboundProxy>> {
        self.proxies.read().await.clone()
    }

    pub async fn get_proxy(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        let proxies = self.proxies.read().await;
        proxies.iter().find(|p| p.tag() == tag).cloned()
    }

    pub async fn get_proxy_info(&self) -> Vec<ProxyInfo> {
        let proxies = self.proxies.read().await;
        let configs = self.proxy_configs.read().await;
        let health_results = self.health_results.read().await;

        let mut info_list = Vec::new();

        for (i, proxy) in proxies.iter().enumerate() {
            let tag = proxy.tag().to_string();
            let config = configs.get(i);
            let health = health_results.get(&tag);

            info_list.push(ProxyInfo {
                tag: tag.clone(),
                proxy_type: config.map(|c| c.outbound_type).unwrap_or(OutboundType::Direct),
                server: config.and_then(|c| c.server.clone()),
                port: config.and_then(|c| c.port),
                latency_ms: health.and_then(|h| h.latency_ms),
                alive: health.map(|h| h.alive).unwrap_or(true),
            });
        }

        info_list
    }

    pub async fn get_alive_proxies(&self) -> Vec<Arc<dyn OutboundProxy>> {
        let proxies = self.proxies.read().await;
        let health_results = self.health_results.read().await;

        proxies
            .iter()
            .filter(|p| {
                health_results
                    .get(p.tag())
                    .map(|h| h.alive)
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    pub async fn proxy_count(&self) -> usize {
        self.proxies.read().await.len()
    }
}

pub struct ProxyProviderManager {
    providers: Arc<RwLock<HashMap<String, Arc<ProxyProvider>>>>,
}

impl ProxyProviderManager {
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_provider(&self, config: ProxyProviderConfig) -> Result<()> {
        let name = config.name.clone();
        let provider = Arc::new(ProxyProvider::new(config));
        provider.load().await?;

        let mut providers = self.providers.write().await;
        providers.insert(name, provider);

        Ok(())
    }

    pub async fn remove_provider(&self, name: &str) {
        let mut providers = self.providers.write().await;
        providers.remove(name);
    }

    pub async fn get_provider(&self, name: &str) -> Option<Arc<ProxyProvider>> {
        let providers = self.providers.read().await;
        providers.get(name).cloned()
    }

    pub async fn get_all_providers(&self) -> Vec<Arc<ProxyProvider>> {
        let providers = self.providers.read().await;
        providers.values().cloned().collect()
    }

    pub async fn get_proxy(&self, provider_name: &str, proxy_tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        let providers = self.providers.read().await;
        if let Some(provider) = providers.get(provider_name) {
            provider.get_proxy(proxy_tag).await
        } else {
            None
        }
    }

    pub async fn get_all_proxies(&self) -> Vec<Arc<dyn OutboundProxy>> {
        let providers = self.providers.read().await;
        let mut all_proxies = Vec::new();

        for provider in providers.values() {
            let proxies = provider.get_proxies().await;
            all_proxies.extend(proxies);
        }

        all_proxies
    }

    pub async fn update_all(&self) -> Vec<Result<bool>> {
        let providers = self.providers.read().await;
        let mut results = Vec::new();

        for provider in providers.values() {
            results.push(provider.update_if_needed().await);
        }

        results
    }

    pub async fn health_check_all(&self) -> Vec<Result<bool>> {
        let providers = self.providers.read().await;
        let mut results = Vec::new();

        for provider in providers.values() {
            results.push(provider.health_check_if_needed().await);
        }

        results
    }

    pub async fn reload_provider(&self, name: &str) -> Result<()> {
        let providers = self.providers.read().await;
        if let Some(provider) = providers.get(name) {
            provider.load().await
        } else {
            Err(Error::config(format!("Proxy provider '{}' not found", name)))
        }
    }

    pub async fn provider_count(&self) -> usize {
        self.providers.read().await.len()
    }
}

impl Default for ProxyProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ProxyProviderManager {
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
    fn test_proxy_provider_config_defaults() {
        let config = ProxyProviderConfig {
            name: "test".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("test.yaml".to_string()),
            interval: 3600,
            health_check: HealthCheckConfig::default(),
        };

        assert_eq!(config.name, "test");
        assert_eq!(config.provider_type, ProxyProviderType::File);
        assert_eq!(config.interval, 3600);
        assert!(config.health_check.enable);
    }

    #[test]
    fn test_health_check_config_defaults() {
        let config = HealthCheckConfig::default();
        assert!(config.enable);
        assert_eq!(config.url, "http://www.gstatic.com/generate_204");
        assert_eq!(config.interval, 300);
        assert_eq!(config.timeout, 5000);
        assert!(!config.lazy);
    }

    #[test]
    fn test_proxy_provider_new() {
        let config = ProxyProviderConfig {
            name: "test-provider".to_string(),
            provider_type: ProxyProviderType::Http,
            url: Some("https://example.com/proxies.yaml".to_string()),
            path: Some("/tmp/proxies.yaml".to_string()),
            interval: 7200,
            health_check: HealthCheckConfig::default(),
        };

        let provider = ProxyProvider::new(config);
        assert_eq!(provider.name(), "test-provider");
        assert_eq!(provider.provider_type(), ProxyProviderType::Http);
    }

    #[test]
    fn test_parse_proxies_yaml() {
        let config = ProxyProviderConfig {
            name: "test".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("test.yaml".to_string()),
            interval: 3600,
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
        let proxies = result.unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].tag, "proxy1");
        assert_eq!(proxies[1].tag, "proxy2");
    }

    #[test]
    fn test_parse_proxies_json() {
        let config = ProxyProviderConfig {
            name: "test".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("test.json".to_string()),
            interval: 3600,
            health_check: HealthCheckConfig::default(),
        };

        let provider = ProxyProvider::new(config);

        let json_content = r#"[
            {"type": "socks5", "tag": "proxy1", "server": "127.0.0.1", "port": 1080},
            {"type": "http", "tag": "proxy2", "server": "127.0.0.1", "port": 8080}
        ]"#;

        let result = provider.parse_proxies(json_content);
        assert!(result.is_ok());
        let proxies = result.unwrap();
        assert_eq!(proxies.len(), 2);
    }

    #[tokio::test]
    async fn test_proxy_provider_manager_new() {
        let manager = ProxyProviderManager::new();
        assert_eq!(manager.provider_count().await, 0);
    }

    #[tokio::test]
    async fn test_needs_update_initial() {
        let config = ProxyProviderConfig {
            name: "test".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some("test.yaml".to_string()),
            interval: 3600,
            health_check: HealthCheckConfig::default(),
        };

        let provider = ProxyProvider::new(config);
        assert!(provider.needs_update().await);
    }
}
