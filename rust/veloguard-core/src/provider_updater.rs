use crate::error::Result;
use crate::proxy_provider::ProxyProviderManager;
use crate::rule_provider::RuleProviderManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;

pub struct ProviderUpdaterConfig {
    pub check_interval: Duration,
    pub enable_proxy_provider_update: bool,
    pub enable_rule_provider_update: bool,
    pub enable_health_check: bool,
}

impl Default for ProviderUpdaterConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(60),
            enable_proxy_provider_update: true,
            enable_rule_provider_update: true,
            enable_health_check: true,
        }
    }
}

type ShutdownSender = Arc<RwLock<Option<tokio::sync::oneshot::Sender<()>>>>;

pub struct ProviderUpdater {
    config: ProviderUpdaterConfig,
    proxy_provider_manager: Option<Arc<ProxyProviderManager>>,
    rule_provider_manager: Option<Arc<RuleProviderManager>>,
    running: Arc<RwLock<bool>>,
    shutdown_tx: ShutdownSender,
}

impl ProviderUpdater {
    pub fn new(config: ProviderUpdaterConfig) -> Self {
        Self {
            config,
            proxy_provider_manager: None,
            rule_provider_manager: None,
            running: Arc::new(RwLock::new(false)),
            shutdown_tx: Arc::new(RwLock::new(None)),
        }
    }

    pub fn with_proxy_provider_manager(mut self, manager: Arc<ProxyProviderManager>) -> Self {
        self.proxy_provider_manager = Some(manager);
        self
    }

    pub fn with_rule_provider_manager(mut self, manager: Arc<RuleProviderManager>) -> Self {
        self.rule_provider_manager = Some(manager);
        self
    }

    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            tracing::warn!("Provider updater is already running");
            return Ok(());
        }
        *running = true;
        drop(running);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        {
            let mut tx_guard = self.shutdown_tx.write().await;
            *tx_guard = Some(shutdown_tx);
        }

        let config = self.config.clone();
        let proxy_manager = self.proxy_provider_manager.clone();
        let rule_manager = self.rule_provider_manager.clone();
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            Self::update_loop(config, proxy_manager, rule_manager, running, shutdown_rx).await;
        });

        tracing::info!(
            "Provider updater started with check interval: {:?}",
            self.config.check_interval
        );

        Ok(())
    }

    async fn update_loop(
        config: ProviderUpdaterConfig,
        proxy_manager: Option<Arc<ProxyProviderManager>>,
        rule_manager: Option<Arc<RuleProviderManager>>,
        running: Arc<RwLock<bool>>,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) {
        let mut check_interval = interval(config.check_interval);
        check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = check_interval.tick() => {
                    let is_running = *running.read().await;
                    if !is_running {
                        break;
                    }

                    if config.enable_proxy_provider_update {
                        if let Some(ref manager) = proxy_manager {
                            Self::update_proxy_providers(manager).await;
                        }
                    }

                    if config.enable_rule_provider_update {
                        if let Some(ref manager) = rule_manager {
                            Self::update_rule_providers(manager).await;
                        }
                    }

                    if config.enable_health_check {
                        if let Some(ref manager) = proxy_manager {
                            Self::health_check_proxies(manager).await;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("Provider updater received shutdown signal");
                    break;
                }
            }
        }

        let mut is_running = running.write().await;
        *is_running = false;
        tracing::info!("Provider updater stopped");
    }

    async fn update_proxy_providers(manager: &ProxyProviderManager) {
        let results = manager.update_all().await;
        let mut updated_count = 0;
        let mut error_count = 0;

        for result in results {
            match result {
                Ok(true) => updated_count += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!("Failed to update proxy provider: {}", e);
                    error_count += 1;
                }
            }
        }

        if updated_count > 0 || error_count > 0 {
            tracing::debug!(
                "Proxy provider update: {} updated, {} errors",
                updated_count,
                error_count
            );
        }
    }

    async fn update_rule_providers(manager: &RuleProviderManager) {
        let results = manager.update_all().await;
        let mut updated_count = 0;
        let mut error_count = 0;

        for result in results {
            match result {
                Ok(true) => updated_count += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!("Failed to update rule provider: {}", e);
                    error_count += 1;
                }
            }
        }

        if updated_count > 0 || error_count > 0 {
            tracing::debug!(
                "Rule provider update: {} updated, {} errors",
                updated_count,
                error_count
            );
        }
    }

    async fn health_check_proxies(manager: &ProxyProviderManager) {
        let results = manager.health_check_all().await;
        let mut checked_count = 0;
        let mut error_count = 0;

        for result in results {
            match result {
                Ok(true) => checked_count += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!("Failed to health check proxy provider: {}", e);
                    error_count += 1;
                }
            }
        }

        if checked_count > 0 || error_count > 0 {
            tracing::debug!(
                "Proxy health check: {} checked, {} errors",
                checked_count,
                error_count
            );
        }
    }

    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        *running = false;
        drop(running);

        let mut tx_guard = self.shutdown_tx.write().await;
        if let Some(tx) = tx_guard.take() {
            let _ = tx.send(());
        }

        tracing::info!("Provider updater stopping...");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn force_update_all(&self) -> Result<()> {
        if let Some(ref manager) = self.proxy_provider_manager {
            for provider in manager.get_all_providers().await {
                if let Err(e) = provider.update().await {
                    tracing::warn!("Failed to force update proxy provider '{}': {}", provider.name(), e);
                }
            }
        }

        if let Some(ref manager) = self.rule_provider_manager {
            for provider in manager.get_all_providers().await {
                if let Err(e) = provider.update().await {
                    tracing::warn!("Failed to force update rule provider '{}': {}", provider.name(), e);
                }
            }
        }

        Ok(())
    }

    pub async fn force_health_check_all(&self) -> Result<()> {
        if let Some(ref manager) = self.proxy_provider_manager {
            for provider in manager.get_all_providers().await {
                if let Err(e) = provider.health_check().await {
                    tracing::warn!("Failed to health check proxy provider '{}': {}", provider.name(), e);
                }
            }
        }

        Ok(())
    }
}

impl Clone for ProviderUpdaterConfig {
    fn clone(&self) -> Self {
        Self {
            check_interval: self.check_interval,
            enable_proxy_provider_update: self.enable_proxy_provider_update,
            enable_rule_provider_update: self.enable_rule_provider_update,
            enable_health_check: self.enable_health_check,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_updater_config_default() {
        let config = ProviderUpdaterConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(60));
        assert!(config.enable_proxy_provider_update);
        assert!(config.enable_rule_provider_update);
        assert!(config.enable_health_check);
    }

    #[test]
    fn test_provider_updater_new() {
        let config = ProviderUpdaterConfig {
            check_interval: Duration::from_secs(120),
            enable_proxy_provider_update: true,
            enable_rule_provider_update: false,
            enable_health_check: true,
        };

        let updater = ProviderUpdater::new(config);
        assert!(updater.proxy_provider_manager.is_none());
        assert!(updater.rule_provider_manager.is_none());
    }

    #[tokio::test]
    async fn test_provider_updater_is_running_initial() {
        let config = ProviderUpdaterConfig::default();
        let updater = ProviderUpdater::new(config);
        assert!(!updater.is_running().await);
    }

    #[tokio::test]
    async fn test_provider_updater_start_stop() {
        let config = ProviderUpdaterConfig {
            check_interval: Duration::from_millis(100),
            enable_proxy_provider_update: false,
            enable_rule_provider_update: false,
            enable_health_check: false,
        };

        let updater = ProviderUpdater::new(config);
        
        updater.start().await.unwrap();
        assert!(updater.is_running().await);
        
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        updater.stop().await.unwrap();
        
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!updater.is_running().await);
    }

    #[tokio::test]
    async fn test_provider_updater_with_managers() {
        let config = ProviderUpdaterConfig::default();
        let proxy_manager = Arc::new(ProxyProviderManager::new());
        let rule_manager = Arc::new(RuleProviderManager::new());

        let updater = ProviderUpdater::new(config)
            .with_proxy_provider_manager(proxy_manager.clone())
            .with_rule_provider_manager(rule_manager.clone());

        assert!(updater.proxy_provider_manager.is_some());
        assert!(updater.rule_provider_manager.is_some());
    }
}
