use crate::config::Config;
use crate::error::Result;
use crate::inbound::InboundManager;
use crate::outbound::OutboundManager;
use crate::routing::Router;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Proxy manager that coordinates inbound and outbound connections
pub struct ProxyManager {
    config: Arc<RwLock<Config>>,
    inbound_manager: InboundManager,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
}

impl ProxyManager {
    /// Create a new proxy manager
    pub async fn new(config: Config) -> Result<Self> {
        let config_arc = Arc::new(RwLock::new(config));
        let router = Arc::new(Router::new(config_arc.clone()).await?);
        
        // Create outbound manager first (wrapped in Arc for sharing)
        let outbound_manager = Arc::new(OutboundManager::new(config_arc.clone()).await?);
        
        // Create inbound manager with reference to outbound manager
        let inbound_manager = InboundManager::new(
            config_arc.clone(),
            router.clone(),
            Arc::clone(&outbound_manager),
        ).await?;

        Ok(Self {
            config: config_arc,
            inbound_manager,
            outbound_manager,
            router,
        })
    }

    /// Start all inbound listeners
    pub async fn start_inbounds(&self) -> Result<()> {
        self.inbound_manager.start().await
    }

    /// Start outbound connection pools
    pub async fn start_outbounds(&self) -> Result<()> {
        self.outbound_manager.start().await
    }

    /// Stop all proxy services
    pub async fn stop(&self) -> Result<()> {
        self.inbound_manager.stop().await?;
        self.outbound_manager.stop().await?;
        Ok(())
    }

    /// Reload configuration
    pub async fn reload(&self, new_config: Config) -> Result<()> {
        let mut config = self.config.write().await;
        *config = new_config;

        // Reload router with new rules
        self.router.reload().await?;

        // Restart inbound listeners
        self.inbound_manager.reload().await?;

        // Restart outbound connections
        self.outbound_manager.reload().await?;

        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Get router reference
    pub fn router(&self) -> Arc<Router> {
        self.router.clone()
    }

    /// Get inbound manager reference
    pub fn inbound_manager(&self) -> &InboundManager {
        &self.inbound_manager
    }

    /// Get outbound manager reference
    pub fn outbound_manager(&self) -> &OutboundManager {
        &self.outbound_manager
    }
}