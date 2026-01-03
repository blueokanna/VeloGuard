pub mod config;
pub mod proxy;
pub mod routing;
pub mod inbound;
pub mod outbound;
pub mod dns;
pub mod netstack;
pub mod error;
pub mod logging;
pub mod tls;
pub mod connection_pool;
pub mod health_check;
pub mod traffic_stats;
pub mod connection_tracker;
pub mod api;

pub use config::*;
pub use proxy::*;
pub use error::*;
pub use connection_pool::*;
pub use health_check::*;
pub use traffic_stats::TrafficStats;
pub use traffic_stats::TrafficStatsManager;
pub use traffic_stats::TrafficSummary;
pub use connection_tracker::ConnectionTracker;
pub use connection_tracker::TrackedConnection;
pub use connection_tracker::ConnectionHandle;
pub use connection_tracker::global_tracker;
pub use routing::{set_runtime_proxy_mode, get_runtime_proxy_mode};

use std::time::Instant;

/// The main VeloGuard proxy server
pub struct VeloGuard {
    config: Config,
    proxy_manager: std::sync::Arc<ProxyManager>,
    traffic_stats: std::sync::Arc<TrafficStatsManager>,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    start_time: std::sync::Arc<std::sync::RwLock<Option<Instant>>>,
}

impl VeloGuard {
    pub async fn new(config: Config) -> Result<Self> {
        config.validate()?;
        logging::init_logging(config.general.log_level)?;

        let proxy_manager = ProxyManager::new(config.clone()).await?;
        let traffic_stats = TrafficStatsManager::new();

        logging::log_success("VeloGuard instance created", None);

        Ok(Self {
            config,
            proxy_manager: std::sync::Arc::new(proxy_manager),
            traffic_stats: std::sync::Arc::new(traffic_stats),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            start_time: std::sync::Arc::new(std::sync::RwLock::new(None)),
        })
    }


    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        let _perf = logging::time_operation("VeloGuard startup");

        // Start inbound listeners
        self.proxy_manager.start_inbounds().await?;

        // Start outbound connections pool
        self.proxy_manager.start_outbounds().await?;

        // Mark as running and record start time
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut start_time) = self.start_time.write() {
            *start_time = Some(Instant::now());
        }

        logging::log_success("VeloGuard proxy server started", None);
        Ok(())
    }

    /// Stop the proxy server
    pub async fn stop(&self) -> Result<()> {
        let _perf = logging::time_operation("VeloGuard shutdown");

        match self.proxy_manager.stop().await {
            Ok(()) => {
                // Mark as not running and clear start time
                self.running.store(false, std::sync::atomic::Ordering::Relaxed);
                if let Ok(mut start_time) = self.start_time.write() {
                    *start_time = None;
                }
                logging::log_success("VeloGuard proxy server stopped", None);
                Ok(())
            }
            Err(e) => {
                // Mark as not running even on error
                self.running.store(false, std::sync::atomic::Ordering::Relaxed);
                if let Ok(mut start_time) = self.start_time.write() {
                    *start_time = None;
                }
                logging::log_error(&e, Some("Failed to stop proxy server"));
                Err(e)
            }
        }
    }

    /// Check if the proxy server is running
    pub async fn is_running(&self) -> Result<bool> {
        Ok(self.running.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        if let Ok(start_time) = self.start_time.read() {
            if let Some(start) = *start_time {
                return start.elapsed().as_secs();
            }
        }
        0
    }

    /// Reload configuration
    pub async fn reload(&mut self, config: Config) -> Result<()> {
        tracing::info!("Reloading VeloGuard configuration");
        self.proxy_manager.reload(config.clone()).await?;
        self.config = config;
        tracing::info!("VeloGuard configuration reloaded");
        Ok(())
    }

    /// Get a reference to the proxy manager
    pub fn proxy_manager(&self) -> std::sync::Arc<ProxyManager> {
        std::sync::Arc::clone(&self.proxy_manager)
    }

    /// Get a reference to the traffic stats manager
    pub fn traffic_stats(&self) -> std::sync::Arc<TrafficStatsManager> {
        std::sync::Arc::clone(&self.traffic_stats)
    }

    /// Get current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}
