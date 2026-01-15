#[macro_use]
pub mod macros;
pub mod api;
pub mod config;
pub mod connection_pool;
pub mod connection_tracker;
pub mod dispatcher;
pub mod dns;
pub mod error;
pub mod geoip;
pub mod health_check;
pub mod inbound;
pub mod jaeger_tracing;
pub mod logging;
pub mod netstack;
pub mod outbound;
pub mod process;
pub mod provider_updater;
pub mod proxy;
pub mod proxy_provider;
pub mod routing;
pub mod rule_provider;
pub mod socket_protect;
pub mod time_sync;
pub mod tls;
pub mod traffic_stats;
pub mod transport;

#[cfg(test)]
mod tests;

/// VeloGuard User-Agent string - generated from Cargo.toml version
pub const USER_AGENT: &str = concat!("Veloguard/v", env!("CARGO_PKG_VERSION"));

/// Get the User-Agent string
/// Returns format: "Veloguard/v0.1.0"
pub fn user_agent() -> &'static str {
    USER_AGENT
}

pub use config::*;
pub use connection_pool::*;
pub use connection_tracker::global_tracker;
pub use connection_tracker::ConnectionHandle;
pub use connection_tracker::ConnectionTracker;
pub use connection_tracker::TrackedConnection;
pub use dispatcher::{Dispatcher, DispatchContext};
pub use error::*;
pub use health_check::*;
pub use proxy::*;
pub use routing::{get_runtime_proxy_mode, set_runtime_proxy_mode};
pub use socket_protect::{
    clear_protect_callback, has_protect_callback, protect_socket, protect_tcp_stream,
    set_protect_callback,
};
pub use traffic_stats::TrafficStats;
pub use traffic_stats::TrafficStatsManager;
pub use traffic_stats::TrafficSummary;

// 导出时间同步模块
pub use time_sync::{
    get_corrected_timestamp, get_vmess_timestamp, get_vmess_timestamp_bytes,
    get_time_offset_ms, init_time_sync, sync_time_async,
    sync_time_blocking, ensure_time_synced, SyncResult,
    get_timestamp_diagnostics, get_vmess_timestamp_with_diagnostics, TimestampDiagnostics,
};

use std::time::Instant;

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

        // 初始化 NTP 时间同步
        // VMess 协议要求客户端和服务器时间差在 ±30 秒内
        tracing::info!("Initializing NTP time synchronization...");
        let sync_result = time_sync::sync_time_blocking();
        if sync_result.success {
            tracing::info!(
                "NTP sync successful: server={}, offset={}ms",
                sync_result.server.unwrap_or_default(),
                sync_result.offset_ms
            );
        } else {
            tracing::warn!(
                "NTP sync failed: {}. Using local time (VMess may fail if time is out of sync)",
                sync_result.error.unwrap_or_default()
            );
        }

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
        self.proxy_manager.start_inbounds().await?;
        self.proxy_manager.start_outbounds().await?;

        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut start_time) = self.start_time.write() {
            *start_time = Some(Instant::now());
        }

        logging::log_success("VeloGuard proxy server started", None);
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let _perf = logging::time_operation("VeloGuard shutdown");

        match self.proxy_manager.stop().await {
            Ok(()) => {
                self.running
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                if let Ok(mut start_time) = self.start_time.write() {
                    *start_time = None;
                }
                logging::log_success("VeloGuard proxy server stopped", None);
                Ok(())
            }
            Err(e) => {
                self.running
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                if let Ok(mut start_time) = self.start_time.write() {
                    *start_time = None;
                }
                logging::log_error(&e, Some("Failed to stop proxy server"));
                Err(e)
            }
        }
    }

    pub async fn is_running(&self) -> Result<bool> {
        Ok(self.running.load(std::sync::atomic::Ordering::Relaxed))
    }

    pub fn uptime_secs(&self) -> u64 {
        if let Ok(start_time) = self.start_time.read() {
            if let Some(start) = *start_time {
                return start.elapsed().as_secs();
            }
        }
        0
    }

    pub async fn reload(&mut self, config: Config) -> Result<()> {
        tracing::info!("Reloading VeloGuard configuration");
        
        // Validate configuration before applying
        config.validate()?;
        
        self.proxy_manager.reload(config.clone()).await?;
        self.config = config;
        tracing::info!("VeloGuard configuration reloaded");
        Ok(())
    }

    pub fn proxy_manager(&self) -> std::sync::Arc<ProxyManager> {
        std::sync::Arc::clone(&self.proxy_manager)
    }

    pub fn traffic_stats(&self) -> std::sync::Arc<TrafficStatsManager> {
        std::sync::Arc::clone(&self.traffic_stats)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}
