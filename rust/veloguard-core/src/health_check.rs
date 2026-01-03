use crate::error::Result;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

/// Health check result
#[derive(Debug, Clone)]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is unhealthy
    Unhealthy { reason: String, last_error: Option<String> },
    /// Health status is unknown
    Unknown,
}

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Health check interval
    pub interval: Duration,
    /// Health check timeout
    pub timeout: Duration,
    /// Maximum consecutive failures before marking unhealthy
    pub max_failures: usize,
    /// Recovery check interval
    pub recovery_interval: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_failures: 3,
            recovery_interval: Duration::from_secs(10),
        }
    }
}

/// Health check target
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct HealthTarget {
    pub tag: String,
    pub address: String,
    pub port: u16,
}

/// Health monitor
pub struct HealthMonitor {
    config: HealthCheckConfig,
    health_status: DashMap<String, HealthInfo>,
}

#[derive(Debug, Clone)]
struct HealthInfo {
    status: HealthStatus,
    last_check: Instant,
    consecutive_failures: usize,
    total_checks: usize,
    successful_checks: usize,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            health_status: DashMap::new(),
        }
    }

    /// Register a health check target
    pub fn register_target(&self, target: HealthTarget) {
        let info = HealthInfo {
            status: HealthStatus::Unknown,
            last_check: Instant::now(),
            consecutive_failures: 0,
            total_checks: 0,
            successful_checks: 0,
        };
        self.health_status.insert(target.tag, info);
    }

    /// Update health status for a target
    pub fn update_health(&self, tag: &str, status: HealthStatus) {
        if let Some(mut info) = self.health_status.get_mut(tag) {
            info.last_check = Instant::now();
            info.total_checks += 1;

            match &status {
                HealthStatus::Healthy => {
                    info.status = status;
                    info.consecutive_failures = 0;
                    info.successful_checks += 1;
                }
                HealthStatus::Unhealthy { .. } => {
                    info.consecutive_failures += 1;
                    if info.consecutive_failures >= self.config.max_failures {
                        info.status = status;
                    }
                }
                HealthStatus::Unknown => {
                    info.status = status;
                }
            }
        }
    }

    /// Get health status for a target
    pub fn get_health(&self, tag: &str) -> Option<HealthStatus> {
        self.health_status.get(tag).map(|info| info.status.clone())
    }

    /// Get health statistics for a target
    pub fn get_stats(&self, tag: &str) -> Option<HealthStats> {
        self.health_status.get(tag).map(|info| HealthStats {
            status: info.status.clone(),
            last_check: info.last_check,
            consecutive_failures: info.consecutive_failures,
            total_checks: info.total_checks,
            successful_checks: info.successful_checks,
            success_rate: if info.total_checks > 0 {
                info.successful_checks as f64 / info.total_checks as f64
            } else {
                0.0
            },
        })
    }

    /// Get all health statuses
    pub fn get_all_health(&self) -> Vec<(String, HealthStatus)> {
        self.health_status
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().status.clone()))
            .collect()
    }

    /// Check if a target needs health check
    pub fn needs_check(&self, tag: &str) -> bool {
        if let Some(info) = self.health_status.get(tag) {
            let interval = match info.status {
                HealthStatus::Unhealthy { .. } => self.config.recovery_interval,
                _ => self.config.interval,
            };
            info.last_check.elapsed() >= interval
        } else {
            false
        }
    }

    /// Get targets that need health checks
    pub fn targets_needing_check(&self) -> Vec<String> {
        self.health_status
            .iter()
            .filter(|entry| {
                let interval = match entry.value().status {
                    HealthStatus::Unhealthy { .. } => self.config.recovery_interval,
                    _ => self.config.interval,
                };
                entry.value().last_check.elapsed() >= interval
            })
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Remove a target from health monitoring
    pub fn remove_target(&self, tag: &str) {
        self.health_status.remove(tag);
    }

    /// Clear all health data
    pub fn clear(&self) {
        self.health_status.clear();
    }
}

/// Health statistics
#[derive(Debug, Clone)]
pub struct HealthStats {
    pub status: HealthStatus,
    pub last_check: Instant,
    pub consecutive_failures: usize,
    pub total_checks: usize,
    pub successful_checks: usize,
    pub success_rate: f64,
}

/// Health check trait for outbound proxies
#[async_trait::async_trait]
pub trait HealthCheckable {
    /// Perform a health check
    async fn health_check(&self) -> Result<HealthStatus>;

    /// Get the health check target information
    fn health_target(&self) -> HealthTarget;
}

/// Background health checker
pub struct HealthChecker {
    monitor: Arc<HealthMonitor>,
    checkables: Vec<Box<dyn HealthCheckable + Send + Sync>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(monitor: Arc<HealthMonitor>) -> Self {
        Self {
            monitor,
            checkables: Vec::new(),
        }
    }

    /// Add a health checkable target
    pub fn add_checkable(&mut self, checkable: Box<dyn HealthCheckable + Send + Sync>) {
        let target = checkable.health_target();
        self.monitor.register_target(target);
        self.checkables.push(checkable);
    }

    /// Start the health checker
    pub async fn start(self) -> Result<()> {
        tokio::spawn(async move {
            loop {
                let targets = self.monitor.targets_needing_check();

                for target_tag in targets {
                    if let Some(checkable) = self.checkables.iter().find(|c| c.health_target().tag == target_tag) {
                        match checkable.health_check().await {
                            Ok(status) => {
                                self.monitor.update_health(&target_tag, status);
                            }
                            Err(e) => {
                                let status = HealthStatus::Unhealthy {
                                    reason: "Health check failed".to_string(),
                                    last_error: Some(e.to_string()),
                                };
                                self.monitor.update_health(&target_tag, status);
                            }
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_monitor() {
        let monitor = HealthMonitor::new(HealthCheckConfig::default());

        // Register a target
        let target = HealthTarget {
            tag: "test-proxy".to_string(),
            address: "127.0.0.1".to_string(),
            port: 1080,
        };
        monitor.register_target(target);

        // Initially unknown
        assert!(matches!(monitor.get_health("test-proxy"), Some(HealthStatus::Unknown)));

        // Update to healthy
        monitor.update_health("test-proxy", HealthStatus::Healthy);
        assert!(matches!(monitor.get_health("test-proxy"), Some(HealthStatus::Healthy)));

        // Update to unhealthy
        let unhealthy_status = HealthStatus::Unhealthy {
            reason: "Connection failed".to_string(),
            last_error: Some("timeout".to_string()),
        };
        monitor.update_health("test-proxy", unhealthy_status.clone());

        // Should still be healthy (need 3 failures)
        assert!(matches!(monitor.get_health("test-proxy"), Some(HealthStatus::Healthy)));

        // 3 failures should mark as unhealthy
        for _ in 0..2 {
            monitor.update_health("test-proxy", unhealthy_status.clone());
        }
        assert!(matches!(monitor.get_health("test-proxy"), Some(HealthStatus::Unhealthy { .. })));
    }
}
