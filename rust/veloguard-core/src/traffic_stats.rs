use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

/// Traffic statistics
#[derive(Debug, Clone, Default)]
pub struct TrafficStats {
    /// Bytes uploaded
    pub upload_bytes: u64,
    /// Bytes downloaded
    pub download_bytes: u64,
    /// Number of connections
    pub connections: u64,
    /// Total connection time in seconds
    pub connection_time_secs: u64,
}

impl TrafficStats {
    /// Add upload bytes
    pub fn add_upload(&mut self, bytes: u64) {
        self.upload_bytes = self.upload_bytes.saturating_add(bytes);
    }

    /// Add download bytes
    pub fn add_download(&mut self, bytes: u64) {
        self.download_bytes = self.download_bytes.saturating_add(bytes);
    }

    /// Add connection
    pub fn add_connection(&mut self) {
        self.connections = self.connections.saturating_add(1);
    }

    /// Add connection time
    pub fn add_connection_time(&mut self, duration: Duration) {
        self.connection_time_secs = self.connection_time_secs.saturating_add(duration.as_secs());
    }

    /// Get total bytes transferred
    pub fn total_bytes(&self) -> u64 {
        self.upload_bytes.saturating_add(self.download_bytes)
    }

    /// Merge with another stats
    pub fn merge(&mut self, other: &TrafficStats) {
        self.upload_bytes = self.upload_bytes.saturating_add(other.upload_bytes);
        self.download_bytes = self.download_bytes.saturating_add(other.download_bytes);
        self.connections = self.connections.saturating_add(other.connections);
        self.connection_time_secs = self.connection_time_secs.saturating_add(other.connection_time_secs);
    }
}

/// Connection traffic tracker
#[derive(Debug)]
pub struct ConnectionTracker {
    pub connection_id: String,
    pub start_time: Instant,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl ConnectionTracker {
    pub fn new(connection_id: String) -> Self {
        Self {
            connection_id,
            start_time: Instant::now(),
            upload_bytes: 0,
            download_bytes: 0,
        }
    }

    pub fn add_upload(&mut self, bytes: u64) {
        self.upload_bytes = self.upload_bytes.saturating_add(bytes);
    }

    pub fn add_download(&mut self, bytes: u64) {
        self.download_bytes = self.download_bytes.saturating_add(bytes);
    }

    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn finalize(self) -> TrafficStats {
        TrafficStats {
            upload_bytes: self.upload_bytes,
            download_bytes: self.download_bytes,
            connections: 1,
            connection_time_secs: self.duration().as_secs(),
        }
    }
}

/// Global traffic statistics manager
pub struct TrafficStatsManager {
    global_stats: RwLock<TrafficStats>,
    proxy_stats: DashMap<String, TrafficStats>,
    active_connections: DashMap<String, ConnectionTracker>,
}

impl Default for TrafficStatsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficStatsManager {
    /// Create a new traffic stats manager
    pub fn new() -> Self {
        Self {
            global_stats: RwLock::new(TrafficStats::default()),
            proxy_stats: DashMap::new(),
            active_connections: DashMap::new(),
        }
    }

    /// Start tracking a connection
    pub async fn start_connection(&self, connection_id: String, proxy_tag: String) -> Arc<ConnectionTracker> {
        let tracker = ConnectionTracker::new(connection_id.clone());
        let tracker_arc = Arc::new(tracker);

        // Store in active connections
        self.active_connections.insert(connection_id.clone(), ConnectionTracker::new(connection_id));

        // Update connection count
        let mut global = self.global_stats.write().await;
        global.add_connection();

        let mut proxy = self.proxy_stats.entry(proxy_tag).or_default();
        proxy.add_connection();

        Arc::clone(&tracker_arc)
    }

    /// Record traffic for a connection
    pub async fn record_traffic(&self, connection_id: &str, upload_bytes: u64, download_bytes: u64) {
        if let Some(mut tracker) = self.active_connections.get_mut(connection_id) {
            tracker.add_upload(upload_bytes);
            tracker.add_download(download_bytes);
        }

        // Update global stats
        let mut global = self.global_stats.write().await;
        global.add_upload(upload_bytes);
        global.add_download(download_bytes);
    }

    /// End tracking a connection
    pub async fn end_connection(&self, connection_id: &str, proxy_tag: &str) {
        if let Some((_, tracker)) = self.active_connections.remove(connection_id) {
            let stats = tracker.finalize();

            // Update proxy stats (only upload/download bytes and connection time,
            // connection count was already added in start_connection)
            let mut proxy = self.proxy_stats.entry(proxy_tag.to_string()).or_default();
            proxy.add_upload(stats.upload_bytes);
            proxy.add_download(stats.download_bytes);
            proxy.add_connection_time(std::time::Duration::from_secs(stats.connection_time_secs));

            // Only add connection time to global stats (upload/download already recorded in record_traffic,
            // connection count was already added in start_connection)
            let mut global = self.global_stats.write().await;
            global.add_connection_time(std::time::Duration::from_secs(stats.connection_time_secs));
        }
    }

    /// Get global traffic statistics
    pub fn global_stats(&self) -> TrafficStats {
        match self.global_stats.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => TrafficStats::default(),
        }
    }

    /// Get traffic statistics for a specific proxy
    pub fn proxy_stats(&self, proxy_tag: &str) -> Option<TrafficStats> {
        self.proxy_stats.get(proxy_tag).map(|s| s.clone())
    }

    /// Get all proxy statistics
    pub fn all_proxy_stats(&self) -> Vec<(String, TrafficStats)> {
        self.proxy_stats
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get active connection count
    pub fn active_connections(&self) -> usize {
        self.active_connections.len()
    }

    /// Get statistics summary
    pub fn summary(&self) -> TrafficSummary {
        let global = self.global_stats();
        let proxy_count = self.proxy_stats.len();
        let active_connections = self.active_connections();

        TrafficSummary {
            global_stats: global,
            proxy_count,
            active_connections,
            proxy_stats: self.all_proxy_stats(),
        }
    }

    /// Reset all statistics
    pub async fn reset(&self) {
        *self.global_stats.write().await = TrafficStats::default();
        self.proxy_stats.clear();
        // Note: active connections are not cleared as they represent current state
    }
}

/// Traffic statistics summary
#[derive(Debug, Clone)]
pub struct TrafficSummary {
    pub global_stats: TrafficStats,
    pub proxy_count: usize,
    pub active_connections: usize,
    pub proxy_stats: Vec<(String, TrafficStats)>,
}

impl std::fmt::Display for TrafficStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Up: {:.2} MB, Down: {:.2} MB, {} connections, {:.1} hours",
            self.upload_bytes as f64 / 1024.0 / 1024.0,
            self.download_bytes as f64 / 1024.0 / 1024.0,
            self.connections,
            self.connection_time_secs as f64 / 3600.0
        )
    }
}

impl std::fmt::Display for TrafficSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Global Stats: {}", self.global_stats)?;
        writeln!(f, "Active Connections: {}", self.active_connections)?;
        writeln!(f, "Proxy Count: {}", self.proxy_count)?;

        if !self.proxy_stats.is_empty() {
            writeln!(f, "\nPer-Proxy Stats:")?;
            for (tag, stats) in &self.proxy_stats {
                writeln!(f, "  {}: {}", tag, stats)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_traffic_stats() {
        let manager = TrafficStatsManager::new();

        // Start a connection (await the async function)
        let _tracker = manager.start_connection("conn1".to_string(), "proxy1".to_string()).await;

        // Record some traffic
        manager.record_traffic("conn1", 1024, 2048).await;

        // End the connection
        manager.end_connection("conn1", "proxy1").await;

        // Check stats
        let global = manager.global_stats();
        assert_eq!(global.upload_bytes, 1024);
        assert_eq!(global.download_bytes, 2048);
        assert_eq!(global.connections, 1);

        let proxy_stats = manager.proxy_stats("proxy1").unwrap();
        assert_eq!(proxy_stats.upload_bytes, 1024);
        assert_eq!(proxy_stats.download_bytes, 2048);
        assert_eq!(proxy_stats.connections, 1);
    }
}
