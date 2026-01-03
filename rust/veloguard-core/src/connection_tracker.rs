//! Real-time connection tracking for VeloGuard
//! Tracks active connections with traffic statistics

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::Instant;

/// Unique connection ID generator
static CONNECTION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a unique connection ID
pub fn generate_connection_id() -> String {
    let id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("conn-{}", id)
}

/// Represents an active connection
#[derive(Debug)]
pub struct TrackedConnection {
    pub id: String,
    pub inbound_tag: String,
    pub outbound_tag: String,
    pub host: String,
    pub destination_ip: Option<String>,
    pub destination_port: u16,
    pub protocol: String,
    pub network: String,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    pub start_time: Instant,
    pub start_timestamp: u64,
    pub rule: String,
    pub rule_payload: String,
    pub process_name: Option<String>,
}

impl TrackedConnection {
    pub fn new(
        inbound_tag: String,
        outbound_tag: String,
        host: String,
        destination_port: u16,
        protocol: String,
        network: String,
        rule: String,
        rule_payload: String,
    ) -> Self {
        let start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
            
        Self {
            id: generate_connection_id(),
            inbound_tag,
            outbound_tag,
            host,
            destination_ip: None,
            destination_port,
            protocol,
            network,
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            start_time: Instant::now(),
            start_timestamp: start,
            rule,
            rule_payload,
            process_name: None,
        }
    }

    pub fn add_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn get_upload(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }

    pub fn get_download(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }

    pub fn duration_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

/// Global connection tracker
pub struct ConnectionTracker {
    connections: DashMap<String, Arc<TrackedConnection>>,
    total_connections: AtomicU64,
    total_upload: AtomicU64,
    total_download: AtomicU64,
    // Real-time traffic counters (reset periodically for speed calculation)
    realtime_upload: AtomicU64,
    realtime_download: AtomicU64,
    last_speed_update: std::sync::RwLock<Instant>,
    upload_speed: AtomicU64,
    download_speed: AtomicU64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            total_connections: AtomicU64::new(0),
            total_upload: AtomicU64::new(0),
            total_download: AtomicU64::new(0),
            realtime_upload: AtomicU64::new(0),
            realtime_download: AtomicU64::new(0),
            last_speed_update: std::sync::RwLock::new(Instant::now()),
            upload_speed: AtomicU64::new(0),
            download_speed: AtomicU64::new(0),
        }
    }

    /// Add global upload bytes (called from relay functions)
    pub fn add_global_upload(&self, bytes: u64) {
        self.total_upload.fetch_add(bytes, Ordering::Relaxed);
        self.realtime_upload.fetch_add(bytes, Ordering::Relaxed);
        self.maybe_update_speed();
    }

    /// Add global download bytes (called from relay functions)
    pub fn add_global_download(&self, bytes: u64) {
        self.total_download.fetch_add(bytes, Ordering::Relaxed);
        self.realtime_download.fetch_add(bytes, Ordering::Relaxed);
        self.maybe_update_speed();
    }

    /// Update speed calculation if enough time has passed
    fn maybe_update_speed(&self) {
        if let Ok(mut last_update) = self.last_speed_update.try_write() {
            let elapsed = last_update.elapsed();
            // Update speed every 500ms for more responsive display
            if elapsed >= std::time::Duration::from_millis(500) {
                let secs = elapsed.as_secs_f64();
                if secs > 0.0 {
                    let upload = self.realtime_upload.swap(0, Ordering::Relaxed);
                    let download = self.realtime_download.swap(0, Ordering::Relaxed);
                    self.upload_speed.store((upload as f64 / secs) as u64, Ordering::Relaxed);
                    self.download_speed.store((download as f64 / secs) as u64, Ordering::Relaxed);
                }
                *last_update = Instant::now();
            }
        }
    }

    /// Force update speed calculation (called periodically from FFI)
    pub fn update_speed(&self) {
        if let Ok(mut last_update) = self.last_speed_update.write() {
            let elapsed = last_update.elapsed();
            let secs = elapsed.as_secs_f64();
            if secs > 0.0 {
                let upload = self.realtime_upload.swap(0, Ordering::Relaxed);
                let download = self.realtime_download.swap(0, Ordering::Relaxed);
                self.upload_speed.store((upload as f64 / secs) as u64, Ordering::Relaxed);
                self.download_speed.store((download as f64 / secs) as u64, Ordering::Relaxed);
            }
            *last_update = Instant::now();
        }
    }

    /// Get current upload speed in bytes/sec
    pub fn upload_speed(&self) -> u64 {
        self.upload_speed.load(Ordering::Relaxed)
    }

    /// Get current download speed in bytes/sec
    pub fn download_speed(&self) -> u64 {
        self.download_speed.load(Ordering::Relaxed)
    }

    /// Start tracking a new connection
    pub fn track(&self, conn: TrackedConnection) -> Arc<TrackedConnection> {
        let id = conn.id.clone();
        let conn_arc = Arc::new(conn);
        self.connections.insert(id, Arc::clone(&conn_arc));
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        conn_arc
    }

    /// Remove a connection from tracking
    pub fn untrack(&self, id: &str) {
        // Just remove the connection from tracking
        // Traffic is already counted in add_global_upload/download during relay
        self.connections.remove(id);
    }

    /// Get a connection by ID
    pub fn get(&self, id: &str) -> Option<Arc<TrackedConnection>> {
        self.connections.get(id).map(|c| Arc::clone(&c))
    }

    /// Get all active connections
    pub fn get_all(&self) -> Vec<Arc<TrackedConnection>> {
        self.connections
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect()
    }

    /// Get active connection count
    pub fn active_count(&self) -> usize {
        self.connections.len()
    }

    /// Get total connection count (including closed)
    pub fn total_count(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Get total upload bytes
    pub fn total_upload(&self) -> u64 {
        // Global traffic is already tracked via add_global_upload
        self.total_upload.load(Ordering::Relaxed)
    }

    /// Get total download bytes
    pub fn total_download(&self) -> u64 {
        // Global traffic is already tracked via add_global_download
        self.total_download.load(Ordering::Relaxed)
    }

    /// Close a connection by ID
    pub fn close_connection(&self, id: &str) -> bool {
        self.connections.remove(id).is_some()
    }

    /// Close all connections
    pub fn close_all(&self) {
        let ids: Vec<String> = self.connections
            .iter()
            .map(|e| e.key().clone())
            .collect();
        for id in ids {
            self.untrack(&id);
        }
    }

    /// Reset all statistics (called when service restarts)
    pub fn reset(&self) {
        // Clear all connections
        self.connections.clear();
        
        // Reset all counters
        self.total_connections.store(0, Ordering::Relaxed);
        self.total_upload.store(0, Ordering::Relaxed);
        self.total_download.store(0, Ordering::Relaxed);
        self.realtime_upload.store(0, Ordering::Relaxed);
        self.realtime_download.store(0, Ordering::Relaxed);
        self.upload_speed.store(0, Ordering::Relaxed);
        self.download_speed.store(0, Ordering::Relaxed);
        
        // Reset speed update time
        if let Ok(mut last_update) = self.last_speed_update.write() {
            *last_update = Instant::now();
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection handle that auto-untracks when dropped
pub struct ConnectionHandle {
    tracker: Arc<ConnectionTracker>,
    connection: Arc<TrackedConnection>,
}

impl ConnectionHandle {
    pub fn new(tracker: Arc<ConnectionTracker>, connection: Arc<TrackedConnection>) -> Self {
        Self { tracker, connection }
    }

    pub fn id(&self) -> &str {
        &self.connection.id
    }

    pub fn add_upload(&self, bytes: u64) {
        self.connection.add_upload(bytes);
    }

    pub fn add_download(&self, bytes: u64) {
        self.connection.add_download(bytes);
    }

    pub fn connection(&self) -> &TrackedConnection {
        &self.connection
    }
}

impl Drop for ConnectionHandle {
    fn drop(&mut self) {
        self.tracker.untrack(&self.connection.id);
    }
}

// Global tracker instance
lazy_static::lazy_static! {
    pub static ref GLOBAL_TRACKER: Arc<ConnectionTracker> = Arc::new(ConnectionTracker::new());
}

/// Get the global connection tracker
pub fn global_tracker() -> Arc<ConnectionTracker> {
    Arc::clone(&GLOBAL_TRACKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_tracking() {
        let tracker = ConnectionTracker::new();
        
        let conn = TrackedConnection::new(
            "mixed".to_string(),
            "proxy".to_string(),
            "example.com".to_string(),
            443,
            "HTTPS".to_string(),
            "tcp".to_string(),
            "DOMAIN-SUFFIX".to_string(),
            "example.com".to_string(),
        );
        
        let id = conn.id.clone();
        let tracked = tracker.track(conn);
        
        assert_eq!(tracker.active_count(), 1);
        
        tracked.add_upload(1024);
        tracked.add_download(2048);
        
        assert_eq!(tracked.get_upload(), 1024);
        assert_eq!(tracked.get_download(), 2048);
        
        // Simulate global traffic tracking (as done in relay functions)
        tracker.add_global_upload(1024);
        tracker.add_global_download(2048);
        
        tracker.untrack(&id);
        assert_eq!(tracker.active_count(), 0);
        // Global traffic is tracked separately
        assert_eq!(tracker.total_upload(), 1024);
        assert_eq!(tracker.total_download(), 2048);
    }
}
