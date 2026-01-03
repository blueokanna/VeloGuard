//! UDP session management
//!
//! Manages UDP sessions for transparent proxying.

use crate::error::{Result, SolidTcpError};
use crate::nat::NatKey;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// UDP session configuration
#[derive(Debug, Clone)]
pub struct UdpConfig {
    /// Session timeout
    pub session_timeout: Duration,
    /// Maximum sessions
    pub max_sessions: usize,
    /// Buffer size for datagrams
    pub buffer_size: usize,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(60),
            max_sessions: 65536,
            buffer_size: 65535,
        }
    }
}

/// UDP session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionState {
    Active,
    Closing,
    Closed,
}

/// UDP session
pub struct UdpSession {
    /// Session key
    pub key: NatKey,
    /// State
    state: UdpSessionState,
    /// Creation time
    #[allow(dead_code)]
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_recv: u64,
    /// Packets sent
    packets_sent: u64,
    /// Packets received
    packets_recv: u64,
    /// Associated domain (from Fake-IP)
    pub domain: Option<String>,
    /// Channel to send data to proxy
    proxy_tx: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
}

impl UdpSession {
    /// Create a new UDP session
    pub fn new(key: NatKey, domain: Option<String>) -> Self {
        let now = Instant::now();
        Self {
            key,
            state: UdpSessionState::Active,
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_recv: 0,
            packets_sent: 0,
            packets_recv: 0,
            domain,
            proxy_tx: None,
        }
    }

    /// Get session state
    pub fn state(&self) -> UdpSessionState {
        self.state
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.state == UdpSessionState::Active
    }

    /// Set proxy channel
    pub fn set_proxy_tx(&mut self, tx: mpsc::Sender<(Vec<u8>, SocketAddr)>) {
        self.proxy_tx = Some(tx);
    }

    /// Record sent data
    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
        self.last_activity = Instant::now();
    }

    /// Record received data
    pub fn record_recv(&mut self, bytes: usize) {
        self.bytes_recv += bytes as u64;
        self.packets_recv += 1;
        self.last_activity = Instant::now();
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Close the session
    pub fn close(&mut self) {
        self.state = UdpSessionState::Closed;
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (self.bytes_sent, self.bytes_recv, self.packets_sent, self.packets_recv)
    }

    /// Get proxy sender
    pub fn proxy_tx(&self) -> Option<&mpsc::Sender<(Vec<u8>, SocketAddr)>> {
        self.proxy_tx.as_ref()
    }
}

/// UDP session manager
pub struct UdpManager {
    /// Active sessions
    sessions: DashMap<NatKey, Arc<parking_lot::RwLock<UdpSession>>>,
    /// Configuration
    config: UdpConfig,
    /// Statistics
    stats: UdpManagerStats,
}

/// UDP manager statistics
#[derive(Debug, Default)]
pub struct UdpManagerStats {
    pub sessions_created: AtomicU64,
    pub sessions_closed: AtomicU64,
    pub datagrams_received: AtomicU64,
    pub datagrams_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
}

impl UdpManager {
    /// Create a new UDP manager
    pub fn new() -> Self {
        Self::with_config(UdpConfig::default())
    }

    /// Create a new UDP manager with custom configuration
    pub fn with_config(config: UdpConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            config,
            stats: UdpManagerStats::default(),
        }
    }

    /// Get or create a session
    pub fn get_or_create_session(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        domain: Option<String>,
    ) -> Result<Arc<parking_lot::RwLock<UdpSession>>> {
        let key = NatKey::new(src, dst);

        // Check if session exists
        if let Some(session) = self.sessions.get(&key) {
            return Ok(session.clone());
        }

        // Check capacity
        if self.sessions.len() >= self.config.max_sessions {
            return Err(SolidTcpError::UdpError(format!(
                "Max sessions reached: {}",
                self.config.max_sessions
            )));
        }

        // Create new session
        let session = UdpSession::new(key, domain);
        let session = Arc::new(parking_lot::RwLock::new(session));
        self.sessions.insert(key, session.clone());
        self.stats.sessions_created.fetch_add(1, Ordering::Relaxed);

        debug!("UDP session created: {} -> {}", src, dst);
        Ok(session)
    }

    /// Get session by key
    pub fn get_session(&self, src: SocketAddr, dst: SocketAddr) -> Option<Arc<parking_lot::RwLock<UdpSession>>> {
        let key = NatKey::new(src, dst);
        self.sessions.get(&key).map(|s| s.clone())
    }

    /// Remove session
    pub fn remove_session(&self, src: SocketAddr, dst: SocketAddr) -> Option<Arc<parking_lot::RwLock<UdpSession>>> {
        let key = NatKey::new(src, dst);
        if let Some((_, session)) = self.sessions.remove(&key) {
            self.stats.sessions_closed.fetch_add(1, Ordering::Relaxed);
            Some(session)
        } else {
            None
        }
    }

    /// Get active session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Cleanup timed out sessions
    pub fn cleanup(&self) {
        let timeout = self.config.session_timeout;
        let to_remove: Vec<_> = self.sessions
            .iter()
            .filter(|entry| {
                let session = entry.read();
                session.state == UdpSessionState::Closed || session.is_timed_out(timeout)
            })
            .map(|entry| *entry.key())
            .collect();

        for key in to_remove {
            if let Some((_, _)) = self.sessions.remove(&key) {
                self.stats.sessions_closed.fetch_add(1, Ordering::Relaxed);
                trace!("UDP session cleaned up: {:?}", key);
            }
        }
    }

    /// Record sent datagram
    pub fn record_sent(&self, src: SocketAddr, dst: SocketAddr, bytes: usize) {
        let key = NatKey::new(src, dst);
        if let Some(session) = self.sessions.get(&key) {
            session.write().record_sent(bytes);
        }
        self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record received datagram
    pub fn record_recv(&self, src: SocketAddr, dst: SocketAddr, bytes: usize) {
        let key = NatKey::new(src, dst);
        if let Some(session) = self.sessions.get(&key) {
            session.write().record_recv(bytes);
        }
        self.stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Get statistics
    pub fn stats(&self) -> &UdpManagerStats {
        &self.stats
    }

    /// Iterate over all sessions
    pub fn iter(&self) -> impl Iterator<Item = Arc<parking_lot::RwLock<UdpSession>>> + '_ {
        self.sessions.iter().map(|e| e.clone())
    }
}

impl Default for UdpManager {
    fn default() -> Self {
        Self::new()
    }
}
