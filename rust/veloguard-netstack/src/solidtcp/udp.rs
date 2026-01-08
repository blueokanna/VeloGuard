//! UDP session management with full QUIC support
//!
//! This module provides comprehensive UDP handling for:
//! - TUN mode (transparent proxy via virtual network interface)
//! - Rule mode (routing based on domain/IP rules)
//! - QUIC protocol support (long-lived bidirectional UDP streams)
//! - DNS interception and Fake-IP resolution

use crate::solidtcp::error::{Result, SolidTcpError};
use crate::solidtcp::nat::NatKey;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, trace};

/// UDP configuration
#[derive(Debug, Clone)]
pub struct UdpConfig {
    /// Session timeout for regular UDP
    pub session_timeout: Duration,
    /// Extended timeout for QUIC connections (longer-lived)
    pub quic_session_timeout: Duration,
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
    /// Buffer size for UDP packets
    pub buffer_size: usize,
    /// Enable QUIC detection and optimization
    pub quic_optimization: bool,
    /// Ports commonly used by QUIC (for detection)
    pub quic_ports: Vec<u16>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(300),      // 5 minutes for regular UDP
            quic_session_timeout: Duration::from_secs(600), // 10 minutes for QUIC
            max_sessions: 65536,
            buffer_size: 65535,
            quic_optimization: true,
            quic_ports: vec![443, 8443, 4433, 8080], // Common QUIC ports
        }
    }
}

/// UDP session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionState {
    /// Session is active and can send/receive
    Active,
    /// Session is being closed
    Closing,
    /// Session is closed
    Closed,
}

/// UDP session type for optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionType {
    /// Regular UDP traffic
    Regular,
    /// QUIC protocol (HTTP/3)
    Quic,
    /// DNS query
    Dns,
    /// Unknown/other
    Unknown,
}

impl UdpSessionType {
    /// Detect session type from destination port and payload
    pub fn detect(dst_port: u16, payload: &[u8], quic_ports: &[u16]) -> Self {
        // DNS detection
        if dst_port == 53 {
            return Self::Dns;
        }

        // QUIC detection by port
        if quic_ports.contains(&dst_port) {
            // Additional QUIC header detection
            if Self::is_quic_packet(payload) {
                return Self::Quic;
            }
        }

        // QUIC can also be detected by packet structure
        if Self::is_quic_packet(payload) {
            return Self::Quic;
        }

        Self::Regular
    }

    /// Check if payload looks like a QUIC packet
    fn is_quic_packet(payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }

        // QUIC packets have specific header formats
        // Long header: first bit is 1 (0x80 or higher for first byte)
        // Short header: first bit is 0, but has specific patterns
        
        let first_byte = payload[0];
        
        // Long header format (used in handshake)
        if first_byte & 0x80 != 0 {
            // Check for QUIC version field (bytes 1-4)
            if payload.len() >= 5 {
                // QUIC v1 version: 0x00000001
                // QUIC v2 version: 0x6b3343cf
                let version = if payload.len() >= 5 {
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]])
                } else {
                    0
                };
                
                // Known QUIC versions
                matches!(version, 
                    0x00000001 |  // QUIC v1
                    0x6b3343cf |  // QUIC v2
                    0xff000000..=0xffffffff | // Draft versions
                    0x51303030..=0x51303939   // Google QUIC (Q000-Q099)
                )
            } else {
                false
            }
        } else {
            // Short header - harder to detect without connection context
            // Usually starts with 0x40-0x7f for QUIC short headers
            (first_byte & 0x40) != 0 && payload.len() >= 20
        }
    }
}

/// UDP session for tracking connections
pub struct UdpSession {
    /// Unique session key
    pub key: NatKey,
    /// Session state
    state: UdpSessionState,
    /// Session type (QUIC, DNS, Regular)
    session_type: UdpSessionType,
    /// Creation timestamp
    created_at: Instant,
    /// Last activity timestamp
    last_activity: Instant,
    /// Bytes sent
    bytes_sent: AtomicU64,
    /// Bytes received
    bytes_recv: AtomicU64,
    /// Packets sent
    packets_sent: AtomicU64,
    /// Packets received
    packets_recv: AtomicU64,
    /// Associated domain (from Fake-IP lookup)
    pub domain: Option<String>,
    /// Outbound tag for routing
    pub outbound_tag: Option<String>,
    /// Channel to send data to proxy
    proxy_tx: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    /// Relay socket for direct forwarding
    relay_socket: Option<Arc<TokioUdpSocket>>,
    /// Is this session protected (Android VPN)
    protected: AtomicBool,
}

impl UdpSession {
    /// Create a new UDP session
    pub fn new(key: NatKey, domain: Option<String>) -> Self {
        let now = Instant::now();
        Self {
            key,
            state: UdpSessionState::Active,
            session_type: UdpSessionType::Unknown,
            created_at: now,
            last_activity: now,
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            domain,
            outbound_tag: None,
            proxy_tx: None,
            relay_socket: None,
            protected: AtomicBool::new(false),
        }
    }

    /// Create a new session with type detection
    pub fn new_with_type(
        key: NatKey,
        domain: Option<String>,
        session_type: UdpSessionType,
    ) -> Self {
        let mut session = Self::new(key, domain);
        session.session_type = session_type;
        session
    }

    /// Get session state
    pub fn state(&self) -> UdpSessionState {
        self.state
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.state == UdpSessionState::Active
    }

    /// Get session type
    pub fn session_type(&self) -> UdpSessionType {
        self.session_type
    }

    /// Set session type
    pub fn set_session_type(&mut self, session_type: UdpSessionType) {
        self.session_type = session_type;
    }

    /// Set the proxy channel
    pub fn set_proxy_tx(&mut self, tx: mpsc::Sender<(Vec<u8>, SocketAddr)>) {
        self.proxy_tx = Some(tx);
    }

    /// Get the proxy channel
    pub fn proxy_tx(&self) -> Option<&mpsc::Sender<(Vec<u8>, SocketAddr)>> {
        self.proxy_tx.as_ref()
    }

    /// Set the relay socket for direct forwarding
    pub fn set_relay_socket(&mut self, socket: Arc<TokioUdpSocket>) {
        self.relay_socket = Some(socket);
    }

    /// Get the relay socket
    pub fn relay_socket(&self) -> Option<&Arc<TokioUdpSocket>> {
        self.relay_socket.as_ref()
    }

    /// Set outbound tag
    pub fn set_outbound_tag(&mut self, tag: String) {
        self.outbound_tag = Some(tag);
    }

    /// Record sent data
    pub fn record_sent(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record received data
    pub fn record_recv(&self, bytes: usize) {
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Touch session to update last activity
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if session is timed out
    pub fn is_timed_out(&self, regular_timeout: Duration, quic_timeout: Duration) -> bool {
        let timeout = match self.session_type {
            UdpSessionType::Quic => quic_timeout,
            _ => regular_timeout,
        };
        self.last_activity.elapsed() > timeout
    }

    /// Check if session is timed out with single timeout
    pub fn is_timed_out_simple(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Close the session
    pub fn close(&mut self) {
        self.state = UdpSessionState::Closed;
    }

    /// Get session statistics
    pub fn stats(&self) -> UdpSessionStats {
        UdpSessionStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            session_type: self.session_type,
            duration: self.created_at.elapsed(),
        }
    }

    /// Mark session as protected (Android)
    pub fn set_protected(&self, protected: bool) {
        self.protected.store(protected, Ordering::Relaxed);
    }

    /// Check if session is protected
    pub fn is_protected(&self) -> bool {
        self.protected.load(Ordering::Relaxed)
    }
}

/// UDP session statistics
#[derive(Debug, Clone)]
pub struct UdpSessionStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub session_type: UdpSessionType,
    pub duration: Duration,
}

/// Global UDP manager statistics
#[derive(Debug, Default)]
pub struct UdpManagerStats {
    pub sessions_created: AtomicU64,
    pub sessions_closed: AtomicU64,
    pub datagrams_received: AtomicU64,
    pub datagrams_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub quic_sessions: AtomicU64,
    pub dns_queries: AtomicU64,
}

impl UdpManagerStats {
    pub fn snapshot(&self) -> UdpManagerStatsSnapshot {
        UdpManagerStatsSnapshot {
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            sessions_closed: self.sessions_closed.load(Ordering::Relaxed),
            datagrams_received: self.datagrams_received.load(Ordering::Relaxed),
            datagrams_sent: self.datagrams_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            quic_sessions: self.quic_sessions.load(Ordering::Relaxed),
            dns_queries: self.dns_queries.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of UDP manager statistics
#[derive(Debug, Clone)]
pub struct UdpManagerStatsSnapshot {
    pub sessions_created: u64,
    pub sessions_closed: u64,
    pub datagrams_received: u64,
    pub datagrams_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub quic_sessions: u64,
    pub dns_queries: u64,
}

/// UDP session manager
/// 
/// Handles all UDP sessions for both TUN mode and rule-based routing.
/// Provides special handling for QUIC protocol to ensure proper
/// bidirectional communication.
pub struct UdpManager {
    /// Active sessions indexed by NAT key
    sessions: DashMap<NatKey, Arc<parking_lot::RwLock<UdpSession>>>,
    /// Configuration
    config: UdpConfig,
    /// Statistics
    stats: UdpManagerStats,
    /// Relay sockets cache for direct connections
    relay_sockets: DashMap<SocketAddr, Arc<TokioUdpSocket>>,
}

impl UdpManager {
    /// Create a new UDP manager with default config
    pub fn new() -> Self {
        Self::with_config(UdpConfig::default())
    }

    /// Create a new UDP manager with custom config
    pub fn with_config(config: UdpConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            config,
            stats: UdpManagerStats::default(),
            relay_sockets: DashMap::new(),
        }
    }

    /// Get or create a session for the given addresses
    pub fn get_or_create_session(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        domain: Option<String>,
    ) -> Result<Arc<parking_lot::RwLock<UdpSession>>> {
        let key = NatKey::new(src, dst);

        // Try to get existing session
        if let Some(session) = self.sessions.get(&key) {
            let mut sess = session.write();
            sess.touch();
            return Ok(session.clone());
        }

        // Check session limit
        if self.sessions.len() >= self.config.max_sessions {
            // Try cleanup first
            self.cleanup();
            if self.sessions.len() >= self.config.max_sessions {
                return Err(SolidTcpError::UdpError(format!(
                    "Max UDP sessions reached: {}",
                    self.config.max_sessions
                )));
            }
        }

        // Create new session
        let session = UdpSession::new(key, domain);
        let session = Arc::new(parking_lot::RwLock::new(session));
        self.sessions.insert(key, session.clone());
        self.stats.sessions_created.fetch_add(1, Ordering::Relaxed);

        debug!("UDP session created: {} -> {}", src, dst);
        Ok(session)
    }

    /// Get or create a session with type detection
    pub fn get_or_create_session_with_detection(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        domain: Option<String>,
        payload: &[u8],
    ) -> Result<Arc<parking_lot::RwLock<UdpSession>>> {
        let key = NatKey::new(src, dst);

        // Try to get existing session
        if let Some(session) = self.sessions.get(&key) {
            let mut sess = session.write();
            sess.touch();
            
            // Update session type if still unknown
            if sess.session_type() == UdpSessionType::Unknown {
                let session_type = UdpSessionType::detect(
                    dst.port(),
                    payload,
                    &self.config.quic_ports,
                );
                sess.set_session_type(session_type);
                
                if session_type == UdpSessionType::Quic {
                    self.stats.quic_sessions.fetch_add(1, Ordering::Relaxed);
                    info!("QUIC session detected: {} -> {}", src, dst);
                }
            }
            
            return Ok(session.clone());
        }

        // Check session limit
        if self.sessions.len() >= self.config.max_sessions {
            self.cleanup();
            if self.sessions.len() >= self.config.max_sessions {
                return Err(SolidTcpError::UdpError(format!(
                    "Max UDP sessions reached: {}",
                    self.config.max_sessions
                )));
            }
        }

        // Detect session type
        let session_type = UdpSessionType::detect(
            dst.port(),
            payload,
            &self.config.quic_ports,
        );

        // Create new session with type
        let session = UdpSession::new_with_type(key, domain, session_type);
        let session = Arc::new(parking_lot::RwLock::new(session));
        self.sessions.insert(key, session.clone());
        self.stats.sessions_created.fetch_add(1, Ordering::Relaxed);

        match session_type {
            UdpSessionType::Quic => {
                self.stats.quic_sessions.fetch_add(1, Ordering::Relaxed);
                info!("QUIC session created: {} -> {}", src, dst);
            }
            UdpSessionType::Dns => {
                self.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                debug!("DNS session created: {} -> {}", src, dst);
            }
            _ => {
                debug!("UDP session created: {} -> {}", src, dst);
            }
        }

        Ok(session)
    }

    /// Get an existing session
    pub fn get_session(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Option<Arc<parking_lot::RwLock<UdpSession>>> {
        let key = NatKey::new(src, dst);
        self.sessions.get(&key).map(|s| s.clone())
    }

    /// Remove a session
    pub fn remove_session(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Option<Arc<parking_lot::RwLock<UdpSession>>> {
        let key = NatKey::new(src, dst);
        if let Some((_, session)) = self.sessions.remove(&key) {
            self.stats.sessions_closed.fetch_add(1, Ordering::Relaxed);
            Some(session)
        } else {
            None
        }
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Record sent data
    pub fn record_sent(&self, src: SocketAddr, dst: SocketAddr, bytes: usize) {
        let key = NatKey::new(src, dst);
        if let Some(session) = self.sessions.get(&key) {
            session.read().record_sent(bytes);
        }
        self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record received data
    pub fn record_recv(&self, src: SocketAddr, dst: SocketAddr, bytes: usize) {
        let key = NatKey::new(src, dst);
        if let Some(session) = self.sessions.get(&key) {
            session.read().record_recv(bytes);
        }
        self.stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Cleanup expired sessions
    pub fn cleanup(&self) {
        let regular_timeout = self.config.session_timeout;
        let quic_timeout = self.config.quic_session_timeout;

        let to_remove: Vec<_> = self
            .sessions
            .iter()
            .filter(|entry| {
                let session = entry.read();
                session.state == UdpSessionState::Closed
                    || session.is_timed_out(regular_timeout, quic_timeout)
            })
            .map(|entry| *entry.key())
            .collect();

        for key in to_remove {
            if let Some((_, session)) = self.sessions.remove(&key) {
                let sess = session.read();
                let stats = sess.stats();
                self.stats.sessions_closed.fetch_add(1, Ordering::Relaxed);
                trace!(
                    "UDP session cleaned up: {:?} (type={:?}, sent={}, recv={})",
                    key, stats.session_type, stats.bytes_sent, stats.bytes_recv
                );
            }
        }

        // Also cleanup relay sockets that are no longer needed
        self.cleanup_relay_sockets();
    }

    /// Cleanup unused relay sockets
    fn cleanup_relay_sockets(&self) {
        let active_dsts: std::collections::HashSet<_> = self
            .sessions
            .iter()
            .map(|e| e.key().dst)
            .collect();

        self.relay_sockets.retain(|addr, _| active_dsts.contains(addr));
    }

    /// Get statistics
    pub fn stats(&self) -> &UdpManagerStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &UdpConfig {
        &self.config
    }

    /// Iterate over all sessions
    pub fn iter(&self) -> impl Iterator<Item = Arc<parking_lot::RwLock<UdpSession>>> + '_ {
        self.sessions.iter().map(|e| e.clone())
    }

    /// Get or create a relay socket for direct forwarding
    pub async fn get_or_create_relay_socket(
        &self,
        target: SocketAddr,
    ) -> Result<Arc<TokioUdpSocket>> {
        // Check cache first
        if let Some(socket) = self.relay_sockets.get(&target) {
            return Ok(socket.clone());
        }

        // Create new socket
        let bind_addr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = TokioUdpSocket::bind(bind_addr)
            .await
            .map_err(|e| SolidTcpError::UdpError(format!("Failed to bind relay socket: {}", e)))?;

        let socket = Arc::new(socket);
        self.relay_sockets.insert(target, socket.clone());

        Ok(socket)
    }

    /// Close all sessions
    pub fn close_all(&self) {
        let keys: Vec<_> = self.sessions.iter().map(|e| *e.key()).collect();
        for key in keys {
            if let Some((_, session)) = self.sessions.remove(&key) {
                session.write().close();
                self.stats.sessions_closed.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.relay_sockets.clear();
    }
}

impl Default for UdpManager {
    fn default() -> Self {
        Self::new()
    }
}
