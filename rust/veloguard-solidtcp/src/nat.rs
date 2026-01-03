//! NAT table for connection tracking

use crate::error::{Result, SolidTcpError};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// NAT entry state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatState {
    Active,
    Establishing,
    Closing,
    Closed,
}

/// NAT entry
#[derive(Debug, Clone)]
pub struct NatEntry {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub local_port: u16,
    pub created: Instant,
    pub last_active: Instant,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub state: NatState,
    pub domain: Option<String>,
}

/// NAT key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl NatKey {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }
}

/// NAT configuration
#[derive(Debug, Clone)]
pub struct NatConfig {
    pub max_entries: usize,
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
    pub port_start: u16,
    pub port_end: u16,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            max_entries: 65536,
            tcp_timeout: Duration::from_secs(300),
            udp_timeout: Duration::from_secs(60),
            port_start: 10000,
            port_end: 60000,
        }
    }
}

/// NAT table
pub struct NatTable {
    tcp: DashMap<NatKey, NatEntry>,
    udp: DashMap<NatKey, NatEntry>,
    reverse_tcp: DashMap<u16, NatKey>,
    reverse_udp: DashMap<u16, NatKey>,
    config: NatConfig,
    next_port: AtomicU64,
}

impl NatTable {
    pub fn new() -> Self {
        Self::with_config(NatConfig::default())
    }

    pub fn with_config(config: NatConfig) -> Self {
        Self {
            tcp: DashMap::new(),
            udp: DashMap::new(),
            reverse_tcp: DashMap::new(),
            reverse_udp: DashMap::new(),
            next_port: AtomicU64::new(config.port_start as u64),
            config,
        }
    }

    fn alloc_port(&self) -> u16 {
        let range = (self.config.port_end - self.config.port_start) as u64;
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        self.config.port_start + ((port - self.config.port_start as u64) % range) as u16
    }

    pub fn insert_tcp(&self, src: SocketAddr, dst: SocketAddr, domain: Option<String>) -> Result<NatEntry> {
        let key = NatKey::new(src, dst);
        if let Some(e) = self.tcp.get(&key) {
            return Ok(e.clone());
        }
        if self.tcp.len() >= self.config.max_entries {
            return Err(SolidTcpError::NatTableFull(self.config.max_entries));
        }

        let now = Instant::now();
        let entry = NatEntry {
            src, dst,
            local_port: self.alloc_port(),
            created: now,
            last_active: now,
            bytes_tx: 0,
            bytes_rx: 0,
            state: NatState::Establishing,
            domain,
        };
        self.tcp.insert(key, entry.clone());
        self.reverse_tcp.insert(entry.local_port, key);
        Ok(entry)
    }

    pub fn insert_udp(&self, src: SocketAddr, dst: SocketAddr, domain: Option<String>) -> Result<NatEntry> {
        let key = NatKey::new(src, dst);
        if let Some(e) = self.udp.get(&key) {
            return Ok(e.clone());
        }
        if self.udp.len() >= self.config.max_entries {
            return Err(SolidTcpError::NatTableFull(self.config.max_entries));
        }

        let now = Instant::now();
        let entry = NatEntry {
            src, dst,
            local_port: self.alloc_port(),
            created: now,
            last_active: now,
            bytes_tx: 0,
            bytes_rx: 0,
            state: NatState::Active,
            domain,
        };
        self.udp.insert(key, entry.clone());
        self.reverse_udp.insert(entry.local_port, key);
        Ok(entry)
    }

    pub fn get_tcp(&self, src: SocketAddr, dst: SocketAddr) -> Option<NatEntry> {
        self.tcp.get(&NatKey::new(src, dst)).map(|e| e.clone())
    }

    pub fn get_udp(&self, src: SocketAddr, dst: SocketAddr) -> Option<NatEntry> {
        self.udp.get(&NatKey::new(src, dst)).map(|e| e.clone())
    }

    pub fn update_tcp_state(&self, src: SocketAddr, dst: SocketAddr, state: NatState) {
        if let Some(mut e) = self.tcp.get_mut(&NatKey::new(src, dst)) {
            e.state = state;
            e.last_active = Instant::now();
        }
    }

    pub fn remove_tcp(&self, src: SocketAddr, dst: SocketAddr) {
        let key = NatKey::new(src, dst);
        if let Some((_, e)) = self.tcp.remove(&key) {
            self.reverse_tcp.remove(&e.local_port);
        }
    }

    pub fn remove_udp(&self, src: SocketAddr, dst: SocketAddr) {
        let key = NatKey::new(src, dst);
        if let Some((_, e)) = self.udp.remove(&key) {
            self.reverse_udp.remove(&e.local_port);
        }
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        let tcp_timeout = self.config.tcp_timeout;
        let udp_timeout = self.config.udp_timeout;

        let tcp_expired: Vec<_> = self.tcp.iter()
            .filter(|e| now.duration_since(e.last_active) > tcp_timeout || e.state == NatState::Closed)
            .map(|e| *e.key())
            .collect();
        for key in tcp_expired {
            if let Some((_, e)) = self.tcp.remove(&key) {
                self.reverse_tcp.remove(&e.local_port);
            }
        }

        let udp_expired: Vec<_> = self.udp.iter()
            .filter(|e| now.duration_since(e.last_active) > udp_timeout)
            .map(|e| *e.key())
            .collect();
        for key in udp_expired {
            if let Some((_, e)) = self.udp.remove(&key) {
                self.reverse_udp.remove(&e.local_port);
            }
        }
    }

    pub fn tcp_count(&self) -> usize { self.tcp.len() }
    pub fn udp_count(&self) -> usize { self.udp.len() }
    pub fn total_count(&self) -> usize { self.tcp_count() + self.udp_count() }

    pub fn clear(&self) {
        self.tcp.clear();
        self.udp.clear();
        self.reverse_tcp.clear();
        self.reverse_udp.clear();
    }
}

impl Default for NatTable {
    fn default() -> Self { Self::new() }
}
