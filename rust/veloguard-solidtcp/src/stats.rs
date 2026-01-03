//! Statistics tracking for the TCP/IP stack
//!
//! Provides comprehensive statistics for monitoring and debugging.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Stack-wide statistics
#[derive(Debug, Default)]
pub struct StackStats {
    /// Start time
    start_time: Option<Instant>,
    
    // Packet statistics
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub packets_invalid: AtomicU64,
    
    // Byte statistics
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    
    // Protocol statistics
    pub tcp_packets: AtomicU64,
    pub udp_packets: AtomicU64,
    pub icmp_packets: AtomicU64,
    pub other_packets: AtomicU64,
    
    // Connection statistics
    pub tcp_connections_total: AtomicU64,
    pub tcp_connections_active: AtomicU64,
    pub udp_sessions_total: AtomicU64,
    pub udp_sessions_active: AtomicU64,
    
    // DNS statistics
    pub dns_queries: AtomicU64,
    pub dns_responses: AtomicU64,
    pub fake_ip_allocations: AtomicU64,
    
    // Error statistics
    pub checksum_errors: AtomicU64,
    pub parse_errors: AtomicU64,
    pub timeout_errors: AtomicU64,
    pub proxy_errors: AtomicU64,
}

impl StackStats {
    /// Create new statistics tracker
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Record received packet
    pub fn record_received(&self, bytes: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record sent packet
    pub fn record_sent(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record dropped packet
    pub fn record_dropped(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record invalid packet
    pub fn record_invalid(&self) {
        self.packets_invalid.fetch_add(1, Ordering::Relaxed);
    }

    /// Record TCP packet
    pub fn record_tcp(&self) {
        self.tcp_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Record UDP packet
    pub fn record_udp(&self) {
        self.udp_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Record ICMP packet
    pub fn record_icmp(&self) {
        self.icmp_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Record other protocol packet
    pub fn record_other(&self) {
        self.other_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Record new TCP connection
    pub fn record_tcp_connection(&self) {
        self.tcp_connections_total.fetch_add(1, Ordering::Relaxed);
        self.tcp_connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record TCP connection closed
    pub fn record_tcp_closed(&self) {
        self.tcp_connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record new UDP session
    pub fn record_udp_session(&self) {
        self.udp_sessions_total.fetch_add(1, Ordering::Relaxed);
        self.udp_sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record UDP session closed
    pub fn record_udp_closed(&self) {
        self.udp_sessions_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record DNS query
    pub fn record_dns_query(&self) {
        self.dns_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Record DNS response
    pub fn record_dns_response(&self) {
        self.dns_responses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record Fake-IP allocation
    pub fn record_fake_ip(&self) {
        self.fake_ip_allocations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record checksum error
    pub fn record_checksum_error(&self) {
        self.checksum_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record parse error
    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record timeout error
    pub fn record_timeout(&self) {
        self.timeout_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record proxy error
    pub fn record_proxy_error(&self) {
        self.proxy_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get snapshot of all statistics
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            uptime: self.uptime(),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_invalid: self.packets_invalid.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            tcp_packets: self.tcp_packets.load(Ordering::Relaxed),
            udp_packets: self.udp_packets.load(Ordering::Relaxed),
            icmp_packets: self.icmp_packets.load(Ordering::Relaxed),
            other_packets: self.other_packets.load(Ordering::Relaxed),
            tcp_connections_total: self.tcp_connections_total.load(Ordering::Relaxed),
            tcp_connections_active: self.tcp_connections_active.load(Ordering::Relaxed),
            udp_sessions_total: self.udp_sessions_total.load(Ordering::Relaxed),
            udp_sessions_active: self.udp_sessions_active.load(Ordering::Relaxed),
            dns_queries: self.dns_queries.load(Ordering::Relaxed),
            dns_responses: self.dns_responses.load(Ordering::Relaxed),
            fake_ip_allocations: self.fake_ip_allocations.load(Ordering::Relaxed),
            checksum_errors: self.checksum_errors.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            timeout_errors: self.timeout_errors.load(Ordering::Relaxed),
            proxy_errors: self.proxy_errors.load(Ordering::Relaxed),
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.packets_received.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_dropped.store(0, Ordering::Relaxed);
        self.packets_invalid.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.tcp_packets.store(0, Ordering::Relaxed);
        self.udp_packets.store(0, Ordering::Relaxed);
        self.icmp_packets.store(0, Ordering::Relaxed);
        self.other_packets.store(0, Ordering::Relaxed);
        self.dns_queries.store(0, Ordering::Relaxed);
        self.dns_responses.store(0, Ordering::Relaxed);
        self.fake_ip_allocations.store(0, Ordering::Relaxed);
        self.checksum_errors.store(0, Ordering::Relaxed);
        self.parse_errors.store(0, Ordering::Relaxed);
        self.timeout_errors.store(0, Ordering::Relaxed);
        self.proxy_errors.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of statistics at a point in time
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub uptime: Duration,
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_dropped: u64,
    pub packets_invalid: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub other_packets: u64,
    pub tcp_connections_total: u64,
    pub tcp_connections_active: u64,
    pub udp_sessions_total: u64,
    pub udp_sessions_active: u64,
    pub dns_queries: u64,
    pub dns_responses: u64,
    pub fake_ip_allocations: u64,
    pub checksum_errors: u64,
    pub parse_errors: u64,
    pub timeout_errors: u64,
    pub proxy_errors: u64,
}

impl StatsSnapshot {
    /// Calculate packets per second (requires two snapshots)
    pub fn packets_per_second(&self, previous: &StatsSnapshot, interval: Duration) -> f64 {
        let delta = self.packets_received.saturating_sub(previous.packets_received);
        delta as f64 / interval.as_secs_f64()
    }

    /// Calculate bytes per second (requires two snapshots)
    pub fn bytes_per_second(&self, previous: &StatsSnapshot, interval: Duration) -> f64 {
        let delta = self.bytes_received.saturating_sub(previous.bytes_received);
        delta as f64 / interval.as_secs_f64()
    }

    /// Get total connections (TCP + UDP)
    pub fn total_connections(&self) -> u64 {
        self.tcp_connections_active + self.udp_sessions_active
    }
}

/// Per-connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub retransmits: u64,
    pub rtt_samples: u64,
    pub rtt_sum_us: u64,
}

impl ConnectionStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
    }

    pub fn record_recv(&mut self, bytes: usize) {
        self.bytes_recv += bytes as u64;
        self.packets_recv += 1;
    }

    pub fn record_retransmit(&mut self) {
        self.retransmits += 1;
    }

    pub fn record_rtt(&mut self, rtt_us: u64) {
        self.rtt_samples += 1;
        self.rtt_sum_us += rtt_us;
    }

    pub fn average_rtt_us(&self) -> Option<u64> {
        if self.rtt_samples > 0 {
            Some(self.rtt_sum_us / self.rtt_samples)
        } else {
            None
        }
    }
}
