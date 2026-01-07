//! Android VPN packet processor using SolidTCP stack
//!
//! This module provides the integration between Android VPN service
//! and the SolidTCP user-space TCP/IP stack.

use bytes::BytesMut;
use crate::solidtcp::{SolidStack, StackBuilder, StackStats};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Android VPN packet processor
///
/// This processor reads IP packets from the TUN device and processes them
/// through the SolidTCP stack for transparent proxying.
#[allow(dead_code)]
pub struct AndroidVpnProcessor {
    /// The SolidTCP stack
    stack: Arc<SolidStack>,
    /// Channel to send packets back to TUN
    tun_tx: mpsc::Sender<BytesMut>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Packet counter for debugging
    packet_count: AtomicU64,
}

/// VPN traffic statistics for external tracking
#[derive(Debug, Clone, Default)]
pub struct VpnTrafficStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub tcp_connections: usize,
    pub udp_sessions: usize,
    pub dns_queries: u64,
}

impl AndroidVpnProcessor {
    /// Create a new Android VPN processor
    pub fn new(proxy_port: u16, tun_tx: mpsc::Sender<BytesMut>) -> Self {
        info!("Creating AndroidVpnProcessor with proxy_port={}", proxy_port);
        
        // Build the SolidTCP stack with configuration
        let mut stack = StackBuilder::new()
            .proxy_port(proxy_port)
            .mtu(1500)
            .dns_intercept(true)
            .build();

        // Set the TUN write channel
        stack.set_tun_tx(tun_tx.clone());
        stack.start();
        
        info!("SolidTCP stack started");

        let stack = Arc::new(stack);

        // Start cleanup task
        let stack_cleanup = stack.clone();
        tokio::spawn(async move {
            stack_cleanup.run_cleanup().await;
        });

        Self {
            stack,
            tun_tx,
            running: Arc::new(AtomicBool::new(true)),
            packet_count: AtomicU64::new(0),
        }
    }

    /// Process an IP packet from the TUN device
    pub async fn process_packet(&self, packet: &[u8]) -> crate::error::Result<()> {
        if packet.is_empty() || !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        let count = self.packet_count.fetch_add(1, Ordering::Relaxed);
        
        // Log packet info for first 100 packets and periodically
        if count < 100 || count % 500 == 0 {
            // Parse IP version and protocol
            if packet.len() >= 20 {
                let version = (packet[0] >> 4) & 0x0F;
                let protocol = packet[9];
                let proto_name = match protocol {
                    6 => "TCP",
                    17 => "UDP",
                    1 => "ICMP",
                    _ => "OTHER",
                };
                
                // Parse source and destination IPs
                let src_ip = if packet.len() >= 16 {
                    format!("{}.{}.{}.{}", packet[12], packet[13], packet[14], packet[15])
                } else {
                    "?".to_string()
                };
                let dst_ip = if packet.len() >= 20 {
                    format!("{}.{}.{}.{}", packet[16], packet[17], packet[18], packet[19])
                } else {
                    "?".to_string()
                };
                
                // Parse ports for TCP/UDP
                let ports = if protocol == 6 || protocol == 17 {
                    let ihl = ((packet[0] & 0x0F) as usize) * 4;
                    if packet.len() >= ihl + 4 {
                        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                        format!(" {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port)
                    } else {
                        format!(" {} -> {}", src_ip, dst_ip)
                    }
                } else {
                    format!(" {} -> {}", src_ip, dst_ip)
                };
                
                info!(
                    "TUN packet #{}: {} bytes, IPv{}, {}{}",
                    count, packet.len(), version, proto_name, ports
                );
            }
        }

        // Delegate to SolidTCP stack
        if let Err(e) = self.stack.process_packet(packet).await {
            debug!("Packet processing error: {}", e);
        }

        Ok(())
    }

    /// Get the current connection count
    pub fn connection_count(&self) -> usize {
        self.stack.connection_count()
    }

    /// Get stack statistics
    pub fn stats(&self) -> &Arc<StackStats> {
        self.stack.stats()
    }

    /// Get VPN traffic statistics for external tracking
    pub fn get_traffic_stats(&self) -> VpnTrafficStats {
        let stats = self.stack.stats();
        let snapshot = stats.snapshot();
        VpnTrafficStats {
            packets_received: snapshot.packets_received,
            packets_sent: snapshot.packets_sent,
            bytes_received: snapshot.bytes_received,
            bytes_sent: snapshot.bytes_sent,
            tcp_connections: self.stack.tcp_manager().connection_count(),
            udp_sessions: self.stack.udp_manager().session_count(),
            dns_queries: snapshot.dns_queries,
        }
    }

    /// Check if processor is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the processor
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.stack.stop();
        let total = self.packet_count.load(Ordering::Relaxed);
        info!("Android VPN processor stopped, processed {} packets total", total);
    }

    /// Reset the Fake-IP pool
    /// This should be called when VPN service restarts to ensure clean state
    pub fn reset_fake_ip_pool(&self) {
        self.stack.fake_ip_pool().clear();
        info!("Fake-IP pool reset via AndroidVpnProcessor");
    }

    /// Reset the entire stack state for restart
    pub fn reset(&self) {
        // Clear Fake-IP pool
        self.stack.fake_ip_pool().clear();
        // Clear NAT table
        self.stack.nat_table().clear();
        // Cleanup TCP/UDP managers
        self.stack.tcp_manager().cleanup();
        self.stack.udp_manager().cleanup();
        // Reset packet counter
        self.packet_count.store(0, Ordering::Relaxed);
        info!("AndroidVpnProcessor fully reset");
    }
}

/// Legacy exports for backward compatibility
pub use crate::solidtcp::TcpState;
pub use crate::solidtcp::NatEntry as TcpNatEntry;
