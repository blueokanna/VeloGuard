//! Platform-neutral TUN packet processing runtime.

use crate::error::{NetStackError, Result};
use crate::solidtcp::{SolidStack, StackBuilder, StackStats};
use bytes::BytesMut;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::{net::Ipv4Addr, net::SocketAddr};
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Traffic counters exposed to platform bridges.
#[derive(Debug, Clone, Default)]
pub struct TunTrafficStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub tcp_connections: usize,
    pub udp_sessions: usize,
    pub dns_queries: u64,
}

/// Owns the userspace TCP/IP stack that translates TUN packets to the local
/// SOCKS inbound. Platform code only owns the TUN descriptor and lifecycle.
pub struct TunPacketProcessor {
    stack: Arc<SolidStack>,
    running: AtomicBool,
    packet_count: AtomicU64,
}

impl TunPacketProcessor {
    pub fn new(proxy_port: u16, mtu: u16, tun_tx: mpsc::Sender<BytesMut>) -> Self {
        Self::new_with_proxy_addr(
            SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port)),
            mtu,
            tun_tx,
        )
    }

    pub fn new_with_proxy_addr(
        proxy_addr: SocketAddr,
        mtu: u16,
        tun_tx: mpsc::Sender<BytesMut>,
    ) -> Self {
        let mut stack = StackBuilder::new()
            .proxy_addr(proxy_addr)
            .mtu(usize::from(mtu))
            .dns_intercept(true)
            .build();
        stack.set_tun_tx(tun_tx);
        stack.start();

        let stack = Arc::new(stack);
        let cleanup_stack = Arc::clone(&stack);
        tokio::spawn(async move {
            cleanup_stack.run_cleanup().await;
        });

        info!(%proxy_addr, mtu, "TUN packet processor started");
        Self {
            stack,
            running: AtomicBool::new(true),
            packet_count: AtomicU64::new(0),
        }
    }

    pub async fn process_packet(&self, packet: &[u8]) -> Result<()> {
        if !self.is_running() {
            return Err(NetStackError::NotRunning);
        }
        if packet.is_empty() {
            return Err(NetStackError::InvalidPacket("empty TUN packet".to_string()));
        }

        let packet_number = self.packet_count.fetch_add(1, Ordering::Relaxed) + 1;
        if packet_number <= 10 || packet_number.is_multiple_of(500) {
            debug!(packet_number, bytes = packet.len(), "processing TUN packet");
        }

        self.stack
            .process_packet(packet)
            .await
            .map_err(|error| NetStackError::InvalidPacket(error.to_string()))
    }

    pub fn connection_count(&self) -> usize {
        self.stack.connection_count()
    }

    pub fn stats(&self) -> &Arc<StackStats> {
        self.stack.stats()
    }

    pub fn traffic_stats(&self) -> TunTrafficStats {
        let snapshot = self.stack.stats().snapshot();
        TunTrafficStats {
            packets_received: snapshot.packets_received,
            packets_sent: snapshot.packets_sent,
            bytes_received: snapshot.bytes_received,
            bytes_sent: snapshot.bytes_sent,
            tcp_connections: self.stack.tcp_manager().connection_count(),
            udp_sessions: self.stack.udp_manager().session_count(),
            dns_queries: snapshot.dns_queries,
        }
    }

    pub fn get_traffic_stats(&self) -> TunTrafficStats {
        self.traffic_stats()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub fn stop(&self) {
        if self.running.swap(false, Ordering::AcqRel) {
            self.stack.stop();
            info!(
                packets = self.packet_count.load(Ordering::Relaxed),
                "TUN packet processor stopped"
            );
        }
    }

    pub fn reset(&self) {
        self.stack.fake_ip_pool().clear();
        self.stack.nat_table().clear();
        self.stack.tcp_manager().cleanup();
        self.stack.udp_manager().cleanup();
        self.packet_count.store(0, Ordering::Relaxed);
    }

    pub fn reset_fake_ip_pool(&self) {
        self.stack.fake_ip_pool().clear();
    }
}

impl Drop for TunPacketProcessor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    #[tokio::test]
    async fn processor_rejects_packets_after_stop() {
        let (tx, _rx) = mpsc::channel(1);
        let processor = TunPacketProcessor::new(7890, 1500, tx);
        processor.stop();
        assert!(matches!(
            processor.process_packet(&[0x45]).await,
            Err(NetStackError::NotRunning)
        ));
    }

    #[tokio::test]
    async fn processor_rejects_empty_packets() {
        let (tx, _rx) = mpsc::channel(1);
        let processor = TunPacketProcessor::new(7890, 1500, tx);
        assert!(matches!(
            processor.process_packet(&[]).await,
            Err(NetStackError::InvalidPacket(_))
        ));
    }

    #[tokio::test]
    async fn processor_preserves_ipv6_proxy_endpoint() {
        let (tx, _rx) = mpsc::channel(1);
        let proxy_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 7890);
        let processor = TunPacketProcessor::new_with_proxy_addr(proxy_addr, 1500, tx);

        assert_eq!(processor.stack.proxy_addr(), proxy_addr);
        processor.stop();
    }
}
