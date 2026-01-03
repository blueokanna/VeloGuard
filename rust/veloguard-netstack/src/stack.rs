use crate::error::{NetStackError, Result};
use crate::tcp::{TcpListener, TcpStack};
use crate::tun::{TunConfig, TunDevice};
use crate::udp::{UdpListener, UdpStack};
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv6Packet,
    TcpPacket, UdpPacket as SmolUdpPacket,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, trace};

/// Network stack configuration
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// TUN device configuration
    pub tun: TunConfig,
    /// Enable TCP handling
    pub enable_tcp: bool,
    /// Enable UDP handling
    pub enable_udp: bool,
    /// TCP buffer size
    pub tcp_buffer_size: usize,
    /// UDP buffer size
    pub udp_buffer_size: usize,
    /// Maximum concurrent TCP connections
    pub max_tcp_connections: usize,
    /// Maximum UDP sessions
    pub max_udp_sessions: usize,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            tun: TunConfig::default(),
            enable_tcp: true,
            enable_udp: true,
            tcp_buffer_size: 64 * 1024,
            udp_buffer_size: 64 * 1024,
            max_tcp_connections: 10000,
            max_udp_sessions: 10000,
        }
    }
}

/// Network stack statistics
#[derive(Debug, Default)]
pub struct StackStats {
    /// Total packets received from TUN
    pub packets_received: AtomicU64,
    /// Total packets sent to TUN
    pub packets_sent: AtomicU64,
    /// Total TCP packets processed
    pub tcp_packets: AtomicU64,
    /// Total UDP packets processed
    pub udp_packets: AtomicU64,
    /// Total bytes uploaded
    pub bytes_uploaded: AtomicU64,
    /// Total bytes downloaded
    pub bytes_downloaded: AtomicU64,
    /// Dropped packets
    pub packets_dropped: AtomicU64,
}

impl StackStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    pub fn tcp_packets(&self) -> u64 {
        self.tcp_packets.load(Ordering::Relaxed)
    }

    pub fn udp_packets(&self) -> u64 {
        self.udp_packets.load(Ordering::Relaxed)
    }

    pub fn bytes_uploaded(&self) -> u64 {
        self.bytes_uploaded.load(Ordering::Relaxed)
    }

    pub fn bytes_downloaded(&self) -> u64 {
        self.bytes_downloaded.load(Ordering::Relaxed)
    }
}

/// The main network stack
pub struct NetStack {
    config: StackConfig,
    tun_device: Option<TunDevice>,
    tcp_stack: TcpStack,
    udp_stack: UdpStack,
    stats: Arc<StackStats>,
    running: Arc<AtomicBool>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl NetStack {
    /// Create a new network stack with default configuration
    pub async fn new() -> Result<Self> {
        Self::with_config(StackConfig::default()).await
    }

    /// Create a new network stack with custom configuration
    pub async fn with_config(config: StackConfig) -> Result<Self> {
        let tcp_stack = TcpStack::new();
        let udp_stack = UdpStack::new();

        Ok(Self {
            config,
            tun_device: None,
            tcp_stack,
            udp_stack,
            stats: Arc::new(StackStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx: None,
        })
    }

    /// Create and setup TUN device
    pub async fn create_tun(&mut self, name: &str, addr: &str, netmask: &str) -> Result<()> {
        let mut config = self.config.tun.clone();
        config.name = name.to_string();
        config.address = addr.parse().map_err(|e| NetStackError::Parse(format!("{}", e)))?;
        config.netmask = netmask.parse().map_err(|e| NetStackError::Parse(format!("{}", e)))?;

        let tun = TunDevice::with_config(config).await?;
        self.tun_device = Some(tun);
        Ok(())
    }

    /// Create TUN device with full configuration
    pub async fn create_tun_with_config(&mut self, config: TunConfig) -> Result<()> {
        let tun = TunDevice::with_config(config).await?;
        self.tun_device = Some(tun);
        Ok(())
    }

    /// Start the network stack
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        info!("Starting network stack");

        // Start TUN device
        if let Some(tun) = &mut self.tun_device {
            tun.start().await?;
        } else {
            return Err(NetStackError::TunError("TUN device not created".to_string()));
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Get TUN packet channels
        let _tun_sender = self.tun_device.as_ref().unwrap().get_sender()
            .ok_or_else(|| NetStackError::TunError("TUN sender not available".to_string()))?;
        let mut tun_receiver = self.tun_device.as_mut().unwrap().take_receiver()
            .ok_or_else(|| NetStackError::TunError("TUN receiver not available".to_string()))?;

        let running = self.running.clone();
        let stats = self.stats.clone();
        let enable_tcp = self.config.enable_tcp;
        let enable_udp = self.config.enable_udp;

        // Clone stacks for the processing task
        // Note: In a real implementation, we'd use Arc<Mutex<>> or similar
        // For now, we'll process packets inline

        running.store(true, Ordering::Relaxed);

        // Spawn packet processing task
        tokio::spawn(async move {
            info!("Packet processing task started");

            loop {
                tokio::select! {
                    // Receive packet from TUN
                    Some(packet) = tun_receiver.recv() => {
                        stats.packets_received.fetch_add(1, Ordering::Relaxed);
                        
                        if let Err(e) = process_ip_packet(&packet, &stats, enable_tcp, enable_udp) {
                            trace!("Failed to process packet: {}", e);
                            stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    // Shutdown signal
                    _ = shutdown_rx.recv() => {
                        info!("Packet processing task shutting down");
                        break;
                    }
                }
            }

            running.store(false, Ordering::Relaxed);
            info!("Packet processing task stopped");
        });

        info!("Network stack started");
        Ok(())
    }

    /// Stop the network stack
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        info!("Stopping network stack");

        // Send shutdown signal
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        // Stop TUN device
        if let Some(tun) = &mut self.tun_device {
            tun.stop().await?;
        }

        // Close all connections
        self.tcp_stack.close_all();
        self.udp_stack.close_all();

        self.running.store(false, Ordering::Relaxed);
        info!("Network stack stopped");
        Ok(())
    }

    /// Check if the stack is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get stack statistics
    pub fn stats(&self) -> &Arc<StackStats> {
        &self.stats
    }

    /// Get TCP listener for accepting new connections
    pub fn tcp_listener(&mut self) -> Option<TcpListener> {
        self.tcp_stack.take_listener()
    }

    /// Get UDP listener for accepting new sessions
    pub fn udp_listener(&mut self) -> Option<UdpListener> {
        self.udp_stack.take_listener()
    }

    /// Get the TCP stack reference
    pub fn tcp_stack(&self) -> &TcpStack {
        &self.tcp_stack
    }

    /// Get the UDP stack reference
    pub fn udp_stack(&self) -> &UdpStack {
        &self.udp_stack
    }

    /// Get the TUN device reference
    pub fn tun_device(&self) -> Option<&TunDevice> {
        self.tun_device.as_ref()
    }

    /// Get configuration
    pub fn config(&self) -> &StackConfig {
        &self.config
    }
}

/// Process an IP packet from the TUN device
fn process_ip_packet(
    packet: &[u8],
    stats: &StackStats,
    enable_tcp: bool,
    enable_udp: bool,
) -> Result<()> {
    if packet.is_empty() {
        return Err(NetStackError::InvalidPacket("Empty packet".to_string()));
    }

    // Determine IP version
    let version = (packet[0] >> 4) & 0x0F;

    match version {
        4 => process_ipv4_packet(packet, stats, enable_tcp, enable_udp),
        6 => process_ipv6_packet(packet, stats, enable_tcp, enable_udp),
        _ => Err(NetStackError::InvalidPacket(format!("Unknown IP version: {}", version))),
    }
}

/// Process an IPv4 packet
fn process_ipv4_packet(
    packet: &[u8],
    stats: &StackStats,
    enable_tcp: bool,
    enable_udp: bool,
) -> Result<()> {
    let ipv4 = Ipv4Packet::new_checked(packet)
        .map_err(|e| NetStackError::InvalidPacket(format!("Invalid IPv4 packet: {}", e)))?;

    let src_ip = IpAddr::V4(Ipv4Addr::from(ipv4.src_addr()));
    let dst_ip = IpAddr::V4(Ipv4Addr::from(ipv4.dst_addr()));
    let protocol = ipv4.next_header();
    let payload = ipv4.payload();

    match protocol {
        IpProtocol::Tcp if enable_tcp => {
            stats.tcp_packets.fetch_add(1, Ordering::Relaxed);
            process_tcp_packet(src_ip, dst_ip, payload, stats)
        }
        IpProtocol::Udp if enable_udp => {
            stats.udp_packets.fetch_add(1, Ordering::Relaxed);
            process_udp_packet(src_ip, dst_ip, payload, stats)
        }
        IpProtocol::Icmp => {
            trace!("ICMP packet from {} to {}", src_ip, dst_ip);
            Ok(()) // Ignore ICMP for now
        }
        _ => {
            trace!("Unsupported protocol: {:?}", protocol);
            Ok(())
        }
    }
}

/// Process an IPv6 packet
fn process_ipv6_packet(
    packet: &[u8],
    stats: &StackStats,
    enable_tcp: bool,
    enable_udp: bool,
) -> Result<()> {
    let ipv6 = Ipv6Packet::new_checked(packet)
        .map_err(|e| NetStackError::InvalidPacket(format!("Invalid IPv6 packet: {}", e)))?;

    let src_ip = IpAddr::V6(Ipv6Addr::from(ipv6.src_addr()));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(ipv6.dst_addr()));
    let protocol = ipv6.next_header();
    let payload = ipv6.payload();

    match protocol {
        IpProtocol::Tcp if enable_tcp => {
            stats.tcp_packets.fetch_add(1, Ordering::Relaxed);
            process_tcp_packet(src_ip, dst_ip, payload, stats)
        }
        IpProtocol::Udp if enable_udp => {
            stats.udp_packets.fetch_add(1, Ordering::Relaxed);
            process_udp_packet(src_ip, dst_ip, payload, stats)
        }
        IpProtocol::Icmpv6 => {
            trace!("ICMPv6 packet from {} to {}", src_ip, dst_ip);
            Ok(())
        }
        _ => {
            trace!("Unsupported protocol: {:?}", protocol);
            Ok(())
        }
    }
}

/// Process a TCP packet
fn process_tcp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    payload: &[u8],
    stats: &StackStats,
) -> Result<()> {
    let tcp = TcpPacket::new_checked(payload)
        .map_err(|e| NetStackError::InvalidPacket(format!("Invalid TCP packet: {}", e)))?;

    let src_port = tcp.src_port();
    let dst_port = tcp.dst_port();
    let src_addr = SocketAddr::new(src_ip, src_port);
    let dst_addr = SocketAddr::new(dst_ip, dst_port);

    let syn = tcp.syn();
    let ack = tcp.ack();
    let fin = tcp.fin();
    let rst = tcp.rst();
    let payload_len = tcp.payload().len();

    // Log SYN packets for debugging
    if syn && !ack {
        info!(
            "TCP SYN: {} -> {} (new connection request)",
            src_addr, dst_addr
        );
    } else {
        trace!(
            "TCP {} -> {} syn={} ack={} fin={} rst={} len={}",
            src_addr, dst_addr, syn, ack, fin, rst, payload_len
        );
    }

    stats.bytes_uploaded.fetch_add(payload_len as u64, Ordering::Relaxed);

    // TCP connection handling would be done here
    // For now, we just log the packet

    Ok(())
}

/// Process a UDP packet
fn process_udp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    payload: &[u8],
    stats: &StackStats,
) -> Result<()> {
    let udp = SmolUdpPacket::new_checked(payload)
        .map_err(|e| NetStackError::InvalidPacket(format!("Invalid UDP packet: {}", e)))?;

    let src_port = udp.src_port();
    let dst_port = udp.dst_port();
    let src_addr = SocketAddr::new(src_ip, src_port);
    let dst_addr = SocketAddr::new(dst_ip, dst_port);

    let payload_len = udp.payload().len();

    trace!(
        "UDP {} -> {} len={}",
        src_addr, dst_addr, payload_len
    );

    stats.bytes_uploaded.fetch_add(payload_len as u64, Ordering::Relaxed);

    // UDP session handling would be done here
    // For now, we just log the packet

    Ok(())
}

/// Builder for creating a NetStack with custom configuration
pub struct NetStackBuilder {
    config: StackConfig,
}

impl NetStackBuilder {
    pub fn new() -> Self {
        Self {
            config: StackConfig::default(),
        }
    }

    pub fn tun_name(mut self, name: &str) -> Self {
        self.config.tun.name = name.to_string();
        self
    }

    pub fn tun_address(mut self, addr: Ipv4Addr) -> Self {
        self.config.tun.address = addr;
        self
    }

    pub fn tun_netmask(mut self, netmask: Ipv4Addr) -> Self {
        self.config.tun.netmask = netmask;
        self
    }

    pub fn tun_mtu(mut self, mtu: u16) -> Self {
        self.config.tun.mtu = mtu;
        self
    }

    pub fn enable_tcp(mut self, enable: bool) -> Self {
        self.config.enable_tcp = enable;
        self
    }

    pub fn enable_udp(mut self, enable: bool) -> Self {
        self.config.enable_udp = enable;
        self
    }

    pub fn tcp_buffer_size(mut self, size: usize) -> Self {
        self.config.tcp_buffer_size = size;
        self
    }

    pub fn udp_buffer_size(mut self, size: usize) -> Self {
        self.config.udp_buffer_size = size;
        self
    }

    pub fn max_tcp_connections(mut self, max: usize) -> Self {
        self.config.max_tcp_connections = max;
        self
    }

    pub fn max_udp_sessions(mut self, max: usize) -> Self {
        self.config.max_udp_sessions = max;
        self
    }

    pub async fn build(self) -> Result<NetStack> {
        NetStack::with_config(self.config).await
    }
}

impl Default for NetStackBuilder {
    fn default() -> Self {
        Self::new()
    }
}
