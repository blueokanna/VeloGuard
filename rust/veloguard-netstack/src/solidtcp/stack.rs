//! Main TCP/IP stack coordinator

use crate::solidtcp::device::DeviceConfig;
use crate::solidtcp::dns::{DnsHandler, FakeIpConfig, FakeIpPool};
use crate::solidtcp::error::{Result, SolidTcpError};
use crate::solidtcp::nat::{NatConfig, NatTable};
use crate::solidtcp::packet::{build_ipv4_tcp, build_ipv4_udp, parse_packet, ParsedPacket, TcpFlags, TcpInfo, TransportInfo};
use crate::solidtcp::stats::StackStats;
use crate::solidtcp::tcp::{TcpAction, TcpConfig, TcpConnection, TcpManager};
use crate::solidtcp::udp::{UdpConfig, UdpManager};
use bytes::BytesMut;
use parking_lot::RwLock;
use smoltcp::wire::IpProtocol;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

#[cfg(target_os = "android")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "android")]
static PROTECT_CALLBACK: parking_lot::RwLock<Option<Box<dyn Fn(i32) -> bool + Send + Sync>>> = parking_lot::RwLock::new(None);

#[cfg(target_os = "android")]
pub fn set_protect_callback<F>(callback: F)
where
    F: Fn(i32) -> bool + Send + Sync + 'static,
{
    let mut guard = PROTECT_CALLBACK.write();
    *guard = Some(Box::new(callback));
    info!("SolidStack: Socket protect callback registered");
}

#[cfg(target_os = "android")]
pub fn clear_protect_callback() {
    let mut guard = PROTECT_CALLBACK.write();
    *guard = None;
    info!("SolidStack: Socket protect callback cleared");
}

#[cfg(target_os = "android")]
pub fn protect_socket(fd: i32) -> bool {
    info!("=== protect_socket called for fd={} ===", fd);
    let guard = PROTECT_CALLBACK.read();
    if let Some(ref callback) = *guard {
        info!("Calling protect callback for fd={}", fd);
        let result = callback(fd);
        if result {
            info!("Socket fd={} protected successfully", fd);
        } else {
            warn!("Socket fd={} protection FAILED", fd);
        }
        result
    } else {
        warn!("No protect callback set for socket fd={} - this will cause routing loop!", fd);
        false
    }
}

#[cfg(target_os = "android")]
pub fn has_protect_callback() -> bool {
    PROTECT_CALLBACK.read().is_some()
}


#[derive(Debug, Clone)]
pub struct StackConfig {
    pub device: DeviceConfig,
    pub tcp: TcpConfig,
    pub udp: UdpConfig,
    pub nat: NatConfig,
    pub fake_ip: FakeIpConfig,
    pub proxy_port: u16,
    pub dns_intercept: bool,
    pub cleanup_interval: Duration,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            device: DeviceConfig::default(),
            tcp: TcpConfig::default(),
            udp: UdpConfig::default(),
            nat: NatConfig::default(),
            fake_ip: FakeIpConfig::default(),
            proxy_port: 7890,
            dns_intercept: true,
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

pub struct StackBuilder {
    config: StackConfig,
}

impl StackBuilder {
    pub fn new() -> Self {
        Self { config: StackConfig::default() }
    }

    pub fn proxy_port(mut self, port: u16) -> Self {
        self.config.proxy_port = port;
        self
    }

    pub fn mtu(mut self, mtu: usize) -> Self {
        self.config.device.mtu = mtu;
        self
    }

    pub fn dns_intercept(mut self, enable: bool) -> Self {
        self.config.dns_intercept = enable;
        self
    }

    pub fn fake_ip_range(mut self, start: Ipv4Addr, size: u32) -> Self {
        self.config.fake_ip.range_start = start;
        self.config.fake_ip.pool_size = size;
        self
    }

    pub fn tcp_timeout(mut self, timeout: Duration) -> Self {
        self.config.tcp.idle_timeout = timeout;
        self
    }

    pub fn udp_timeout(mut self, timeout: Duration) -> Self {
        self.config.udp.session_timeout = timeout;
        self
    }

    pub fn build(self) -> SolidStack {
        SolidStack::new(self.config)
    }
}

impl Default for StackBuilder {
    fn default() -> Self { Self::new() }
}

/// Main TCP/IP stack
pub struct SolidStack {
    config: StackConfig,
    tcp_manager: Arc<TcpManager>,
    udp_manager: Arc<UdpManager>,
    nat_table: Arc<NatTable>,
    fake_ip_pool: Arc<FakeIpPool>,
    dns_handler: Arc<DnsHandler>,
    stats: Arc<StackStats>,
    running: Arc<AtomicBool>,
    tun_tx: Option<mpsc::Sender<BytesMut>>,
}

impl SolidStack {
    pub fn new(config: StackConfig) -> Self {
        let fake_ip_pool = Arc::new(FakeIpPool::with_config(config.fake_ip.clone()));
        let dns_handler = Arc::new(DnsHandler::new(fake_ip_pool.clone()));

        Self {
            tcp_manager: Arc::new(TcpManager::with_config(config.tcp.clone())),
            udp_manager: Arc::new(UdpManager::with_config(config.udp.clone())),
            nat_table: Arc::new(NatTable::with_config(config.nat.clone())),
            fake_ip_pool,
            dns_handler,
            stats: Arc::new(StackStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            tun_tx: None,
            config,
        }
    }

    pub fn with_defaults() -> Self { Self::new(StackConfig::default()) }
    pub fn builder() -> StackBuilder { StackBuilder::new() }

    pub fn set_tun_tx(&mut self, tx: mpsc::Sender<BytesMut>) { self.tun_tx = Some(tx); }
    pub fn tun_tx(&self) -> Option<&mpsc::Sender<BytesMut>> { self.tun_tx.as_ref() }

    pub fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        info!("SolidStack started");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.tcp_manager.cleanup();
        self.udp_manager.cleanup();
        self.nat_table.clear();
        info!("SolidStack stopped");
    }

    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }
    pub fn stats(&self) -> &Arc<StackStats> { &self.stats }
    pub fn tcp_manager(&self) -> &Arc<TcpManager> { &self.tcp_manager }
    pub fn udp_manager(&self) -> &Arc<UdpManager> { &self.udp_manager }
    pub fn nat_table(&self) -> &Arc<NatTable> { &self.nat_table }
    pub fn fake_ip_pool(&self) -> &Arc<FakeIpPool> { &self.fake_ip_pool }
    pub fn dns_handler(&self) -> &Arc<DnsHandler> { &self.dns_handler }
    pub fn proxy_port(&self) -> u16 { self.config.proxy_port }

    pub fn connection_count(&self) -> usize {
        self.tcp_manager.connection_count() + self.udp_manager.session_count()
    }

    pub async fn process_packet(&self, packet: &[u8]) -> Result<()> {
        if !self.is_running() { return Ok(()); }

        self.stats.record_received(packet.len());

        let parsed = match parse_packet(packet) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_parse_error();
                debug!("Packet parse error: {}", e);
                return Ok(());
            }
        };

        debug!(
            "Packet: {:?} {} -> {} proto={:?}",
            parsed.version, parsed.src_addr, parsed.dst_addr, parsed.protocol
        );

        match parsed.protocol {
            IpProtocol::Tcp => {
                self.stats.record_tcp();
                self.handle_tcp_packet(&parsed, packet).await
            }
            IpProtocol::Udp => {
                self.stats.record_udp();
                self.handle_udp_packet(&parsed, packet).await
            }
            IpProtocol::Icmp => {
                self.stats.record_icmp();
                Ok(())
            }
            _ => {
                self.stats.record_other();
                Ok(())
            }
        }
    }


    async fn handle_tcp_packet(&self, parsed: &ParsedPacket, raw: &[u8]) -> Result<()> {
        let tcp_info = match &parsed.transport {
            TransportInfo::Tcp(info) => info,
            _ => return Ok(()),
        };

        let src_addr = parsed.src_socket().ok_or_else(|| {
            SolidTcpError::InvalidPacket("Missing source address".to_string())
        })?;
        let dst_addr = parsed.dst_socket().ok_or_else(|| {
            SolidTcpError::InvalidPacket("Missing destination address".to_string())
        })?;

        let ip_header_len = parsed.payload_offset;
        let tcp_data_offset = if ip_header_len + 12 < raw.len() {
            ((raw[ip_header_len + 12] >> 4) as usize) * 4
        } else {
            20
        };
        
        let payload_start = ip_header_len + tcp_data_offset;
        let ip_total_len = if raw.len() >= 4 {
            u16::from_be_bytes([raw[2], raw[3]]) as usize
        } else {
            raw.len()
        };
        
        let payload_end = ip_total_len.min(raw.len());
        let payload = if payload_start < payload_end {
            &raw[payload_start..payload_end]
        } else {
            &[]
        };

        debug!(
            "TCP: {} -> {} flags={:?} seq={} ack={} payload_len={}",
            src_addr, dst_addr, tcp_info.flags, tcp_info.seq, tcp_info.ack, payload.len()
        );

        if tcp_info.flags.syn && !tcp_info.flags.ack {
            return self.handle_tcp_syn(src_addr, dst_addr, tcp_info, parsed).await;
        }

        if let Some(conn) = self.tcp_manager.get_connection(src_addr, dst_addr) {
            let action = {
                let mut conn = conn.write();
                conn.process(tcp_info, payload)?
            };

            self.execute_tcp_action(src_addr, dst_addr, &conn, action).await?;
        } else if !tcp_info.flags.rst {
            debug!("No connection for packet, sending RST: {} -> {}", src_addr, dst_addr);
            self.send_tcp_packet(
                dst_addr, src_addr,
                tcp_info.ack, tcp_info.seq.wrapping_add(1),
                TcpFlags::rst_ack(), &[], None,
            ).await?;
        }

        Ok(())
    }

    async fn handle_tcp_syn(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp_info: &TcpInfo,
        _parsed: &ParsedPacket,
    ) -> Result<()> {
        // 防止回环：检查目标是否为本地代理端口
        if let IpAddr::V4(ip) = dst_addr.ip() {
            if ip.is_loopback() && dst_addr.port() == self.config.proxy_port {
                warn!(
                    "Blocking loopback connection attempt: {} -> 127.0.0.1:{} (proxy port)",
                    src_addr, self.config.proxy_port
                );
                self.send_tcp_packet(
                    dst_addr, src_addr,
                    0, tcp_info.seq.wrapping_add(1),
                    TcpFlags::rst_ack(), &[], None,
                ).await?;
                return Ok(());
            }
        }

        let domain = if let IpAddr::V4(ip) = dst_addr.ip() {
            let d = self.fake_ip_pool.lookup(ip);
            if d.is_none() && self.fake_ip_pool.is_fake_ip(ip) {
                warn!("TCP SYN to Fake-IP {} but no domain mapping found!", ip);
            }
            d
        } else {
            None
        };

        info!(
            "=== TCP SYN received: {} -> {} (domain: {:?}, is_fake_ip: {}) ===",
            src_addr, dst_addr, domain, 
            if let IpAddr::V4(ip) = dst_addr.ip() { self.fake_ip_pool.is_fake_ip(ip) } else { false }
        );

        if domain.is_none() {
            if let IpAddr::V4(ip) = dst_addr.ip() {
                if self.fake_ip_pool.is_fake_ip(ip) {
                    warn!("Cannot proxy connection to Fake-IP {} without domain mapping", ip);
                    self.send_tcp_packet(
                        dst_addr, src_addr,
                        0, tcp_info.seq.wrapping_add(1),
                        TcpFlags::rst_ack(), &[], None,
                    ).await?;
                    return Ok(());
                }
            }
        }

        let conn = self.tcp_manager.handle_syn(src_addr, dst_addr, tcp_info, domain.clone())?;
        self.stats.record_tcp_connection();

        let (our_seq, their_seq, mss) = {
            let conn = conn.read();
            (conn.snd_nxt().wrapping_sub(1), conn.rcv_nxt(), conn.mss())
        };

        info!("Sending SYN-ACK to {} for connection to {:?}", src_addr, domain.as_ref().unwrap_or(&dst_addr.to_string()));

        self.send_tcp_packet(
            dst_addr, src_addr, our_seq, their_seq,
            TcpFlags::syn_ack(), &[], Some(mss),
        ).await?;

        let stack = self.clone_for_proxy();
        let conn_clone = conn.clone();
        
        tokio::spawn(async move {
            if let Err(e) = stack.establish_proxy_connection(
                src_addr, dst_addr, domain, conn_clone,
            ).await {
                warn!("Proxy connection failed: {} -> {}: {}", src_addr, dst_addr, e);
            }
        });

        Ok(())
    }

    fn clone_for_proxy(&self) -> StackProxy {
        StackProxy {
            proxy_port: self.config.proxy_port,
            tun_tx: self.tun_tx.clone(),
            tcp_manager: self.tcp_manager.clone(),
            udp_manager: self.udp_manager.clone(),
            nat_table: self.nat_table.clone(),
            stats: self.stats.clone(),
            running: self.running.clone(),
        }
    }


    async fn execute_tcp_action(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        conn: &Arc<RwLock<TcpConnection>>,
        action: TcpAction,
    ) -> Result<()> {
        match action {
            TcpAction::SendAck => {
                let (seq, ack) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt())
                };
                self.send_tcp_packet(dst_addr, src_addr, seq, ack, TcpFlags::ack_only(), &[], None).await?;
            }
            TcpAction::SendFinAck => {
                let (seq, ack) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt())
                };
                self.send_tcp_packet(dst_addr, src_addr, seq, ack, TcpFlags::fin_ack(), &[], None).await?;
                let close_action = conn.write().close();
                if close_action == TcpAction::SendFin { }
            }
            TcpAction::SendFin => {
                let (seq, ack) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt())
                };
                self.send_tcp_packet(dst_addr, src_addr, seq, ack, TcpFlags::fin_ack(), &[], None).await?;
            }
            TcpAction::SendRst => {
                let seq = conn.read().snd_nxt();
                self.send_tcp_packet(dst_addr, src_addr, seq, 0, TcpFlags::rst_only(), &[], None).await?;
            }
            TcpAction::Established => {
                debug!("TCP connection established: {} -> {}", src_addr, dst_addr);
            }
            TcpAction::Close => {
                self.tcp_manager.remove_connection(src_addr, dst_addr);
                self.stats.record_tcp_closed();
                debug!("TCP connection closed: {} -> {}", src_addr, dst_addr);
            }
            TcpAction::SendData(data) => {
                let (seq, ack) = {
                    let mut conn = conn.write();
                    let seq = conn.snd_nxt();
                    let ack = conn.rcv_nxt();
                    conn.advance_snd_nxt(data.len() as u32);
                    (seq, ack)
                };
                self.send_tcp_packet(dst_addr, src_addr, seq, ack, TcpFlags::psh_ack(), &data, None).await?;
            }
            TcpAction::None => {}
        }
        Ok(())
    }

    async fn handle_udp_packet(&self, parsed: &ParsedPacket, raw: &[u8]) -> Result<()> {
        let udp_info = match &parsed.transport {
            TransportInfo::Udp(info) => info,
            _ => return Ok(()),
        };

        let src_addr = parsed.src_socket().ok_or_else(|| {
            SolidTcpError::InvalidPacket("Missing source address".to_string())
        })?;
        let dst_addr = parsed.dst_socket().ok_or_else(|| {
            SolidTcpError::InvalidPacket("Missing destination address".to_string())
        })?;

        let payload_start = parsed.payload_offset + 8;
        let payload = if udp_info.payload_len > 0 && payload_start < raw.len() {
            &raw[payload_start..raw.len().min(payload_start + udp_info.payload_len)]
        } else {
            return Ok(());
        };

        info!("UDP packet: {} -> {} ({} bytes payload)", src_addr, dst_addr, payload.len());

        if dst_addr.port() == 53 && self.config.dns_intercept {
            info!("=== DNS query intercepted: {} -> {} ({} bytes) ===", src_addr, dst_addr, payload.len());
            return self.handle_dns_query(src_addr, dst_addr, payload).await;
        }

        self.handle_udp_data(src_addr, dst_addr, payload).await
    }

    async fn handle_dns_query(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<()> {
        self.stats.record_dns_query();
        info!("=== Processing DNS query: {} -> {} ({} bytes) ===", src_addr, dst_addr, payload.len());

        match self.dns_handler.handle_query(payload) {
            Ok((response, domain)) => {
                if let Some(ref d) = domain {
                    info!("DNS query for domain: {} - Fake-IP allocated", d);
                    self.stats.record_fake_ip();
                }
                self.stats.record_dns_response();
                info!("DNS response ready: {} bytes, sending back to {} from {}", response.len(), src_addr, dst_addr);

                match self.send_udp_packet(dst_addr, src_addr, &response).await {
                    Ok(()) => {
                        info!("=== DNS response sent successfully to {} ===", src_addr);
                    }
                    Err(e) => {
                        warn!("Failed to send DNS response to {}: {}", src_addr, e);
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                warn!("DNS query handling failed: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    async fn handle_udp_data(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<()> {
        use crate::solidtcp::udp::UdpSessionType;
        
        let domain = if let IpAddr::V4(ip) = dst_addr.ip() {
            self.fake_ip_pool.lookup(ip)
        } else {
            None
        };

        // Detect session type (QUIC, DNS, Regular)
        let session_type = UdpSessionType::detect(
            dst_addr.port(),
            payload,
            &[443, 8443, 4433, 8080], // Common QUIC ports
        );

        let type_str = match session_type {
            UdpSessionType::Quic => "QUIC",
            UdpSessionType::Dns => "DNS",
            UdpSessionType::Regular => "UDP",
            UdpSessionType::Unknown => "UNKNOWN",
        };

        debug!(
            "{} data: {} -> {} ({} bytes, domain: {:?})",
            type_str, src_addr, dst_addr, payload.len(), domain
        );

        // Get or create session with type detection
        let session = self.udp_manager.get_or_create_session_with_detection(
            src_addr, dst_addr, domain.clone(), payload
        )?;
        
        self.udp_manager.record_sent(src_addr, dst_addr, payload.len());

        // Check if session already has an active relay - use a block to limit lock scope
        let has_relay = {
            let sess = session.read();
            sess.relay_socket().is_some() || sess.proxy_tx().is_some()
        };

        if has_relay {
            // Get relay info without holding lock across await
            let relay_info = {
                let sess = session.read();
                if let Some(relay_socket) = sess.relay_socket() {
                    Some((relay_socket.clone(), true))
                } else if sess.proxy_tx().is_some() {
                    // For proxy_tx, we need to clone it
                    None // Will handle separately
                } else {
                    None
                }
            };
            
            if let Some((relay_socket, _)) = relay_info {
                // Direct relay - send to target
                let target = match &domain {
                    Some(d) => {
                        // Resolve domain
                        match tokio::net::lookup_host(format!("{}:{}", d, dst_addr.port())).await {
                            Ok(mut addrs) => addrs.next().unwrap_or(dst_addr),
                            Err(_) => dst_addr,
                        }
                    }
                    None => dst_addr,
                };
                
                if let Err(e) = relay_socket.send_to(payload, target).await {
                    debug!("UDP relay send error: {}", e);
                }
                return Ok(());
            }
        }

        // Create new relay for this session
        let stack = self.clone_for_proxy();
        let payload_vec = payload.to_vec();
        let session_clone = session.clone();
        let is_quic = session_type == UdpSessionType::Quic;
        
        tokio::spawn(async move {
            if let Err(e) = stack.forward_udp_with_session(
                src_addr, dst_addr, domain, &payload_vec, session_clone, is_quic
            ).await {
                debug!("UDP forward error: {} -> {}: {}", src_addr, dst_addr, e);
            }
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_tcp_packet(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        payload: &[u8],
        mss: Option<u16>,
    ) -> Result<()> {
        let tun_tx = self.tun_tx.as_ref().ok_or(SolidTcpError::DeviceNotReady)?;

        let (src_ip, dst_ip) = match (src_addr.ip(), dst_addr.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
            _ => return Err(SolidTcpError::Unsupported("IPv6 not supported".to_string())),
        };

        let packet = build_ipv4_tcp(
            src_ip, dst_ip, src_addr.port(), dst_addr.port(),
            seq, ack, flags, 65535, payload, mss,
        );

        self.stats.record_sent(packet.len());
        tun_tx.send(BytesMut::from(&packet[..]))
            .await
            .map_err(|_| SolidTcpError::ChannelClosed)?;

        Ok(())
    }

    async fn send_udp_packet(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<()> {
        let tun_tx = self.tun_tx.as_ref().ok_or_else(|| {
            warn!("TUN TX channel not available!");
            SolidTcpError::DeviceNotReady
        })?;

        let (src_ip, dst_ip) = match (src_addr.ip(), dst_addr.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
            _ => return Err(SolidTcpError::Unsupported("IPv6 not supported".to_string())),
        };

        info!("Building UDP packet: {}:{} -> {}:{} ({} bytes payload)", 
            src_ip, src_addr.port(), dst_ip, dst_addr.port(), payload.len());

        let packet = build_ipv4_udp(src_ip, dst_ip, src_addr.port(), dst_addr.port(), payload);

        info!("Sending UDP packet to TUN: {} bytes total", packet.len());
        self.stats.record_sent(packet.len());
        
        match tun_tx.send(BytesMut::from(&packet[..])).await {
            Ok(()) => {
                info!("UDP packet sent to TUN successfully");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to send UDP packet to TUN: {}", e);
                Err(SolidTcpError::ChannelClosed)
            }
        }
    }

    pub async fn run_cleanup(&self) {
        let interval = self.config.cleanup_interval;
        let mut ticker = tokio::time::interval(interval);

        while self.is_running() {
            ticker.tick().await;
            self.tcp_manager.cleanup();
            self.udp_manager.cleanup();
            self.nat_table.cleanup();
            self.fake_ip_pool.cleanup_expired();
        }
    }

    #[allow(dead_code)]
    async fn establish_proxy_connection(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        domain: Option<String>,
        conn: Arc<RwLock<TcpConnection>>,
    ) -> Result<()> {
        let proxy = self.clone_for_proxy();
        proxy.establish_proxy_connection(src_addr, dst_addr, domain, conn).await
    }
}

struct StackProxy {
    proxy_port: u16,
    tun_tx: Option<mpsc::Sender<BytesMut>>,
    tcp_manager: Arc<TcpManager>,
    udp_manager: Arc<UdpManager>,
    #[allow(dead_code)]
    nat_table: Arc<NatTable>,
    stats: Arc<StackStats>,
    running: Arc<AtomicBool>,
}


impl StackProxy {
    /// Forward UDP with session management for QUIC support
    async fn forward_udp_with_session(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        domain: Option<String>,
        payload: &[u8],
        _session: Arc<parking_lot::RwLock<crate::solidtcp::udp::UdpSession>>,
        is_quic: bool,
    ) -> Result<()> {
        use tokio::net::UdpSocket;
        
        let proxy_addr: SocketAddr = format!("127.0.0.1:{}", self.proxy_port)
            .parse()
            .map_err(|e| SolidTcpError::ProxyError(format!("Invalid proxy address: {}", e)))?;
        
        // Create TCP socket for SOCKS5 UDP ASSOCIATE
        let tcp_socket = tokio::net::TcpSocket::new_v4()
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to create TCP socket: {}", e)))?;
        
        #[cfg(target_os = "android")]
        {
            let fd = tcp_socket.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect UDP associate TCP socket fd={}", fd);
            } else {
                debug!("Protected UDP associate TCP socket fd={}", fd);
            }
        }
        
        let mut tcp_stream = tcp_socket.connect(proxy_addr).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP associate connect failed: {}", e)))?;

        // SOCKS5 handshake
        tcp_stream.write_all(&[0x05, 0x01, 0x00]).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP greeting failed: {}", e)))?;

        let mut response = [0u8; 2];
        tcp_stream.read_exact(&mut response).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP response failed: {}", e)))?;

        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(SolidTcpError::ProxyAuthFailed);
        }

        // UDP ASSOCIATE request
        let request = [
            0x05, 0x03, 0x00,  // VER, CMD=UDP ASSOCIATE, RSV
            0x01,              // ATYP=IPv4
            0x00, 0x00, 0x00, 0x00,  // BND.ADDR (0.0.0.0)
            0x00, 0x00,        // BND.PORT (0)
        ];
        tcp_stream.write_all(&request).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP associate request failed: {}", e)))?;

        let mut assoc_response = [0u8; 10];
        tcp_stream.read_exact(&mut assoc_response).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP associate response failed: {}", e)))?;

        if assoc_response[1] != 0x00 {
            return Err(SolidTcpError::ProxyError(format!(
                "UDP ASSOCIATE failed: {}",
                assoc_response[1]
            )));
        }

        // Parse relay address
        let relay_addr = match assoc_response[3] {
            0x01 => {
                let ip = Ipv4Addr::new(
                    assoc_response[4], assoc_response[5],
                    assoc_response[6], assoc_response[7],
                );
                let port = u16::from_be_bytes([assoc_response[8], assoc_response[9]]);
                // 如果服务器返回 0.0.0.0，使用代理服务器地址
                let ip = if ip.is_unspecified() { 
                    Ipv4Addr::new(127, 0, 0, 1) 
                } else { 
                    ip 
                };
                // 验证端口有效性
                if port == 0 {
                    return Err(SolidTcpError::ProxyError(
                        "Invalid relay port 0 from SOCKS5 server".to_string()
                    ));
                }
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            _ => {
                return Err(SolidTcpError::ProxyError("Unsupported relay address type".to_string()));
            }
        };

        if is_quic {
            info!("QUIC UDP relay established: {} -> {} via {}", src_addr, dst_addr, relay_addr);
        } else {
            debug!("UDP relay address: {}", relay_addr);
        }

        // Create UDP socket for relay
        let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP socket bind failed: {}", e)))?;
        
        #[cfg(target_os = "android")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = std_socket.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect UDP relay socket fd={}", fd);
            } else {
                debug!("Protected UDP relay socket fd={}", fd);
            }
        }
        
        std_socket.set_nonblocking(true)
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to set nonblocking: {}", e)))?;
        let udp_socket = Arc::new(UdpSocket::from_std(std_socket)
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to convert UDP socket: {}", e)))?);

        // Build SOCKS5 UDP request
        let mut udp_request = Vec::with_capacity(payload.len() + 262);
        udp_request.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG

        if let Some(ref domain) = domain {
            udp_request.push(0x03); // ATYP=Domain
            udp_request.push(domain.len() as u8);
            udp_request.extend_from_slice(domain.as_bytes());
        } else {
            match dst_addr.ip() {
                IpAddr::V4(ip) => {
                    udp_request.push(0x01); // ATYP=IPv4
                    udp_request.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    udp_request.push(0x04); // ATYP=IPv6
                    udp_request.extend_from_slice(&ip.octets());
                }
            }
        }
        udp_request.extend_from_slice(&dst_addr.port().to_be_bytes());
        udp_request.extend_from_slice(payload);

        // 验证UDP请求包大小
        if udp_request.len() > 65507 {
            warn!("UDP request too large: {} bytes, truncating", udp_request.len());
            udp_request.truncate(65507);
        }

        // Send initial packet with error handling
        match udp_socket.send_to(&udp_request, relay_addr).await {
            Ok(sent) => {
                if is_quic {
                    debug!("QUIC packet forwarded: {} -> {} ({}/{} bytes sent)", 
                           src_addr, dst_addr, sent, udp_request.len());
                } else {
                    debug!("UDP forwarded: {} -> {} ({}/{} bytes sent)", 
                           src_addr, dst_addr, sent, udp_request.len());
                }
            }
            Err(e) => {
                // 详细记录错误信息
                let error_kind = e.kind();
                let error_code = e.raw_os_error();
                warn!(
                    "UDP send failed: {} -> {} via {}: {} (kind: {:?}, os_error: {:?})",
                    src_addr, dst_addr, relay_addr, e, error_kind, error_code
                );
                return Err(SolidTcpError::ProxyError(format!(
                    "UDP send failed: {} (os error: {:?})",
                    e, error_code
                )));
            }
        }

        // Set up bidirectional relay for QUIC
        let tun_tx = self.tun_tx.clone();
        let stats = self.stats.clone();
        let running = self.running.clone();
        let udp_manager = self.udp_manager.clone();
        let udp_socket_clone = udp_socket.clone();
        let _domain_clone = domain.clone();

        // Timeout based on session type
        let recv_timeout = if is_quic {
            Duration::from_secs(300) // 5 minutes for QUIC
        } else {
            Duration::from_secs(30) // 30 seconds for regular UDP
        };

        // Spawn receiver task for responses
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            
            loop {
                let timeout_result = tokio::time::timeout(
                    recv_timeout,
                    udp_socket_clone.recv_from(&mut buf)
                ).await;

                match timeout_result {
                    Ok(Ok((n, _from))) => {
                        if n <= 10 {
                            continue;
                        }

                        // Parse SOCKS5 UDP response header
                        let atyp = buf[3];
                        let header_len = match atyp {
                            0x01 => 10, // IPv4
                            0x03 => 7 + buf[4] as usize, // Domain
                            0x04 => 22, // IPv6
                            _ => {
                                debug!("Unknown ATYP in UDP response: {}", atyp);
                                continue;
                            }
                        };

                        if n <= header_len {
                            continue;
                        }

                        let response_payload = &buf[header_len..n];
                        
                        // Record received data
                        udp_manager.record_recv(src_addr, dst_addr, response_payload.len());

                        // Send response back to TUN
                        if let Some(ref tx) = tun_tx {
                            let (src_ip, dst_ip) = match (dst_addr.ip(), src_addr.ip()) {
                                (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
                                _ => continue,
                            };

                            let packet = build_ipv4_udp(
                                src_ip, dst_ip,
                                dst_addr.port(), src_addr.port(),
                                response_payload,
                            );

                            stats.record_sent(packet.len());
                            if tx.send(BytesMut::from(&packet[..])).await.is_err() {
                                debug!("Failed to send UDP response to TUN");
                                break;
                            }

                            if is_quic {
                                trace!("QUIC response: {} <- {} ({} bytes)", src_addr, dst_addr, response_payload.len());
                            }
                        }

                        // For non-QUIC, we might exit after first response
                        if !is_quic && !running.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("UDP recv error: {}", e);
                        break;
                    }
                    Err(_) => {
                        // Timeout
                        if is_quic {
                            debug!("QUIC session timeout: {} -> {}", src_addr, dst_addr);
                        } else {
                            debug!("UDP recv timeout");
                        }
                        break;
                    }
                }

                // Check if we should continue
                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }

            // Cleanup
            drop(tcp_stream);
            debug!("UDP relay closed: {} -> {}", src_addr, dst_addr);
        });

        Ok(())
    }

    /// Legacy forward_udp for backward compatibility
    #[allow(dead_code)]
    async fn forward_udp(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        domain: Option<String>,
        payload: &[u8],
    ) -> Result<()> {
        use tokio::net::UdpSocket;
        
        let proxy_addr: SocketAddr = format!("127.0.0.1:{}", self.proxy_port)
            .parse()
            .map_err(|e| SolidTcpError::ProxyError(format!("Invalid proxy address: {}", e)))?;
        
        let tcp_socket = tokio::net::TcpSocket::new_v4()
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to create TCP socket: {}", e)))?;
        
        #[cfg(target_os = "android")]
        {
            let fd = tcp_socket.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect UDP associate TCP socket fd={}", fd);
            } else {
                debug!("Protected UDP associate TCP socket fd={}", fd);
            }
        }
        
        let mut tcp_stream = tcp_socket.connect(proxy_addr).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP associate connect failed: {}", e)))?;

        tcp_stream.write_all(&[0x05, 0x01, 0x00]).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP greeting failed: {}", e)))?;

        let mut response = [0u8; 2];
        tcp_stream.read_exact(&mut response).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP response failed: {}", e)))?;

        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(SolidTcpError::ProxyAuthFailed);
        }

        let request = [
            0x05, 0x03, 0x00,
            0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        tcp_stream.write_all(&request).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP associate request failed: {}", e)))?;

        let mut assoc_response = [0u8; 10];
        tcp_stream.read_exact(&mut assoc_response).await
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP associate response failed: {}", e)))?;

        if assoc_response[1] != 0x00 {
            return Err(SolidTcpError::ProxyError(format!(
                "UDP ASSOCIATE failed: {}",
                assoc_response[1]
            )));
        }

        let relay_addr = match assoc_response[3] {
            0x01 => {
                let ip = Ipv4Addr::new(
                    assoc_response[4], assoc_response[5],
                    assoc_response[6], assoc_response[7],
                );
                let port = u16::from_be_bytes([assoc_response[8], assoc_response[9]]);
                let ip = if ip.is_unspecified() { Ipv4Addr::new(127, 0, 0, 1) } else { ip };
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            _ => {
                return Err(SolidTcpError::ProxyError("Unsupported relay address type".to_string()));
            }
        };

        debug!("UDP relay address: {}", relay_addr);

        let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP socket bind failed: {}", e)))?;
        
        #[cfg(target_os = "android")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = std_socket.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect UDP relay socket fd={}", fd);
            } else {
                debug!("Protected UDP relay socket fd={}", fd);
            }
        }
        
        std_socket.set_nonblocking(true)
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to set nonblocking: {}", e)))?;
        let _udp_socket = UdpSocket::from_std(std_socket)
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to convert UDP socket: {}", e)))?;

        let mut udp_request = Vec::with_capacity(payload.len() + 262);
        udp_request.extend_from_slice(&[0x00, 0x00, 0x00]);

        if let Some(ref domain) = domain {
            udp_request.push(0x03);
            udp_request.push(domain.len() as u8);
            udp_request.extend_from_slice(domain.as_bytes());
        } else {
            match dst_addr.ip() {
                IpAddr::V4(ip) => {
                    udp_request.push(0x01);
                    udp_request.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    udp_request.push(0x04);
                    udp_request.extend_from_slice(&ip.octets());
                }
            }
        }
        udp_request.extend_from_slice(&dst_addr.port().to_be_bytes());
        udp_request.extend_from_slice(payload);

        // Parse relay address
        let relay_addr = match assoc_response[3] {
            0x01 => {
                let ip = Ipv4Addr::new(
                    assoc_response[4], assoc_response[5],
                    assoc_response[6], assoc_response[7],
                );
                let port = u16::from_be_bytes([assoc_response[8], assoc_response[9]]);
                let ip = if ip.is_unspecified() { Ipv4Addr::new(127, 0, 0, 1) } else { ip };
                // 验证端口有效性
                if port == 0 {
                    return Err(SolidTcpError::ProxyError(
                        "Invalid relay port 0 from SOCKS5 server".to_string()
                    ));
                }
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            _ => {
                return Err(SolidTcpError::ProxyError("Unsupported relay address type".to_string()));
            }
        };

        debug!("UDP relay address: {}", relay_addr);

        // Create UDP socket for relay
        let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP socket bind failed: {}", e)))?;
        
        #[cfg(target_os = "android")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = std_socket.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect UDP relay socket fd={}", fd);
            } else {
                debug!("Protected UDP relay socket fd={}", fd);
            }
        }
        
        std_socket.set_nonblocking(true)
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to set nonblocking: {}", e)))?;
        let udp_socket = Arc::new(UdpSocket::from_std(std_socket)
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to convert UDP socket: {}", e)))?);

        // Build SOCKS5 UDP request
        let mut udp_request = Vec::with_capacity(payload.len() + 262);
        udp_request.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG

        if let Some(ref domain) = domain {
            udp_request.push(0x03); // ATYP=Domain
            udp_request.push(domain.len() as u8);
            udp_request.extend_from_slice(domain.as_bytes());
        } else {
            match dst_addr.ip() {
                IpAddr::V4(ip) => {
                    udp_request.push(0x01); // ATYP=IPv4
                    udp_request.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    udp_request.push(0x04); // ATYP=IPv6
                    udp_request.extend_from_slice(&ip.octets());
                }
            }
        }
        udp_request.extend_from_slice(&dst_addr.port().to_be_bytes());
        udp_request.extend_from_slice(payload);

        // 验证UDP请求包大小
        if udp_request.len() > 65507 {
            warn!("UDP request too large: {} bytes, truncating", udp_request.len());
            udp_request.truncate(65507);
        }

        // Send packet with error handling
        match udp_socket.send_to(&udp_request, relay_addr).await {
            Ok(sent) => {
                debug!("UDP forwarded: {} -> {} ({}/{} bytes sent)", 
                       src_addr, dst_addr, sent, udp_request.len());
            }
            Err(e) => {
                let error_kind = e.kind();
                let error_code = e.raw_os_error();
                warn!(
                    "UDP send failed: {} -> {} via {}: {} (kind: {:?}, os_error: {:?})",
                    src_addr, dst_addr, relay_addr, e, error_kind, error_code
                );
                return Err(SolidTcpError::ProxyError(format!(
                    "UDP send failed: {} (os error: {:?})",
                    e, error_code
                )));
            }
        }

        let tun_tx = self.tun_tx.clone();
        let stats = self.stats.clone();
        let _running = self.running.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            
            let timeout = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                udp_socket.recv_from(&mut buf)
            );

            match timeout.await {
                Ok(Ok((n, _))) => {
                    if n > 10 {
                        let atyp = buf[3];
                        let header_len = match atyp {
                            0x01 => 10,
                            0x03 => 7 + buf[4] as usize,
                            0x04 => 22,
                            _ => return,
                        };

                        if n > header_len {
                            let response_payload = &buf[header_len..n];
                            
                            if let Some(ref tx) = tun_tx {
                                let (src_ip, dst_ip) = match (dst_addr.ip(), src_addr.ip()) {
                                    (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
                                    _ => return,
                                };

                                let packet = build_ipv4_udp(
                                    src_ip, dst_ip,
                                    dst_addr.port(), src_addr.port(),
                                    response_payload,
                                );

                                stats.record_sent(packet.len());
                                let _ = tx.send(BytesMut::from(&packet[..])).await;
                            }
                        }
                    }
                }
                Ok(Err(e)) => { debug!("UDP recv error: {}", e); }
                Err(_) => { debug!("UDP recv timeout"); }
            }

            drop(tcp_stream);
        });

        Ok(())
    }


    async fn establish_proxy_connection(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        domain: Option<String>,
        conn: Arc<RwLock<TcpConnection>>,
    ) -> Result<()> {
        info!("=== Establishing proxy connection: {} -> {} (domain: {:?}) ===", src_addr, dst_addr, domain);
        
        let proxy_addr: SocketAddr = format!("127.0.0.1:{}", self.proxy_port)
            .parse()
            .map_err(|e| SolidTcpError::ProxyError(format!("Invalid proxy address: {}", e)))?;
        
        let tcp_socket = tokio::net::TcpSocket::new_v4()
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to create TCP socket: {}", e)))?;
        
        #[cfg(target_os = "android")]
        {
            let fd = tcp_socket.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect proxy TCP socket fd={}", fd);
            }
        }
        
        let mut stream = tcp_socket.connect(proxy_addr).await
            .map_err(|e| SolidTcpError::ProxyError(format!("Connect failed: {}", e)))?;

        let _ = stream.set_nodelay(true);

        self.socks5_handshake(&mut stream, dst_addr, domain.as_deref()).await?;

        info!("SOCKS5 handshake complete: {} -> {}", src_addr, dst_addr);

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
        conn.write().set_proxy_tx(tx);

        let (mut read_half, mut write_half) = stream.into_split();

        let running = self.running.clone();
        let src_clone = src_addr;
        let dst_clone = dst_addr;
        let conn_for_ws = conn.clone();
        tokio::spawn(async move {
            let mut first_data = true;
            let mut write_buffer = Vec::with_capacity(65536);
            
            while running.load(Ordering::Relaxed) {
                match rx.recv().await {
                    Some(data) => {
                        if first_data && data.len() > 20 {
                            first_data = false;
                            if let Ok(text) = std::str::from_utf8(&data[..data.len().min(512)]) {
                                let text_lower = text.to_lowercase();
                                if text_lower.contains("upgrade: websocket") || 
                                   text_lower.contains("connection: upgrade") {
                                    info!("WebSocket upgrade detected for {} -> {}", src_clone, dst_clone);
                                    conn_for_ws.write().set_websocket(true);
                                }
                            }
                        }
                        
                        write_buffer.extend_from_slice(&data);
                        
                        if write_buffer.len() >= 16384 || rx.is_empty() {
                            if let Err(e) = write_half.write_all(&write_buffer).await {
                                warn!("App->Proxy write error: {} for {} -> {}", e, src_clone, dst_clone);
                                break;
                            }
                            if let Err(e) = write_half.flush().await {
                                warn!("App->Proxy flush error: {} for {} -> {}", e, src_clone, dst_clone);
                                break;
                            }
                            write_buffer.clear();
                        }
                    }
                    None => break,
                }
            }
            
            if !write_buffer.is_empty() {
                let _ = write_half.write_all(&write_buffer).await;
                let _ = write_half.flush().await;
            }
        });

        let tun_tx = self.tun_tx.clone();
        let stats = self.stats.clone();
        let tcp_manager = self.tcp_manager.clone();
        let running = self.running.clone();
        let conn_clone = conn.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            
            while running.load(Ordering::Relaxed) {
                match read_half.read(&mut buf).await {
                    Ok(0) => {
                        info!("Proxy->App: EOF for {} -> {}", src_addr, dst_addr);
                        break;
                    }
                    Ok(n) => {
                        let send_info = {
                            let mut conn_guard = conn_clone.write();
                            let base_seq = conn_guard.snd_nxt();
                            let ack = conn_guard.rcv_nxt();
                            let mss = conn_guard.mss() as usize;
                            
                            let ips = match (dst_addr.ip(), src_addr.ip()) {
                                (IpAddr::V4(s), IpAddr::V4(d)) => Some((s, d)),
                                _ => None,
                            };
                            
                            if let Some((src_ip, dst_ip)) = ips {
                                conn_guard.advance_snd_nxt(n as u32);
                                Some((base_seq, ack, mss, src_ip, dst_ip))
                            } else {
                                warn!("IPv6 not supported");
                                None
                            }
                        };
                        
                        let (base_seq, ack, mss, src_ip, dst_ip) = match send_info {
                            Some(info) => info,
                            None => break,
                        };
                        
                        let effective_mss = mss.min(1360);
                        let data = &buf[..n];
                        let mut offset = 0;
                        let mut seq = base_seq;
                        let mut packets_to_send = Vec::new();
                        
                        while offset < data.len() {
                            let chunk_end = (offset + effective_mss).min(data.len());
                            let chunk = &data[offset..chunk_end];
                            let is_last = chunk_end == data.len();
                            
                            let flags = if is_last || data.len() <= effective_mss {
                                TcpFlags::psh_ack()
                            } else {
                                TcpFlags::ack_only()
                            };
                            
                            let packet = build_ipv4_tcp(
                                src_ip, dst_ip,
                                dst_addr.port(), src_addr.port(),
                                seq, ack,
                                flags,
                                65535,
                                chunk,
                                None,
                            );
                            
                            packets_to_send.push(packet);
                            
                            seq = seq.wrapping_add(chunk.len() as u32);
                            offset = chunk_end;
                        }
                        
                        if let Some(ref tx) = tun_tx {
                            for packet in packets_to_send {
                                stats.record_sent(packet.len());
                                if tx.send(BytesMut::from(&packet[..])).await.is_err() {
                                    warn!("Failed to send to TUN");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Proxy read error: {} for {} -> {}", e, src_addr, dst_addr);
                        break;
                    }
                }
            }

            let fin_info = {
                let conn_guard = conn_clone.read();
                let ips = match (dst_addr.ip(), src_addr.ip()) {
                    (IpAddr::V4(s), IpAddr::V4(d)) => Some((s, d)),
                    _ => None,
                };
                ips.map(|(src_ip, dst_ip)| (conn_guard.snd_nxt(), conn_guard.rcv_nxt(), src_ip, dst_ip))
            };
            
            if let Some((seq, ack, src_ip, dst_ip)) = fin_info {
                if let Some(ref tx) = tun_tx {
                    let packet = build_ipv4_tcp(
                        src_ip, dst_ip,
                        dst_addr.port(), src_addr.port(),
                        seq, ack,
                        TcpFlags::fin_ack(),
                        65535,
                        &[],
                        None,
                    );
                    let _ = tx.send(BytesMut::from(&packet[..])).await;
                }
            }
            
            tcp_manager.remove_connection(src_addr, dst_addr);
        });

        Ok(())
    }


    async fn socks5_handshake(
        &self,
        stream: &mut TokioTcpStream,
        target: SocketAddr,
        domain: Option<&str>,
    ) -> Result<()> {
        stream.write_all(&[0x05, 0x01, 0x00]).await
            .map_err(|e| SolidTcpError::ProxyError(format!("Greeting failed: {}", e)))?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await
            .map_err(|e| SolidTcpError::ProxyError(format!("Response failed: {}", e)))?;

        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(SolidTcpError::ProxyAuthFailed);
        }

        let mut request = vec![0x05, 0x01, 0x00];

        if let Some(domain) = domain {
            request.push(0x03);
            request.push(domain.len() as u8);
            request.extend_from_slice(domain.as_bytes());
        } else {
            match target.ip() {
                IpAddr::V4(ip) => {
                    request.push(0x01);
                    request.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    request.push(0x04);
                    request.extend_from_slice(&ip.octets());
                }
            }
        }
        request.extend_from_slice(&target.port().to_be_bytes());

        stream.write_all(&request).await
            .map_err(|e| SolidTcpError::ProxyError(format!("Connect request failed: {}", e)))?;

        let mut connect_response = [0u8; 10];
        stream.read_exact(&mut connect_response).await
            .map_err(|e| SolidTcpError::ProxyError(format!("Connect response failed: {}", e)))?;

        if connect_response[1] != 0x00 {
            let error_msg = match connect_response[1] {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown error",
            };
            return Err(SolidTcpError::ProxyError(format!(
                "SOCKS5 connect failed: {} ({})",
                error_msg, connect_response[1]
            )));
        }

        match connect_response[3] {
            0x01 => {
                // IPv4 - already read enough
            }
            0x03 => {
                let domain_len = connect_response[4] as usize;
                let mut skip = vec![0u8; domain_len + 2 - 6];
                if !skip.is_empty() {
                    let _ = stream.read_exact(&mut skip).await;
                }
            }
            0x04 => {
                let mut skip = [0u8; 12];
                let _ = stream.read_exact(&mut skip).await;
            }
            _ => {}
        }

        Ok(())
    }
}
