use crate::error::{NetStackError, Result};
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Waker;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, trace};

const NAT_TIMEOUT: Duration = Duration::from_secs(300);
const QUIC_NAT_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_NAT_ENTRIES: usize = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionType {
    Regular,
    Quic,
    Dns,
}

impl UdpSessionType {
    pub fn detect(dst_port: u16, payload: &[u8]) -> Self {
        // DNS detection
        if dst_port == 53 {
            return Self::Dns;
        }

        if matches!(dst_port, 443 | 8443 | 4433 | 8080)
            && Self::is_quic_packet(payload) {
                return Self::Quic;
            }

        if Self::is_quic_packet(payload) {
            return Self::Quic;
        }

        Self::Regular
    }

    fn is_quic_packet(payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }

        let first_byte = payload[0];

        if first_byte & 0x80 != 0 && payload.len() >= 5 {
            let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
            return matches!(version,
                0x00000001 |  // QUIC v1
                0x6b3343cf |  // QUIC v2
                0xff000000..=0xffffffff | // Draft versions
                0x51303030..=0x51303939   // Google QUIC
            );
        }
        (first_byte & 0x40) != 0 && payload.len() >= 20
    }

    pub fn timeout(&self) -> Duration {
        match self {
            Self::Quic => QUIC_NAT_TIMEOUT,
            _ => NAT_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub data: Bytes,
}

impl UdpPacket {
    pub fn new(src_addr: SocketAddr, dst_addr: SocketAddr, data: Bytes) -> Self {
        Self {
            src_addr,
            dst_addr,
            data,
        }
    }
}

#[derive(Debug, Clone)]
struct NatEntry {
    original_src: SocketAddr,
    original_dst: SocketAddr,
    last_activity: Instant,
    session_type: UdpSessionType,
}

pub struct UdpNatTable {
    forward: DashMap<(SocketAddr, SocketAddr), u16>,
    reverse: DashMap<u16, NatEntry>,
    next_port: AtomicU64,
    base_port: u16,
}

impl UdpNatTable {
    pub fn new(base_port: u16) -> Self {
        Self {
            forward: DashMap::new(),
            reverse: DashMap::new(),
            next_port: AtomicU64::new(base_port as u64),
            base_port,
        }
    }

    pub fn get_or_create(&self, src: SocketAddr, dst: SocketAddr) -> Result<u16> {
        self.get_or_create_with_type(src, dst, UdpSessionType::Regular)
    }

    pub fn get_or_create_with_type(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        session_type: UdpSessionType,
    ) -> Result<u16> {
        let key = (src, dst);
        if let Some(port) = self.forward.get(&key) {
            if let Some(mut entry) = self.reverse.get_mut(&port) {
                entry.last_activity = Instant::now();
                // Upgrade to QUIC if detected
                if session_type == UdpSessionType::Quic
                    && entry.session_type != UdpSessionType::Quic
                {
                    entry.session_type = UdpSessionType::Quic;
                    info!("NAT entry upgraded to QUIC: {} -> {}", src, dst);
                }
            }
            return Ok(*port);
        }

        if self.forward.len() >= MAX_NAT_ENTRIES {
            self.cleanup_expired();
            if self.forward.len() >= MAX_NAT_ENTRIES {
                return Err(NetStackError::NatTableFull);
            }
        }

        let port = self.allocate_port();
        self.forward.insert(key, port);
        self.reverse.insert(
            port,
            NatEntry {
                original_src: src,
                original_dst: dst,
                last_activity: Instant::now(),
                session_type,
            },
        );

        let type_str = match session_type {
            UdpSessionType::Quic => "QUIC",
            UdpSessionType::Dns => "DNS",
            UdpSessionType::Regular => "UDP",
        };
        debug!(
            "{} NAT mapping created: {}:{} -> port {}",
            type_str, src, dst, port
        );
        Ok(port)
    }

    pub fn lookup_reverse(&self, port: u16) -> Option<(SocketAddr, SocketAddr)> {
        self.reverse
            .get(&port)
            .map(|entry| (entry.original_src, entry.original_dst))
    }

    pub fn remove(&self, src: SocketAddr, dst: SocketAddr) {
        let key = (src, dst);
        if let Some((_, port)) = self.forward.remove(&key) {
            self.reverse.remove(&port);
            debug!("NAT mapping removed: {}:{}", src, dst);
        }
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let expired: Vec<u16> = self
            .reverse
            .iter()
            .filter(|entry| {
                let timeout = entry.session_type.timeout();
                now.duration_since(entry.last_activity) > timeout
            })
            .map(|entry| *entry.key())
            .collect();

        for port in expired {
            if let Some((_, entry)) = self.reverse.remove(&port) {
                self.forward
                    .remove(&(entry.original_src, entry.original_dst));
                let type_str = match entry.session_type {
                    UdpSessionType::Quic => "QUIC",
                    UdpSessionType::Dns => "DNS",
                    UdpSessionType::Regular => "UDP",
                };
                trace!(
                    "{} NAT mapping expired: {}:{}",
                    type_str,
                    entry.original_src,
                    entry.original_dst
                );
            }
        }
    }

    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    fn allocate_port(&self) -> u16 {
        loop {
            let port = self.next_port.fetch_add(1, Ordering::Relaxed) as u16;
            let port = if port < self.base_port {
                self.base_port
            } else if port > 65534 {
                self.next_port
                    .store(self.base_port as u64, Ordering::Relaxed);
                self.base_port
            } else {
                port
            };

            if !self.reverse.contains_key(&port) {
                return port;
            }
        }
    }
}

impl Default for UdpNatTable {
    fn default() -> Self {
        Self::new(30000)
    }
}

pub struct UdpSession {
    pub id: u16,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    recv_queue: Arc<Mutex<VecDeque<UdpPacket>>>,
    recv_waker: Arc<Mutex<Option<Waker>>>,
    send_tx: mpsc::Sender<UdpPacket>,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    closed: Arc<AtomicBool>,
    session_type: UdpSessionType,
    created_at: Instant,
}

impl UdpSession {
    #[allow(dead_code)]
    fn new(
        id: u16,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        send_tx: mpsc::Sender<UdpPacket>,
    ) -> Self {
        Self::new_with_type(id, src_addr, dst_addr, send_tx, UdpSessionType::Regular)
    }

    fn new_with_type(
        id: u16,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        send_tx: mpsc::Sender<UdpPacket>,
        session_type: UdpSessionType,
    ) -> Self {
        Self {
            id,
            src_addr,
            dst_addr,
            recv_queue: Arc::new(Mutex::new(VecDeque::with_capacity(64))),
            recv_waker: Arc::new(Mutex::new(None)),
            send_tx,
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            closed: Arc::new(AtomicBool::new(false)),
            session_type,
            created_at: Instant::now(),
        }
    }

    /// Get session type
    pub fn session_type(&self) -> UdpSessionType {
        self.session_type
    }

    /// Check if this is a QUIC session
    pub fn is_quic(&self) -> bool {
        self.session_type == UdpSessionType::Quic
    }

    /// Get session duration
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub async fn send(&self, data: Bytes) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(NetStackError::ChannelClosed);
        }

        let packet = UdpPacket::new(self.src_addr, self.dst_addr, data.clone());
        self.upload_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        self.send_tx
            .send(packet)
            .await
            .map_err(|_| NetStackError::ChannelClosed)
    }

    pub fn try_send(&self, data: Bytes) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(NetStackError::ChannelClosed);
        }

        let packet = UdpPacket::new(self.src_addr, self.dst_addr, data.clone());
        self.upload_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        self.send_tx
            .try_send(packet)
            .map_err(|_| NetStackError::ChannelClosed)
    }

    pub async fn recv(&self) -> Result<UdpPacket> {
        loop {
            {
                let mut queue = self.recv_queue.lock();
                if let Some(packet) = queue.pop_front() {
                    return Ok(packet);
                }

                if self.closed.load(Ordering::Relaxed) {
                    return Err(NetStackError::ChannelClosed);
                }
            }

            let notify = tokio::sync::Notify::new();
            {
                let mut waker = self.recv_waker.lock();
                *waker = Some(futures::task::noop_waker());
            }
            notify.notified().await;
        }
    }

    pub fn try_recv(&self) -> Option<UdpPacket> {
        self.recv_queue.lock().pop_front()
    }

    pub(crate) fn push_packet(&self, packet: UdpPacket) {
        self.download_bytes
            .fetch_add(packet.data.len() as u64, Ordering::Relaxed);

        let mut queue = self.recv_queue.lock();
        queue.push_back(packet);

        if let Some(waker) = self.recv_waker.lock().take() {
            waker.wake();
        }
    }

    pub fn upload_bytes(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }

    pub fn download_bytes(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        if let Some(waker) = self.recv_waker.lock().take() {
            waker.wake();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

pub struct UdpStack {
    nat_table: Arc<UdpNatTable>,
    sessions: Arc<DashMap<u16, Arc<UdpSession>>>,
    new_session_tx: mpsc::Sender<Arc<UdpSession>>,
    new_session_rx: Option<mpsc::Receiver<Arc<UdpSession>>>,
    send_tx: mpsc::Sender<UdpPacket>,
    send_rx: Option<mpsc::Receiver<UdpPacket>>,
    session_counter: AtomicU64,
}

impl UdpStack {
    pub fn new() -> Self {
        let (new_session_tx, new_session_rx) = mpsc::channel(256);
        let (send_tx, send_rx) = mpsc::channel(1024);

        Self {
            nat_table: Arc::new(UdpNatTable::default()),
            sessions: Arc::new(DashMap::new()),
            new_session_tx,
            new_session_rx: Some(new_session_rx),
            send_tx,
            send_rx: Some(send_rx),
            session_counter: AtomicU64::new(0),
        }
    }

    pub fn process_packet(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        data: Bytes,
    ) -> Result<()> {
        self.process_packet_with_detection(src_addr, dst_addr, data)
    }

    pub fn process_packet_with_detection(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        data: Bytes,
    ) -> Result<()> {
        // Detect session type
        let session_type = UdpSessionType::detect(dst_addr.port(), &data);

        let nat_port = self
            .nat_table
            .get_or_create_with_type(src_addr, dst_addr, session_type)?;
        let session = if let Some(session) = self.sessions.get(&nat_port) {
            session.clone()
        } else {
            let session = Arc::new(UdpSession::new_with_type(
                nat_port,
                src_addr,
                dst_addr,
                self.send_tx.clone(),
                session_type,
            ));
            self.sessions.insert(nat_port, session.clone());
            self.session_counter.fetch_add(1, Ordering::Relaxed);

            let _ = self.new_session_tx.try_send(session.clone());

            let type_str = match session_type {
                UdpSessionType::Quic => "QUIC",
                UdpSessionType::Dns => "DNS",
                UdpSessionType::Regular => "UDP",
            };
            debug!(
                "{} session created: {} -> {} (port {})",
                type_str, src_addr, dst_addr, nat_port
            );
            session
        };

        // Push packet to session
        let packet = UdpPacket::new(src_addr, dst_addr, data);
        session.push_packet(packet);

        Ok(())
    }

    pub fn process_response(&self, nat_port: u16, data: Bytes) -> Result<()> {
        if let Some(session) = self.sessions.get(&nat_port) {
            let packet = UdpPacket::new(session.dst_addr, session.src_addr, data);
            session.push_packet(packet);
            Ok(())
        } else {
            Err(NetStackError::UdpError("Session not found".to_string()))
        }
    }

    pub fn get_session(&self, nat_port: u16) -> Option<Arc<UdpSession>> {
        self.sessions.get(&nat_port).map(|s| s.clone())
    }

    pub fn remove_session(&self, nat_port: u16) {
        if let Some((_, session)) = self.sessions.remove(&nat_port) {
            session.close();
            self.nat_table.reverse.remove(&nat_port);
            debug!("UDP session removed: port {}", nat_port);
        }
    }

    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    pub fn total_sessions(&self) -> u64 {
        self.session_counter.load(Ordering::Relaxed)
    }

    pub fn take_listener(&mut self) -> Option<UdpListener> {
        self.new_session_rx.take().map(|rx| UdpListener { rx })
    }

    pub fn take_send_receiver(&mut self) -> Option<mpsc::Receiver<UdpPacket>> {
        self.send_rx.take()
    }

    pub fn nat_table(&self) -> &Arc<UdpNatTable> {
        &self.nat_table
    }

    pub fn cleanup_expired(&self) {
        self.nat_table.cleanup_expired();

        let to_remove: Vec<u16> = self
            .sessions
            .iter()
            .filter(|entry| !self.nat_table.reverse.contains_key(entry.key()))
            .map(|entry| *entry.key())
            .collect();

        for port in to_remove {
            self.remove_session(port);
        }
    }

    pub fn close_all(&self) {
        let sessions: Vec<_> = self.sessions.iter().map(|e| *e.key()).collect();
        for port in sessions {
            self.remove_session(port);
        }
    }
}

impl Default for UdpStack {
    fn default() -> Self {
        Self::new()
    }
}

pub struct UdpListener {
    rx: mpsc::Receiver<Arc<UdpSession>>,
}

impl UdpListener {
    pub async fn accept(&mut self) -> Option<Arc<UdpSession>> {
        self.rx.recv().await
    }
}

pub struct UdpSocket {
    session: Arc<UdpSession>,
}

impl UdpSocket {
    pub fn new(session: Arc<UdpSession>) -> Self {
        Self { session }
    }

    pub fn session(&self) -> &Arc<UdpSession> {
        &self.session
    }

    pub fn src_addr(&self) -> SocketAddr {
        self.session.src_addr
    }

    pub fn dst_addr(&self) -> SocketAddr {
        self.session.dst_addr
    }

    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        self.session.send(Bytes::copy_from_slice(data)).await?;
        Ok(data.len())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let packet = self.session.recv().await?;
        let len = std::cmp::min(buf.len(), packet.data.len());
        buf[..len].copy_from_slice(&packet.data[..len]);
        Ok((len, packet.src_addr))
    }

    pub fn close(&self) {
        self.session.close();
    }
}
