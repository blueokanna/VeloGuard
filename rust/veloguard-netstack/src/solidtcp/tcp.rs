//! TCP connection management

use crate::solidtcp::error::Result;
use crate::solidtcp::nat::NatKey;
use crate::solidtcp::packet::{TcpInfo, DEFAULT_MSS_V4};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

/// TCP state (RFC 793)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed, Listen, SynSent, SynReceived, Established,
    FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// TCP action to take after processing a segment
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpAction {
    None,
    SendAck,
    SendFin,
    SendFinAck,
    SendRst,
    SendData(Vec<u8>),
    Established,
    Close,
}

/// TCP configuration
#[derive(Debug, Clone)]
pub struct TcpConfig {
    pub recv_window: u16,
    pub mss: u16,
    pub idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub time_wait: Duration,
    pub websocket_timeout: Duration,
    pub max_recv_buffer: usize,
    pub max_send_buffer: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            recv_window: 65535,
            mss: 1360,
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(30),
            time_wait: Duration::from_secs(10),
            websocket_timeout: Duration::from_secs(3600),
            max_recv_buffer: 1024 * 1024,
            max_send_buffer: 1024 * 1024,
        }
    }
}

/// TCP connection
pub struct TcpConnection {
    pub key: NatKey,
    state: TcpState,
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
    mss: u16,
    config: TcpConfig,
    recv_buf: VecDeque<u8>,
    send_buf: VecDeque<u8>,
    last_active: Instant,
    bytes_tx: u64,
    bytes_rx: u64,
    pub domain: Option<String>,
    proxy_tx: Option<mpsc::Sender<Vec<u8>>>,
    fin_recv: bool,
    pending_data: VecDeque<u8>,
    ooo_segments: BTreeMap<u32, Vec<u8>>,
    max_ooo_size: usize,
    ooo_size: usize,
    is_websocket: bool,
    recv_window: u32,
    last_window_update: u32,
    #[allow(dead_code)]
    cwnd: u32,
    #[allow(dead_code)]
    ssthresh: u32,
    dup_ack_count: u32,
}

impl TcpConnection {
    pub fn new_passive(key: NatKey, their_seq: u32, their_mss: Option<u16>, domain: Option<String>) -> Self {
        let config = TcpConfig::default();
        let iss: u32 = rand::random();
        let mss = their_mss.unwrap_or(DEFAULT_MSS_V4).min(config.mss);
        let is_websocket = matches!(key.dst.port(), 80 | 443 | 8080 | 8443 | 9000);
        let initial_cwnd = (10 * mss as u32).min(64 * 1024);
        
        Self {
            key, state: TcpState::SynReceived,
            snd_nxt: iss.wrapping_add(1), snd_una: iss,
            rcv_nxt: their_seq.wrapping_add(1),
            mss, config,
            recv_buf: VecDeque::new(), send_buf: VecDeque::new(),
            last_active: Instant::now(),
            bytes_tx: 0, bytes_rx: 0,
            domain, proxy_tx: None, fin_recv: false,
            pending_data: VecDeque::new(),
            ooo_segments: BTreeMap::new(),
            max_ooo_size: 512 * 1024,
            ooo_size: 0,
            is_websocket,
            recv_window: 65535 * 4,
            last_window_update: 65535 * 4,
            cwnd: initial_cwnd,
            ssthresh: 65535 * 2,
            dup_ack_count: 0,
        }
    }
    
    pub fn set_websocket(&mut self, is_ws: bool) {
        self.is_websocket = is_ws;
        if is_ws {
            self.max_ooo_size = 1024 * 1024;
            info!("Connection marked as WebSocket: {:?}", self.key);
        }
    }
    
    pub fn is_websocket(&self) -> bool { self.is_websocket }
    pub fn recv_window(&self) -> u32 { self.recv_window }
    
    fn update_recv_window(&mut self) {
        let buffer_used = self.recv_buf.len() + self.pending_data.len() + self.ooo_size;
        let max_buffer = self.config.max_recv_buffer;
        let available = max_buffer.saturating_sub(buffer_used);
        self.recv_window = (available as u32).min(65535 * 4);
        
        let window_diff = self.recv_window.abs_diff(self.last_window_update);
        
        if window_diff > 16384 {
            self.last_window_update = self.recv_window;
        }
    }

    pub fn state(&self) -> TcpState { self.state }
    pub fn is_established(&self) -> bool { self.state == TcpState::Established }
    pub fn is_closed(&self) -> bool { matches!(self.state, TcpState::Closed | TcpState::TimeWait) }
    
    pub fn set_proxy_tx(&mut self, tx: mpsc::Sender<Vec<u8>>) {
        self.proxy_tx = Some(tx.clone());
        if !self.pending_data.is_empty() {
            let data: Vec<u8> = self.pending_data.drain(..).collect();
            info!("Flushing {} bytes of pending data to proxy", data.len());
            let tx_clone = tx;
            tokio::spawn(async move {
                let _ = tx_clone.send(data).await;
            });
        }
    }
    
    pub fn snd_nxt(&self) -> u32 { self.snd_nxt }
    pub fn rcv_nxt(&self) -> u32 { self.rcv_nxt }
    pub fn mss(&self) -> u16 { self.mss }
    
    pub fn advance_snd_nxt(&mut self, len: u32) {
        self.snd_nxt = self.snd_nxt.wrapping_add(len);
        self.bytes_tx += len as u64;
    }

    pub fn process(&mut self, seg: &TcpInfo, payload: &[u8]) -> Result<TcpAction> {
        self.last_active = Instant::now();
        if seg.flags.rst {
            info!("TCP RST: {:?}", self.key);
            self.state = TcpState::Closed;
            return Ok(TcpAction::Close);
        }
        match self.state {
            TcpState::SynReceived => self.on_syn_recv(seg),
            TcpState::Established => self.on_established(seg, payload),
            TcpState::FinWait1 => self.on_fin_wait1(seg),
            TcpState::FinWait2 => self.on_fin_wait2(seg),
            TcpState::CloseWait => self.on_close_wait(seg),
            TcpState::Closing => self.on_closing(seg),
            TcpState::LastAck => self.on_last_ack(seg),
            TcpState::TimeWait => self.on_time_wait(seg),
            _ => Ok(TcpAction::None),
        }
    }

    fn on_syn_recv(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack && self.valid_ack(seg.ack) {
            self.snd_una = seg.ack;
            self.state = TcpState::Established;
            info!("TCP ESTABLISHED: {:?}", self.key);
            return Ok(TcpAction::Established);
        }
        Ok(TcpAction::None)
    }

    fn on_established(&mut self, seg: &TcpInfo, payload: &[u8]) -> Result<TcpAction> {
        if seg.flags.ack { self.process_ack(seg.ack); }
        let mut action = TcpAction::None;
        if !payload.is_empty() { action = self.process_data(seg.seq, payload)?; }
        if seg.flags.fin {
            self.fin_recv = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::CloseWait;
            debug!("TCP FIN recv -> CLOSE_WAIT: {:?}", self.key);
            return Ok(TcpAction::SendFinAck);
        }
        Ok(action)
    }

    fn on_fin_wait1(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack && self.valid_ack(seg.ack) {
            self.snd_una = seg.ack;
            if seg.flags.fin {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.state = TcpState::TimeWait;
                return Ok(TcpAction::SendAck);
            }
            self.state = TcpState::FinWait2;
        }
        if seg.flags.fin {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::Closing;
            return Ok(TcpAction::SendAck);
        }
        Ok(TcpAction::None)
    }

    fn on_fin_wait2(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.fin {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::TimeWait;
            return Ok(TcpAction::SendAck);
        }
        Ok(TcpAction::None)
    }

    fn on_close_wait(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack { self.process_ack(seg.ack); }
        Ok(TcpAction::None)
    }

    fn on_closing(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack && self.valid_ack(seg.ack) { self.state = TcpState::TimeWait; }
        Ok(TcpAction::None)
    }

    fn on_last_ack(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack && self.valid_ack(seg.ack) {
            self.state = TcpState::Closed;
            return Ok(TcpAction::Close);
        }
        Ok(TcpAction::None)
    }

    fn on_time_wait(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.fin { return Ok(TcpAction::SendAck); }
        Ok(TcpAction::None)
    }

    fn valid_ack(&self, ack: u32) -> bool {
        let (una, nxt) = (self.snd_una, self.snd_nxt);
        if una <= nxt { ack > una && ack <= nxt } else { ack > una || ack <= nxt }
    }

    fn process_ack(&mut self, ack: u32) {
        if self.valid_ack(ack) { self.snd_una = ack; }
    }

    fn process_data(&mut self, seq: u32, data: &[u8]) -> Result<TcpAction> {
        if data.is_empty() { return Ok(TcpAction::None); }
        
        self.update_recv_window();
        let seq_end = seq.wrapping_add(data.len() as u32);
        
        if self.seq_before_or_eq(seq_end, self.rcv_nxt) {
            trace!("Complete retransmission detected: seq={}, seq_end={}, rcv_nxt={}", seq, seq_end, self.rcv_nxt);
            return Ok(TcpAction::SendAck);
        }
        
        if seq == self.rcv_nxt {
            self.dup_ack_count = 0;
            self.recv_buf.extend(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
            self.bytes_rx += data.len() as u64;
            self.try_deliver_ooo_segments();
            let d: Vec<u8> = self.recv_buf.drain(..).collect();
            if !d.is_empty() { self.deliver_to_proxy(d); }
            self.update_recv_window();
            return Ok(TcpAction::SendAck);
        }
        
        if self.seq_before(seq, self.rcv_nxt) && self.seq_after(seq_end, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip < data.len() {
                let new_data = &data[skip..];
                trace!("Partial retransmission: seq={}, skip={}, new_len={}", seq, skip, new_data.len());
                self.recv_buf.extend(new_data);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(new_data.len() as u32);
                self.bytes_rx += new_data.len() as u64;
                self.try_deliver_ooo_segments();
                let d: Vec<u8> = self.recv_buf.drain(..).collect();
                if !d.is_empty() { self.deliver_to_proxy(d); }
            }
            return Ok(TcpAction::SendAck);
        }
        
        if self.seq_after(seq, self.rcv_nxt) {
            self.dup_ack_count += 1;
            if self.ooo_size + data.len() <= self.max_ooo_size {
                if !self.ooo_segments.contains_key(&seq) {
                    debug!("Buffering out-of-order segment: seq={}, len={}, expected={}, gap={}", 
                           seq, data.len(), self.rcv_nxt, seq.wrapping_sub(self.rcv_nxt));
                    self.ooo_segments.insert(seq, data.to_vec());
                    self.ooo_size += data.len();
                }
            } else {
                warn!("OOO buffer full ({} bytes), dropping segment: seq={}, len={}", 
                      self.ooo_size, seq, data.len());
            }
        }
        
        Ok(TcpAction::SendAck)
    }
    
    fn try_deliver_ooo_segments(&mut self) {
        loop {
            let next_seq = self.rcv_nxt;
            if let Some(data) = self.ooo_segments.remove(&next_seq) {
                debug!("Delivering OOO segment: seq={}, len={}", next_seq, data.len());
                self.ooo_size -= data.len();
                self.recv_buf.extend(&data);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
                self.bytes_rx += data.len() as u64;
            } else {
                let mut found = None;
                for (&seg_seq, seg_data) in self.ooo_segments.iter() {
                    let seg_end = seg_seq.wrapping_add(seg_data.len() as u32);
                    if self.seq_before_or_eq(seg_seq, self.rcv_nxt) && self.seq_after(seg_end, self.rcv_nxt) {
                        let skip = self.rcv_nxt.wrapping_sub(seg_seq) as usize;
                        if skip < seg_data.len() {
                            found = Some((seg_seq, skip));
                            break;
                        }
                    }
                }
                
                if let Some((seg_seq, skip)) = found {
                    if let Some(data) = self.ooo_segments.remove(&seg_seq) {
                        let new_data = &data[skip..];
                        debug!("Delivering partial OOO segment: seq={}, skip={}, len={}", 
                               seg_seq, skip, new_data.len());
                        self.ooo_size -= data.len();
                        self.recv_buf.extend(new_data);
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(new_data.len() as u32);
                        self.bytes_rx += new_data.len() as u64;
                        continue;
                    }
                }
                break;
            }
        }
    }

    fn deliver_to_proxy(&mut self, data: Vec<u8>) {
        if data.is_empty() { return; }
        
        if let Some(ref tx) = self.proxy_tx {
            let data_len = data.len();
            let tx = tx.clone();
            trace!("Sending {} bytes to proxy", data_len);
            
            if data_len > 16384 {
                debug!("Large data transfer: {} bytes to proxy", data_len);
                tokio::spawn(async move { 
                    if let Err(e) = tx.send(data).await {
                        warn!("Failed to send large data to proxy: {}", e);
                    }
                });
            } else {
                match tx.try_send(data) {
                    Ok(()) => { trace!("Data sent to proxy via try_send"); }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                        debug!("Proxy channel full, spawning send task for {} bytes", data.len());
                        tokio::spawn(async move { 
                            if let Err(e) = tx.send(data).await {
                                warn!("Failed to send data to proxy: {}", e);
                            }
                        });
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        warn!("Proxy channel closed, cannot send {} bytes", data_len);
                    }
                }
            }
        } else {
            debug!("Buffering {} bytes (proxy not ready)", data.len());
            let current_pending = self.pending_data.len();
            if current_pending + data.len() <= self.config.max_recv_buffer {
                self.pending_data.extend(data);
            } else {
                warn!("Pending data buffer full ({} bytes), dropping {} bytes", 
                      current_pending, data.len());
            }
        }
    }
    
    fn seq_before(&self, seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) < 0
    }
    
    fn seq_after(&self, seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) > 0
    }
    
    fn seq_before_or_eq(&self, seq1: u32, seq2: u32) -> bool {
        seq1 == seq2 || self.seq_before(seq1, seq2)
    }

    pub fn send(&mut self, data: &[u8]) { self.send_buf.extend(data); }

    pub fn get_send_data(&mut self) -> Option<Vec<u8>> {
        if self.send_buf.is_empty() { return None; }
        let len = self.send_buf.len().min(self.mss as usize);
        let data: Vec<u8> = self.send_buf.drain(..len).collect();
        self.snd_nxt = self.snd_nxt.wrapping_add(data.len() as u32);
        self.bytes_tx += data.len() as u64;
        Some(data)
    }

    pub fn close(&mut self) -> TcpAction {
        match self.state {
            TcpState::Established => { self.state = TcpState::FinWait1; TcpAction::SendFin }
            TcpState::CloseWait => { self.state = TcpState::LastAck; TcpAction::SendFin }
            _ => TcpAction::None,
        }
    }

    /// Force close the connection immediately
    /// This drops the proxy channel to signal spawned tasks to exit
    pub fn force_close(&mut self) {
        self.state = TcpState::Closed;
        // Drop the proxy sender to signal the write task to exit
        self.proxy_tx = None;
        // Clear buffers
        self.recv_buf.clear();
        self.send_buf.clear();
        self.pending_data.clear();
        self.ooo_segments.clear();
        self.ooo_size = 0;
    }

    pub fn is_timed_out(&self) -> bool {
        let timeout = match self.state {
            TcpState::Established => {
                if self.is_websocket { self.config.websocket_timeout } else { self.config.idle_timeout }
            }
            TcpState::TimeWait => self.config.time_wait,
            _ => self.config.connect_timeout,
        };
        self.last_active.elapsed() > timeout
    }

    pub fn stats(&self) -> (u64, u64) { (self.bytes_tx, self.bytes_rx) }
}

/// TCP connection manager
pub struct TcpManager {
    connections: DashMap<NatKey, Arc<RwLock<TcpConnection>>>,
    #[allow(dead_code)]
    config: TcpConfig,
}

impl TcpManager {
    pub fn new() -> Self {
        Self::with_config(TcpConfig::default())
    }

    pub fn with_config(config: TcpConfig) -> Self {
        Self {
            connections: DashMap::new(),
            config,
        }
    }

    pub fn handle_syn(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        tcp_info: &TcpInfo,
        domain: Option<String>,
    ) -> Result<Arc<RwLock<TcpConnection>>> {
        let key = NatKey::new(src, dst);
        
        if let Some(conn) = self.connections.get(&key) {
            return Ok(conn.clone());
        }

        let conn = TcpConnection::new_passive(key, tcp_info.seq, tcp_info.mss, domain);
        let conn = Arc::new(RwLock::new(conn));
        self.connections.insert(key, conn.clone());
        
        trace!("TCP connection created: {} -> {}", src, dst);
        Ok(conn)
    }

    pub fn get_connection(&self, src: SocketAddr, dst: SocketAddr) -> Option<Arc<RwLock<TcpConnection>>> {
        let key = NatKey::new(src, dst);
        self.connections.get(&key).map(|c| c.clone())
    }

    pub fn remove_connection(&self, src: SocketAddr, dst: SocketAddr) {
        let key = NatKey::new(src, dst);
        self.connections.remove(&key);
        trace!("TCP connection removed: {} -> {}", src, dst);
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn cleanup(&self) {
        let to_remove: Vec<_> = self.connections
            .iter()
            .filter(|entry| {
                let conn = entry.read();
                conn.is_closed() || conn.is_timed_out()
            })
            .map(|entry| *entry.key())
            .collect();

        for key in to_remove {
            self.connections.remove(&key);
            trace!("TCP connection cleaned up: {:?}", key);
        }
    }

    /// Force close all connections immediately
    /// This is called during shutdown to ensure all proxy tasks exit
    pub fn force_close_all(&self) {
        let count = self.connections.len();
        
        // Mark all connections as closed and drop their proxy channels
        for entry in self.connections.iter() {
            let mut conn = entry.write();
            conn.force_close();
        }
        
        // Clear all connections
        self.connections.clear();
        
        info!("Force closed {} TCP connections", count);
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<RwLock<TcpConnection>>> + '_ {
        self.connections.iter().map(|e| e.clone())
    }
}

impl Default for TcpManager {
    fn default() -> Self {
        Self::new()
    }
}
