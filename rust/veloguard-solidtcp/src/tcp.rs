//! TCP connection management

use crate::error::Result;
use crate::nat::NatKey;
use crate::packet::{TcpInfo, DEFAULT_MSS_V4};
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
    /// No action needed
    None,
    /// Send ACK
    SendAck,
    /// Send FIN
    SendFin,
    /// Send FIN-ACK
    SendFinAck,
    /// Send RST
    SendRst,
    /// Send data
    SendData(Vec<u8>),
    /// Connection established
    Established,
    /// Connection closed
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
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            recv_window: 65535,
            mss: 1360, // Conservative MSS for better compatibility
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(30),
            time_wait: Duration::from_secs(10),
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
    /// Buffer for data received before proxy connection is established
    pending_data: VecDeque<u8>,
    /// Out-of-order segments buffer (seq -> data)
    ooo_segments: BTreeMap<u32, Vec<u8>>,
    /// Maximum out-of-order buffer size (bytes)
    max_ooo_size: usize,
    /// Current out-of-order buffer size
    ooo_size: usize,
}


impl TcpConnection {
    pub fn new_passive(key: NatKey, their_seq: u32, their_mss: Option<u16>, domain: Option<String>) -> Self {
        let config = TcpConfig::default();
        let iss: u32 = rand::random();
        let mss = their_mss.unwrap_or(DEFAULT_MSS_V4).min(config.mss);
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
            max_ooo_size: 256 * 1024, // 256KB max out-of-order buffer
            ooo_size: 0,
        }
    }

    pub fn state(&self) -> TcpState { self.state }
    pub fn is_established(&self) -> bool { self.state == TcpState::Established }
    pub fn is_closed(&self) -> bool { matches!(self.state, TcpState::Closed | TcpState::TimeWait) }
    
    pub fn set_proxy_tx(&mut self, tx: mpsc::Sender<Vec<u8>>) {
        self.proxy_tx = Some(tx.clone());
        // Flush any pending data that was buffered before proxy was ready
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
    
    /// Advance snd_nxt by the given amount (used when sending data directly)
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
        
        // Check if this is a retransmission of already received data
        let seq_end = seq.wrapping_add(data.len() as u32);
        
        // If seq_end is at or before rcv_nxt, this is a complete retransmission
        if self.seq_before_or_eq(seq_end, self.rcv_nxt) {
            // Already received all this data, just ACK
            debug!("Complete retransmission detected: seq={}, seq_end={}, rcv_nxt={}", seq, seq_end, self.rcv_nxt);
            return Ok(TcpAction::SendAck);
        }
        
        // If seq is exactly what we expect - in-order delivery
        if seq == self.rcv_nxt {
            self.recv_buf.extend(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
            self.bytes_rx += data.len() as u64;
            
            // Check if we can deliver any out-of-order segments now
            self.try_deliver_ooo_segments();
            
            // Deliver data to proxy
            let d: Vec<u8> = self.recv_buf.drain(..).collect();
            if !d.is_empty() {
                self.deliver_to_proxy(d);
            }
            return Ok(TcpAction::SendAck);
        }
        
        // Partial overlap - seq is before rcv_nxt but seq_end is after
        if self.seq_before(seq, self.rcv_nxt) && self.seq_after(seq_end, self.rcv_nxt) {
            // Calculate how much of this segment is new
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip < data.len() {
                let new_data = &data[skip..];
                debug!("Partial retransmission: seq={}, skip={}, new_len={}", seq, skip, new_data.len());
                self.recv_buf.extend(new_data);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(new_data.len() as u32);
                self.bytes_rx += new_data.len() as u64;
                
                // Check if we can deliver any out-of-order segments now
                self.try_deliver_ooo_segments();
                
                // Deliver data to proxy
                let d: Vec<u8> = self.recv_buf.drain(..).collect();
                if !d.is_empty() {
                    self.deliver_to_proxy(d);
                }
            }
            return Ok(TcpAction::SendAck);
        }
        
        // Out-of-order segment - buffer it if within window
        if self.seq_after(seq, self.rcv_nxt) {
            // Check if we have room in the OOO buffer
            if self.ooo_size + data.len() <= self.max_ooo_size {
                // Only store if we don't already have this segment
                if !self.ooo_segments.contains_key(&seq) {
                    debug!("Buffering out-of-order segment: seq={}, len={}, expected={}", 
                           seq, data.len(), self.rcv_nxt);
                    self.ooo_segments.insert(seq, data.to_vec());
                    self.ooo_size += data.len();
                }
            } else {
                warn!("OOO buffer full, dropping segment: seq={}, len={}", seq, data.len());
            }
        }
        
        // Send duplicate ACK to trigger fast retransmit
        Ok(TcpAction::SendAck)
    }
    
    /// Try to deliver buffered out-of-order segments
    fn try_deliver_ooo_segments(&mut self) {
        loop {
            // Find segment that starts at rcv_nxt
            let next_seq = self.rcv_nxt;
            if let Some(data) = self.ooo_segments.remove(&next_seq) {
                debug!("Delivering OOO segment: seq={}, len={}", next_seq, data.len());
                self.ooo_size -= data.len();
                self.recv_buf.extend(&data);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
                self.bytes_rx += data.len() as u64;
            } else {
                // Also check for overlapping segments
                let mut found = None;
                for (&seg_seq, seg_data) in self.ooo_segments.iter() {
                    let seg_end = seg_seq.wrapping_add(seg_data.len() as u32);
                    
                    // If segment overlaps with rcv_nxt
                    if self.seq_before_or_eq(seg_seq, self.rcv_nxt) && self.seq_after(seg_end, self.rcv_nxt) {
                        // Calculate how much of this segment is new
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
    
    /// Deliver data to proxy or buffer it
    fn deliver_to_proxy(&mut self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        
        if let Some(ref tx) = self.proxy_tx {
            // Proxy is ready, send data
            let data_len = data.len();
            let tx = tx.clone();
            debug!("Sending {} bytes to proxy", data_len);
            
            // Use try_send first to avoid spawning tasks for small data
            match tx.try_send(data) {
                Ok(()) => {
                    trace!("Data sent to proxy via try_send");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                    // Channel is full, spawn a task to wait
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
        } else {
            // Proxy not ready yet, buffer the data
            debug!("Buffering {} bytes (proxy not ready)", data.len());
            self.pending_data.extend(data);
        }
    }
    
    /// Check if seq1 is before seq2 (handling wraparound)
    fn seq_before(&self, seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) < 0
    }
    
    /// Check if seq1 is after seq2 (handling wraparound)
    fn seq_after(&self, seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) > 0
    }
    
    /// Check if seq1 is before or equal to seq2
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

    pub fn is_timed_out(&self) -> bool {
        let timeout = match self.state {
            TcpState::Established => self.config.idle_timeout,
            TcpState::TimeWait => self.config.time_wait,
            _ => self.config.connect_timeout,
        };
        self.last_active.elapsed() > timeout
    }

    pub fn stats(&self) -> (u64, u64) { (self.bytes_tx, self.bytes_rx) }
}

/// TCP connection manager
pub struct TcpManager {
    /// Active connections
    connections: DashMap<NatKey, Arc<RwLock<TcpConnection>>>,
    /// Configuration
    #[allow(dead_code)]
    config: TcpConfig,
}

impl TcpManager {
    /// Create a new TCP manager
    pub fn new() -> Self {
        Self::with_config(TcpConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: TcpConfig) -> Self {
        Self {
            connections: DashMap::new(),
            config,
        }
    }

    /// Handle incoming SYN packet
    pub fn handle_syn(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        tcp_info: &TcpInfo,
        domain: Option<String>,
    ) -> Result<Arc<RwLock<TcpConnection>>> {
        let key = NatKey::new(src, dst);
        
        // Check if connection already exists
        if let Some(conn) = self.connections.get(&key) {
            return Ok(conn.clone());
        }

        // Create new connection
        let conn = TcpConnection::new_passive(key, tcp_info.seq, tcp_info.mss, domain);
        let conn = Arc::new(RwLock::new(conn));
        self.connections.insert(key, conn.clone());
        
        trace!("TCP connection created: {} -> {}", src, dst);
        Ok(conn)
    }

    /// Get connection by addresses
    pub fn get_connection(&self, src: SocketAddr, dst: SocketAddr) -> Option<Arc<RwLock<TcpConnection>>> {
        let key = NatKey::new(src, dst);
        self.connections.get(&key).map(|c| c.clone())
    }

    /// Remove connection
    pub fn remove_connection(&self, src: SocketAddr, dst: SocketAddr) {
        let key = NatKey::new(src, dst);
        self.connections.remove(&key);
        trace!("TCP connection removed: {} -> {}", src, dst);
    }

    /// Get active connection count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Cleanup timed out connections
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

    /// Iterate over all connections
    pub fn iter(&self) -> impl Iterator<Item = Arc<RwLock<TcpConnection>>> + '_ {
        self.connections.iter().map(|e| e.clone())
    }
}

impl Default for TcpManager {
    fn default() -> Self {
        Self::new()
    }
}
