use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, TargetAddr};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex, RwLock};

const MUX_VERSION: u8 = 0;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxStatus {
    New = 0x01,
    Keep = 0x02,
    End = 0x03,
    KeepAlive = 0x04,
}

impl MuxStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(MuxStatus::New),
            0x02 => Some(MuxStatus::Keep),
            0x03 => Some(MuxStatus::End),
            0x04 => Some(MuxStatus::KeepAlive),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxNetwork {
    Tcp = 0x01,
    Udp = 0x02,
}

impl MuxNetwork {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(MuxNetwork::Tcp),
            0x02 => Some(MuxNetwork::Udp),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxAddressType {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

#[derive(Debug, Clone)]
pub struct MuxFrame {
    pub session_id: u16,
    pub status: MuxStatus,
    pub option: u8,
    pub network: Option<MuxNetwork>,
    pub address: Option<MuxAddress>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MuxAddress {
    pub addr_type: MuxAddressType,
    pub host: String,
    pub port: u16,
}

impl MuxAddress {
    pub fn from_target(target: &TargetAddr) -> Self {
        match target {
            TargetAddr::Domain(domain, port) => Self {
                addr_type: MuxAddressType::Domain,
                host: domain.clone(),
                port: *port,
            },
            TargetAddr::Ip(addr) => match addr {
                std::net::SocketAddr::V4(v4) => Self {
                    addr_type: MuxAddressType::Ipv4,
                    host: v4.ip().to_string(),
                    port: v4.port(),
                },
                std::net::SocketAddr::V6(v6) => Self {
                    addr_type: MuxAddressType::Ipv6,
                    host: v6.ip().to_string(),
                    port: v6.port(),
                },
            },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.addr_type as u8);
        match self.addr_type {
            MuxAddressType::Ipv4 => {
                let ip: std::net::Ipv4Addr =
                    self.host.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
                buf.extend_from_slice(&ip.octets());
            }
            MuxAddressType::Domain => {
                buf.push(self.host.len() as u8);
                buf.extend_from_slice(self.host.as_bytes());
            }
            MuxAddressType::Ipv6 => {
                let ip: std::net::Ipv6Addr =
                    self.host.parse().unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
                buf.extend_from_slice(&ip.octets());
            }
        }
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }
        let addr_type = match data[0] {
            0x01 => MuxAddressType::Ipv4,
            0x02 => MuxAddressType::Domain,
            0x03 => MuxAddressType::Ipv6,
            _ => return None,
        };
        let (host, consumed) = match addr_type {
            MuxAddressType::Ipv4 => {
                if data.len() < 5 {
                    return None;
                }
                let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                (ip.to_string(), 5)
            }
            MuxAddressType::Domain => {
                if data.len() < 2 {
                    return None;
                }
                let len = data[1] as usize;
                if data.len() < 2 + len {
                    return None;
                }
                let domain = String::from_utf8_lossy(&data[2..2 + len]).to_string();
                (domain, 2 + len)
            }
            MuxAddressType::Ipv6 => {
                if data.len() < 17 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = std::net::Ipv6Addr::from(octets);
                (ip.to_string(), 17)
            }
        };
        if data.len() < consumed + 2 {
            return None;
        }
        let port = u16::from_be_bytes([data[consumed], data[consumed + 1]]);
        Some((Self { addr_type, host, port }, consumed + 2))
    }
}

impl MuxFrame {
    pub fn new_stream(session_id: u16, network: MuxNetwork, address: MuxAddress) -> Self {
        Self {
            session_id,
            status: MuxStatus::New,
            option: 0x01,
            network: Some(network),
            address: Some(address),
            data: Vec::new(),
        }
    }

    pub fn data(session_id: u16, data: Vec<u8>) -> Self {
        Self {
            session_id,
            status: MuxStatus::Keep,
            option: 0x00,
            network: None,
            address: None,
            data,
        }
    }

    pub fn end(session_id: u16) -> Self {
        Self {
            session_id,
            status: MuxStatus::End,
            option: 0x00,
            network: None,
            address: None,
            data: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn keep_alive() -> Self {
        Self {
            session_id: 0,
            status: MuxStatus::KeepAlive,
            option: 0x00,
            network: None,
            address: None,
            data: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.session_id.to_be_bytes());
        payload.push(self.status as u8);
        payload.push(self.option);
        if self.status == MuxStatus::New {
            if let Some(network) = self.network {
                payload.push(network as u8);
            }
            if self.option & 0x01 != 0 {
                if let Some(ref address) = self.address {
                    payload.extend_from_slice(&address.encode());
                }
            }
        }
        payload.extend_from_slice(&self.data);
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.push(MUX_VERSION);
        frame.push(0x00);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + length {
            return None;
        }
        let payload = &data[4..4 + length];
        if payload.len() < 4 {
            return None;
        }
        let session_id = u16::from_be_bytes([payload[0], payload[1]]);
        let status = MuxStatus::from_u8(payload[2])?;
        let option = payload[3];
        let mut offset = 4;
        let mut network = None;
        let mut address = None;
        if status == MuxStatus::New {
            if payload.len() <= offset {
                return None;
            }
            network = MuxNetwork::from_u8(payload[offset]);
            offset += 1;
            if option & 0x01 != 0 {
                if let Some((addr, consumed)) = MuxAddress::decode(&payload[offset..]) {
                    address = Some(addr);
                    offset += consumed;
                }
            }
        }
        let frame_data = payload[offset..].to_vec();
        Some((
            Self {
                session_id,
                status,
                option,
                network,
                address,
                data: frame_data,
            },
            4 + length,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub enabled: bool,
    pub concurrency: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            concurrency: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Open,
    Closed,
}

struct MuxStreamData {
    state: StreamState,
    recv_buf: Vec<u8>,
    recv_tx: mpsc::Sender<Vec<u8>>,
}

type MuxStreamMap = Arc<DashMap<u16, Arc<Mutex<MuxStreamData>>>>;

pub struct MuxConnection {
    inner: Arc<Mutex<Box<dyn AsyncReadWrite>>>,
    streams: MuxStreamMap,
    next_session_id: AtomicU16,
    closed: Arc<std::sync::atomic::AtomicBool>,
    config: MuxConfig,
}

impl MuxConnection {
    pub fn new(inner: Box<dyn AsyncReadWrite>, config: MuxConfig) -> Self {
        let conn = Self {
            inner: Arc::new(Mutex::new(inner)),
            streams: Arc::new(DashMap::new()),
            next_session_id: AtomicU16::new(1),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            config,
        };
        conn.start_read_loop();
        conn
    }

    fn start_read_loop(&self) {
        let inner = self.inner.clone();
        let streams = self.streams.clone();
        let closed = self.closed.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut pending = Vec::new();
            while !closed.load(Ordering::Relaxed) {
                let n = {
                    let mut inner_guard = inner.lock().await;
                    match tokio::time::timeout(
                        Duration::from_millis(100),
                        inner_guard.read(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => n,
                        Ok(Err(_)) => break,
                        Err(_) => continue,
                    }
                };
                pending.extend_from_slice(&buf[..n]);
                while let Some((frame, consumed)) = MuxFrame::decode(&pending) {
                    pending.drain(..consumed);
                    match frame.status {
                        MuxStatus::New => {
                            tracing::debug!("Mux: new stream, session_id={}", frame.session_id);
                        }
                        MuxStatus::Keep => {
                            if let Some(stream_data) = streams.get(&frame.session_id) {
                                let stream_data = stream_data.clone();
                                let mut data = stream_data.lock().await;
                                if data.state != StreamState::Closed {
                                    data.recv_buf.extend_from_slice(&frame.data);
                                    let _ = data.recv_tx.try_send(frame.data);
                                }
                            }
                        }
                        MuxStatus::End => {
                            if let Some(stream_data) = streams.get(&frame.session_id) {
                                let stream_data = stream_data.clone();
                                let mut data = stream_data.lock().await;
                                data.state = StreamState::Closed;
                            }
                            streams.remove(&frame.session_id);
                        }
                        MuxStatus::KeepAlive => {}
                    }
                }
            }
            closed.store(true, Ordering::Relaxed);
        });
    }

    pub async fn open_stream(&self, target: &TargetAddr, network: MuxNetwork) -> Result<MuxStream> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::network("Mux connection closed"));
        }
        if self.streams.len() >= self.config.concurrency {
            return Err(Error::network("Too many concurrent streams"));
        }
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        let address = MuxAddress::from_target(target);
        let (recv_tx, recv_rx) = mpsc::channel(1024);
        let stream_data = Arc::new(Mutex::new(MuxStreamData {
            state: StreamState::Open,
            recv_buf: Vec::new(),
            recv_tx,
        }));
        self.streams.insert(session_id, stream_data);
        let frame = MuxFrame::new_stream(session_id, network, address);
        let encoded = frame.encode();
        {
            let mut inner = self.inner.lock().await;
            inner
                .write_all(&encoded)
                .await
                .map_err(|e| Error::network(format!("Failed to send new stream frame: {}", e)))?;
            inner.flush().await.ok();
        }
        Ok(MuxStream {
            session_id,
            connection: self.inner.clone(),
            streams: self.streams.clone(),
            recv_rx: Mutex::new(recv_rx),
            recv_buf: Mutex::new(Vec::new()),
            closed: self.closed.clone(),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

impl Drop for MuxConnection {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct MuxStream {
    session_id: u16,
    connection: Arc<Mutex<Box<dyn AsyncReadWrite>>>,
    streams: MuxStreamMap,
    recv_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    recv_buf: Mutex<Vec<u8>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl MuxStream {
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::network("Stream closed"));
        }
        let frame = MuxFrame::data(self.session_id, data.to_vec());
        let encoded = frame.encode();
        let mut conn = self.connection.lock().await;
        conn.write_all(&encoded)
            .await
            .map_err(|e| Error::network(format!("Failed to send data: {}", e)))?;
        conn.flush().await.ok();
        Ok(())
    }

    pub async fn recv(&self) -> Result<Vec<u8>> {
        {
            let mut buf = self.recv_buf.lock().await;
            if !buf.is_empty() {
                let data = std::mem::take(&mut *buf);
                return Ok(data);
            }
        }
        let mut rx = self.recv_rx.lock().await;
        match rx.recv().await {
            Some(data) => Ok(data),
            None => Err(Error::network("Stream closed")),
        }
    }

    pub async fn close(&self) -> Result<()> {
        let frame = MuxFrame::end(self.session_id);
        let encoded = frame.encode();
        let mut conn = self.connection.lock().await;
        conn.write_all(&encoded).await.ok();
        conn.flush().await.ok();
        self.streams.remove(&self.session_id);
        Ok(())
    }

    pub fn session_id(&self) -> u16 {
        self.session_id
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        let _recv_buf = &this.recv_buf;
        let _recv_rx = &this.recv_rx;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();
        let session_id = this.session_id;
        let connection = this.connection.clone();
        let data = buf.to_vec();
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            let frame = MuxFrame::data(session_id, data);
            let encoded = frame.encode();
            let mut conn = connection.lock().await;
            let _ = conn.write_all(&encoded).await;
            let _ = conn.flush().await;
            waker.wake();
        });
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        let session_id = this.session_id;
        let connection = this.connection.clone();
        let streams = this.streams.clone();
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            let frame = MuxFrame::end(session_id);
            let encoded = frame.encode();
            let mut conn = connection.lock().await;
            let _ = conn.write_all(&encoded).await;
            let _ = conn.flush().await;
            streams.remove(&session_id);
            waker.wake();
        });
        Poll::Ready(Ok(()))
    }
}

type MuxConnectionVec = Arc<RwLock<Vec<Arc<MuxConnection>>>>;

pub struct MuxConnectionPool {
    connections: MuxConnectionVec,
    config: MuxConfig,
    max_connections: usize,
}

impl MuxConnectionPool {
    pub fn new(config: MuxConfig, max_connections: usize) -> Self {
        Self {
            connections: Arc::new(RwLock::new(Vec::new())),
            config,
            max_connections,
        }
    }

    pub async fn add_connection(&self, inner: Box<dyn AsyncReadWrite>) {
        let mut connections = self.connections.write().await;
        connections.retain(|c| !c.is_closed());
        if connections.len() < self.max_connections {
            let conn = Arc::new(MuxConnection::new(inner, self.config.clone()));
            connections.push(conn);
        }
    }

    pub async fn get_connection(&self) -> Option<Arc<MuxConnection>> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .filter(|c| !c.is_closed() && c.stream_count() < self.config.concurrency)
            .min_by_key(|c| c.stream_count())
            .cloned()
    }

    pub async fn get_or_create_connection<F, Fut>(&self, create_fn: F) -> Result<Arc<MuxConnection>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Box<dyn AsyncReadWrite>>>,
    {
        if let Some(conn) = self.get_connection().await {
            return Ok(conn);
        }
        let inner = create_fn().await?;
        let conn = Arc::new(MuxConnection::new(inner, self.config.clone()));
        let mut connections = self.connections.write().await;
        connections.retain(|c| !c.is_closed());
        connections.push(conn.clone());
        Ok(conn)
    }

    #[allow(dead_code)]
    pub async fn close_all(&self) {
        let connections = self.connections.read().await;
        for conn in connections.iter() {
            conn.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mux_status_from_u8() {
        assert_eq!(MuxStatus::from_u8(0x01), Some(MuxStatus::New));
        assert_eq!(MuxStatus::from_u8(0x02), Some(MuxStatus::Keep));
        assert_eq!(MuxStatus::from_u8(0x03), Some(MuxStatus::End));
        assert_eq!(MuxStatus::from_u8(0x04), Some(MuxStatus::KeepAlive));
        assert_eq!(MuxStatus::from_u8(0x00), None);
    }

    #[test]
    fn test_mux_network_from_u8() {
        assert_eq!(MuxNetwork::from_u8(0x01), Some(MuxNetwork::Tcp));
        assert_eq!(MuxNetwork::from_u8(0x02), Some(MuxNetwork::Udp));
        assert_eq!(MuxNetwork::from_u8(0x00), None);
    }

    #[test]
    fn test_mux_address_encode_decode_ipv4() {
        let addr = MuxAddress {
            addr_type: MuxAddressType::Ipv4,
            host: "192.168.1.1".to_string(),
            port: 8080,
        };
        let encoded = addr.encode();
        let (decoded, _) = MuxAddress::decode(&encoded).unwrap();
        assert_eq!(decoded.addr_type, MuxAddressType::Ipv4);
        assert_eq!(decoded.host, "192.168.1.1");
        assert_eq!(decoded.port, 8080);
    }

    #[test]
    fn test_mux_address_encode_decode_domain() {
        let addr = MuxAddress {
            addr_type: MuxAddressType::Domain,
            host: "example.com".to_string(),
            port: 443,
        };
        let encoded = addr.encode();
        let (decoded, _) = MuxAddress::decode(&encoded).unwrap();
        assert_eq!(decoded.addr_type, MuxAddressType::Domain);
        assert_eq!(decoded.host, "example.com");
        assert_eq!(decoded.port, 443);
    }

    #[test]
    fn test_mux_frame_encode_decode_new() {
        let addr = MuxAddress {
            addr_type: MuxAddressType::Domain,
            host: "test.com".to_string(),
            port: 80,
        };
        let frame = MuxFrame::new_stream(1, MuxNetwork::Tcp, addr);
        let encoded = frame.encode();
        let (decoded, _) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.session_id, 1);
        assert_eq!(decoded.status, MuxStatus::New);
        assert_eq!(decoded.network, Some(MuxNetwork::Tcp));
        assert!(decoded.address.is_some());
    }

    #[test]
    fn test_mux_frame_encode_decode_data() {
        let frame = MuxFrame::data(42, b"hello world".to_vec());
        let encoded = frame.encode();
        let (decoded, _) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.status, MuxStatus::Keep);
        assert_eq!(decoded.data, b"hello world");
    }

    #[test]
    fn test_mux_frame_encode_decode_end() {
        let frame = MuxFrame::end(100);
        let encoded = frame.encode();
        let (decoded, _) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.session_id, 100);
        assert_eq!(decoded.status, MuxStatus::End);
    }
}
