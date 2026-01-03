//! TCP stack implementation for veloguard-netstack
//!
//! Handles TCP connections from the TUN device and provides
//! AsyncRead/AsyncWrite streams for proxying.

use crate::error::{NetStackError, Result};
use bytes::{Bytes, BytesMut};
use futures::Stream;
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::debug;

/// TCP connection identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnectionId {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
}

impl std::fmt::Display for TcpConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.src_addr, self.dst_addr)
    }
}

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// Internal TCP connection data
struct TcpConnectionInner {
    state: TcpState,
    /// Data received from remote, waiting to be read by application
    recv_buffer: BytesMut,
    /// Data to be sent to remote
    send_buffer: BytesMut,
    /// Waker for read operations
    read_waker: Option<Waker>,
    /// Waker for write operations
    write_waker: Option<Waker>,
    /// Connection closed flag
    closed: bool,
    /// Bytes uploaded
    upload_bytes: u64,
    /// Bytes downloaded
    download_bytes: u64,
}

/// A TCP connection that can be used for proxying
pub struct TcpConnection {
    id: TcpConnectionId,
    inner: Arc<Mutex<TcpConnectionInner>>,
    /// Channel to send data back to the stack
    stack_tx: mpsc::Sender<TcpStackEvent>,
}

impl TcpConnection {
    fn new(id: TcpConnectionId, stack_tx: mpsc::Sender<TcpStackEvent>) -> Self {
        Self {
            id,
            inner: Arc::new(Mutex::new(TcpConnectionInner {
                state: TcpState::SynReceived,
                recv_buffer: BytesMut::with_capacity(64 * 1024),
                send_buffer: BytesMut::with_capacity(64 * 1024),
                read_waker: None,
                write_waker: None,
                closed: false,
                upload_bytes: 0,
                download_bytes: 0,
            })),
            stack_tx,
        }
    }

    /// Get the connection ID
    pub fn id(&self) -> TcpConnectionId {
        self.id
    }

    /// Get the source address
    pub fn src_addr(&self) -> SocketAddr {
        self.id.src_addr
    }

    /// Get the destination address
    pub fn dst_addr(&self) -> SocketAddr {
        self.id.dst_addr
    }

    /// Get the current state
    pub fn state(&self) -> TcpState {
        self.inner.lock().state
    }

    /// Check if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.inner.lock().closed
    }

    /// Get upload bytes
    pub fn upload_bytes(&self) -> u64 {
        self.inner.lock().upload_bytes
    }

    /// Get download bytes
    pub fn download_bytes(&self) -> u64 {
        self.inner.lock().download_bytes
    }

    /// Push data received from the network into the connection
    pub(crate) fn push_recv_data(&self, data: &[u8]) {
        let mut inner = self.inner.lock();
        inner.recv_buffer.extend_from_slice(data);
        inner.download_bytes += data.len() as u64;
        if let Some(waker) = inner.read_waker.take() {
            waker.wake();
        }
    }

    /// Take data to be sent to the network
    #[allow(dead_code)]
    pub(crate) fn take_send_data(&self) -> Option<Bytes> {
        let mut inner = self.inner.lock();
        if inner.send_buffer.is_empty() {
            None
        } else {
            Some(inner.send_buffer.split().freeze())
        }
    }

    /// Set the connection state
    #[allow(dead_code)]
    pub(crate) fn set_state(&self, state: TcpState) {
        let mut inner = self.inner.lock();
        inner.state = state;
        if state == TcpState::Closed {
            inner.closed = true;
            if let Some(waker) = inner.read_waker.take() {
                waker.wake();
            }
            if let Some(waker) = inner.write_waker.take() {
                waker.wake();
            }
        }
    }

    /// Close the connection
    pub fn close(&self) {
        let mut inner = self.inner.lock();
        inner.closed = true;
        inner.state = TcpState::Closed;
        if let Some(waker) = inner.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = inner.write_waker.take() {
            waker.wake();
        }
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut inner = self.inner.lock();

        if !inner.recv_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), inner.recv_buffer.len());
            buf.put_slice(&inner.recv_buffer.split_to(len));
            return Poll::Ready(Ok(()));
        }

        if inner.closed {
            return Poll::Ready(Ok(())); // EOF
        }

        inner.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut inner = self.inner.lock();

        if inner.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Connection closed",
            )));
        }

        inner.send_buffer.extend_from_slice(buf);
        inner.upload_bytes += buf.len() as u64;

        // Notify the stack that there's data to send
        let _ = self.stack_tx.try_send(TcpStackEvent::DataReady(self.id));

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.close();
        let _ = self.stack_tx.try_send(TcpStackEvent::Close(self.id));
        Poll::Ready(Ok(()))
    }
}

/// Events from TCP connections to the stack
#[derive(Debug)]
pub enum TcpStackEvent {
    /// Data is ready to be sent
    DataReady(TcpConnectionId),
    /// Connection should be closed
    Close(TcpConnectionId),
}

/// TCP stack that manages connections
pub struct TcpStack {
    /// Active connections
    connections: Arc<Mutex<HashMap<TcpConnectionId, Arc<TcpConnection>>>>,
    /// Channel for new connections
    new_conn_tx: mpsc::Sender<Arc<TcpConnection>>,
    new_conn_rx: Option<mpsc::Receiver<Arc<TcpConnection>>>,
    /// Channel for stack events
    event_tx: mpsc::Sender<TcpStackEvent>,
    event_rx: Option<mpsc::Receiver<TcpStackEvent>>,
    /// Connection counter
    conn_counter: AtomicU64,
}

impl TcpStack {
    pub fn new() -> Self {
        let (new_conn_tx, new_conn_rx) = mpsc::channel(256);
        let (event_tx, event_rx) = mpsc::channel(1024);

        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            new_conn_tx,
            new_conn_rx: Some(new_conn_rx),
            event_tx,
            event_rx: Some(event_rx),
            conn_counter: AtomicU64::new(0),
        }
    }

    /// Create a new TCP connection (called when SYN is received)
    pub fn create_connection(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> Result<Arc<TcpConnection>> {
        let id = TcpConnectionId { src_addr, dst_addr };

        let conn = Arc::new(TcpConnection::new(id, self.event_tx.clone()));
        
        {
            let mut connections = self.connections.lock();
            if connections.contains_key(&id) {
                return Err(NetStackError::TcpError("Connection already exists".to_string()));
            }
            connections.insert(id, conn.clone());
        }

        self.conn_counter.fetch_add(1, Ordering::Relaxed);
        debug!("TCP connection created: {}", id);

        // Notify listener about new connection
        let _ = self.new_conn_tx.try_send(conn.clone());

        Ok(conn)
    }

    /// Get an existing connection
    pub fn get_connection(&self, id: &TcpConnectionId) -> Option<Arc<TcpConnection>> {
        self.connections.lock().get(id).cloned()
    }

    /// Remove a connection
    pub fn remove_connection(&self, id: &TcpConnectionId) -> Option<Arc<TcpConnection>> {
        let conn = self.connections.lock().remove(id);
        if conn.is_some() {
            debug!("TCP connection removed: {}", id);
        }
        conn
    }

    /// Get the number of active connections
    pub fn active_connections(&self) -> usize {
        self.connections.lock().len()
    }

    /// Get total connection count
    pub fn total_connections(&self) -> u64 {
        self.conn_counter.load(Ordering::Relaxed)
    }

    /// Take the new connection receiver
    pub fn take_listener(&mut self) -> Option<TcpListener> {
        self.new_conn_rx.take().map(|rx| TcpListener { rx })
    }

    /// Take the event receiver
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<TcpStackEvent>> {
        self.event_rx.take()
    }

    /// Push received data to a connection
    pub fn push_data(&self, id: &TcpConnectionId, data: &[u8]) -> Result<()> {
        if let Some(conn) = self.get_connection(id) {
            conn.push_recv_data(data);
            Ok(())
        } else {
            Err(NetStackError::TcpError("Connection not found".to_string()))
        }
    }

    /// Close all connections
    pub fn close_all(&self) {
        let connections: Vec<_> = self.connections.lock().drain().collect();
        for (_, conn) in connections {
            conn.close();
        }
    }
}

impl Default for TcpStack {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP listener that accepts new connections
pub struct TcpListener {
    rx: mpsc::Receiver<Arc<TcpConnection>>,
}

impl TcpListener {
    /// Accept a new connection
    pub async fn accept(&mut self) -> Option<Arc<TcpConnection>> {
        self.rx.recv().await
    }
}

impl Stream for TcpListener {
    type Item = Arc<TcpConnection>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}

pin_project! {
    /// A TCP stream wrapper that implements AsyncRead + AsyncWrite
    pub struct TcpStream {
        conn: Arc<TcpConnection>,
    }
}

impl TcpStream {
    pub fn new(conn: Arc<TcpConnection>) -> Self {
        Self { conn }
    }

    pub fn connection(&self) -> &Arc<TcpConnection> {
        &self.conn
    }

    pub fn src_addr(&self) -> SocketAddr {
        self.conn.src_addr()
    }

    pub fn dst_addr(&self) -> SocketAddr {
        self.conn.dst_addr()
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let mut inner = this.conn.inner.lock();

        if !inner.recv_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), inner.recv_buffer.len());
            buf.put_slice(&inner.recv_buffer.split_to(len));
            return Poll::Ready(Ok(()));
        }

        if inner.closed {
            return Poll::Ready(Ok(()));
        }

        inner.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let mut inner = this.conn.inner.lock();

        if inner.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Connection closed",
            )));
        }

        inner.send_buffer.extend_from_slice(buf);
        inner.upload_bytes += buf.len() as u64;

        let _ = this.conn.stack_tx.try_send(TcpStackEvent::DataReady(this.conn.id));

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();
        this.conn.close();
        let _ = this.conn.stack_tx.try_send(TcpStackEvent::Close(this.conn.id));
        Poll::Ready(Ok(()))
    }
}
