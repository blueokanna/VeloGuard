//! TCP Transport - Raw TCP connection transport
//! 
//! This is the default transport layer, providing direct TCP connections
//! without any additional encapsulation.

use crate::error::{Error, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// TCP transport configuration
#[derive(Debug, Clone, Default)]
pub struct TcpConfig {
    /// Enable TCP keepalive
    pub keepalive: bool,
    /// TCP keepalive interval in seconds
    pub keepalive_interval: Option<u32>,
    /// Enable TCP_NODELAY (disable Nagle's algorithm)
    pub nodelay: bool,
}

/// TCP transport stream wrapper
pub struct TcpTransportStream {
    inner: TcpStream,
}

impl TcpTransportStream {
    /// Create a new TCP transport stream from an existing TcpStream
    pub fn new(stream: TcpStream) -> Self {
        Self { inner: stream }
    }

    /// Connect to a remote address
    pub async fn connect(addr: SocketAddr, config: &TcpConfig) -> Result<Self> {
        let stream = TcpStream::connect(addr).await
            .map_err(|e| Error::network(format!("TCP connect failed: {}", e)))?;

        if config.nodelay {
            stream.set_nodelay(true).ok();
        }

        Ok(Self { inner: stream })
    }

    /// Connect to a domain:port
    pub async fn connect_domain(domain: &str, port: u16, config: &TcpConfig) -> Result<Self> {
        let addr = format!("{}:{}", domain, port);
        let stream = TcpStream::connect(&addr).await
            .map_err(|e| Error::network(format!("TCP connect to {} failed: {}", addr, e)))?;

        if config.nodelay {
            stream.set_nodelay(true).ok();
        }

        Ok(Self { inner: stream })
    }

    /// Get the inner TcpStream
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }

    /// Get a reference to the inner TcpStream
    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.local_addr()
            .map_err(|e| Error::network(format!("Failed to get local addr: {}", e)))
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.inner.peer_addr()
            .map_err(|e| Error::network(format!("Failed to get peer addr: {}", e)))
    }
}

impl AsyncRead for TcpTransportStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpTransportStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
