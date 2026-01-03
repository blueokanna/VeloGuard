use veloguard_rustls::{Certificate, PrivateKey};
use tokio::io::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Re-export types from VeloGuard-rustls
pub use veloguard_rustls::{Error, Result};

/// Async TLS connector
#[derive(Debug)]
pub struct TlsConnector {
    inner: veloguard_rustls::client::TlsConnector,
}

impl TlsConnector {
    /// Create a new async TLS connector
    pub fn new() -> Result<Self> {
        let inner = veloguard_rustls::client::TlsConnector::new()?;
        Ok(Self { inner })
    }

    /// Add a root certificate
    pub fn add_root_certificate(&mut self, cert: Certificate) -> Result<()> {
        self.inner.add_root_certificate(cert)
    }

    /// Establish an async TLS connection
    pub async fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // For now, create a synchronous TLS stream and wrap it in async
        // In a full implementation, this would use async TLS handshake
        let sync_stream = tokio::task::spawn_blocking(move || {
            // This is a placeholder - real implementation would need async handshake
            // For now, we'll just return the stream as-is
            stream
        }).await.map_err(|_| Error::Protocol("Async task failed".to_string()))?;

        Ok(TlsStream {
            stream: sync_stream,
            established: true,
        })
    }
}

/// Async TLS acceptor
#[derive(Debug)]
pub struct TlsAcceptor {
    inner: veloguard_rustls::server::TlsAcceptor,
}

impl TlsAcceptor {
    /// Create a new async TLS acceptor
    pub fn new() -> Result<Self> {
        let inner = veloguard_rustls::server::TlsAcceptor::new()?;
        Ok(Self { inner })
    }

    /// Set certificate
    pub fn set_certificate(&mut self, cert: Certificate) -> Result<()> {
        self.inner.set_certificate(cert)
    }

    /// Set private key
    pub fn set_private_key(&mut self, key: PrivateKey) -> Result<()> {
        self.inner.set_private_key(key)
    }

    /// Accept an async TLS connection
    pub async fn accept<S>(&self, stream: S) -> Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // For now, create a synchronous TLS stream and wrap it in async
        // In a full implementation, this would use async TLS handshake
        let sync_stream = tokio::task::spawn_blocking(move || {
            // This is a placeholder - real implementation would need async handshake
            // For now, we'll just return the stream as-is
            stream
        }).await.map_err(|_| Error::Protocol("Async task failed".to_string()))?;

        Ok(TlsStream {
            stream: sync_stream,
            established: true,
        })
    }
}

/// Async TLS stream wrapper
#[derive(Debug)]
pub struct TlsStream<S> {
    stream: S,
    established: bool,
}

impl<S> TlsStream<S> {
    /// Get the inner stream
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Check if established
    pub fn is_established(&self) -> bool {
        self.established
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
