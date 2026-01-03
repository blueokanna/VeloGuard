//! TLS 1.2 implementation

use crate::{Error, Result, TlsConfig, Certificate, PrivateKey};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use std::pin::Pin;
use std::task::{Context, Poll};

/// TLS 1.2 stream wrapper
pub struct TlsStream<S> {
    inner: S,
    state: TlsState,
}

enum TlsState {
    Handshaking,
    Established,
}

impl<S> TlsStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            state: TlsState::Handshaking,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, TlsState::Established)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
