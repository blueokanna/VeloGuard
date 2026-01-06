use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use quinn::{RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::crypto::CryptoContext;
use super::error::{Result, QuicError};
use super::MAX_PAYLOAD_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    Tcp,
    Udp,
    Control,
}

pin_project! {
    pub struct QuicStream {
        #[pin]
        send: SendStream,
        #[pin]
        recv: RecvStream,
        crypto: Option<CryptoContext>,
        read_buf: BytesMut,
        stream_type: StreamType,
    }
}

impl QuicStream {
    pub fn new(send: SendStream, recv: RecvStream, stream_type: StreamType) -> Self {
        Self {
            send,
            recv,
            crypto: None,
            read_buf: BytesMut::with_capacity(MAX_PAYLOAD_SIZE),
            stream_type,
        }
    }

    pub fn with_crypto(
        send: SendStream,
        recv: RecvStream,
        crypto: CryptoContext,
        stream_type: StreamType,
    ) -> Self {
        Self {
            send,
            recv,
            crypto: Some(crypto),
            read_buf: BytesMut::with_capacity(MAX_PAYLOAD_SIZE),
            stream_type,
        }
    }

    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    pub fn id(&self) -> quinn::StreamId {
        self.send.id()
    }

    pub async fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.send.write_all(data).await?;
        Ok(())
    }

    pub async fn read_raw(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        match self.recv.read(buf).await? {
            Some(n) => Ok(Some(n)),
            None => Ok(None),
        }
    }

    pub async fn write_encrypted(&mut self, data: &[u8]) -> Result<()> {
        let encrypted = if let Some(ref mut crypto) = self.crypto {
            crypto.encrypt(data)?
        } else {
            Bytes::copy_from_slice(data)
        };

        let len = encrypted.len() as u16;
        self.send.write_all(&len.to_be_bytes()).await?;
        self.send.write_all(&encrypted).await?;
        Ok(())
    }

    pub async fn read_encrypted(&mut self) -> Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 2];
        match self.recv.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
            Err(quinn::ReadExactError::ReadError(e)) => return Err(e.into()),
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len > MAX_PAYLOAD_SIZE + 28 {
            return Err(QuicError::InvalidPacket);
        }

        let mut data = vec![0u8; len];
        match self.recv.read_exact(&mut data).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
            Err(quinn::ReadExactError::ReadError(e)) => return Err(e.into()),
        }

        let decrypted = if let Some(ref crypto) = self.crypto {
            crypto.decrypt(&data)?
        } else {
            data
        };

        Ok(Some(decrypted))
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish()?;
        Ok(())
    }

    pub fn stop(&mut self, error_code: quinn::VarInt) -> Result<()> {
        self.recv.stop(error_code)?;
        Ok(())
    }

    pub fn split(self) -> (QuicSendStream, QuicRecvStream) {
        (
            QuicSendStream {
                inner: self.send,
                crypto: self.crypto.clone(),
            },
            QuicRecvStream {
                inner: self.recv,
                crypto: self.crypto,
            },
        )
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        this.recv.poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        match this.send.poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        match this.send.finish() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::other(e))),
        }
    }
}

pub struct QuicSendStream {
    inner: SendStream,
    crypto: Option<CryptoContext>,
}

impl QuicSendStream {
    pub async fn write_encrypted(&mut self, data: &[u8]) -> Result<()> {
        let encrypted = if let Some(ref mut crypto) = self.crypto {
            crypto.encrypt(data)?
        } else {
            Bytes::copy_from_slice(data)
        };

        let len = encrypted.len() as u16;
        self.inner.write_all(&len.to_be_bytes()).await?;
        self.inner.write_all(&encrypted).await?;
        Ok(())
    }

    pub async fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.inner.write_all(data).await?;
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.inner.finish()?;
        Ok(())
    }
}

pub struct QuicRecvStream {
    inner: RecvStream,
    crypto: Option<CryptoContext>,
}

impl QuicRecvStream {
    pub async fn read_encrypted(&mut self) -> Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 2];
        match self.inner.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
            Err(quinn::ReadExactError::ReadError(e)) => return Err(e.into()),
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len > MAX_PAYLOAD_SIZE + 28 {
            return Err(QuicError::InvalidPacket);
        }

        let mut data = vec![0u8; len];
        match self.inner.read_exact(&mut data).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
            Err(quinn::ReadExactError::ReadError(e)) => return Err(e.into()),
        }

        let decrypted = if let Some(ref crypto) = self.crypto {
            crypto.decrypt(&data)?
        } else {
            data
        };

        Ok(Some(decrypted))
    }

    pub async fn read_raw(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        match self.inner.read(buf).await? {
            Some(n) => Ok(Some(n)),
            None => Ok(None),
        }
    }

    pub fn stop(&mut self, error_code: quinn::VarInt) -> Result<()> {
        self.inner.stop(error_code)?;
        Ok(())
    }
}
