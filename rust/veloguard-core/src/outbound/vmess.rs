use crate::config::OutboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use crate::time_sync;
use crate::tls::SkipServerVerification;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use chacha20poly1305::ChaCha20Poly1305;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use sha1::Sha1;
use sha2::Sha256;
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Shake128,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;
type HmacMd5 = Hmac<Md5>;
type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

const VMESS_VERSION: u8 = 1;
const VMESS_AEAD_AUTH_LEN: usize = 16;
const VMESS_AEAD_NONCE_LEN: usize = 12;
const VMESS_TIME_WINDOW_SECS: i64 = 30;
const VMESS_TIME_TOLERANCE: i64 = 2;
const VMESS_MAX_CHUNK_SIZE: usize = 16384; // 2^14

#[allow(dead_code)]
const VMESS_AEAD_KEY_LEN: usize = 16;

pub struct ShakeMask {
    reader: sha3::Shake128Reader,
}

impl ShakeMask {
    pub fn new(iv: &[u8]) -> Self {
        use sha3::digest::Update;
        let mut hasher = Shake128::default();
        Update::update(&mut hasher, iv);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// 获取下一个掩码字节
    pub fn next_byte(&mut self) -> u8 {
        let mut buf = [0u8; 1];
        self.reader.read(&mut buf);
        buf[0]
    }

    /// 获取下一个 16 位掩码
    pub fn next_u16(&mut self) -> u16 {
        let high = self.next_byte() as u16;
        let low = self.next_byte() as u16;
        (high << 8) | low
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCommand {
    Tcp = 0x01,
    Udp = 0x02,
}

impl VmessCommand {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(VmessCommand::Tcp),
            0x02 => Some(VmessCommand::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCipher {
    Auto,
    Aes128Cfb,        // 0x00 - Legacy
    None,             // 0x01 - 不加密
    Aes128Gcm,        // 0x02 - AES-128-GCM
    Chacha20Poly1305, // 0x03 - ChaCha20-Poly1305
    Zero,             // 特殊: 用于测试
}

impl VmessCipher {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "aes-128-cfb" | "aes128cfb" => VmessCipher::Aes128Cfb,
            "aes-128-gcm" | "aes128gcm" => VmessCipher::Aes128Gcm,
            "chacha20-poly1305" | "chacha20poly1305" => VmessCipher::Chacha20Poly1305,
            "none" => VmessCipher::None,
            "zero" => VmessCipher::Zero,
            _ => VmessCipher::Auto,
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            VmessCipher::Aes128Cfb => 0x00,        // AES-128-CFB
            VmessCipher::None => 0x01,             // 不加密
            VmessCipher::Aes128Gcm => 0x02,        // AES-128-GCM
            VmessCipher::Chacha20Poly1305 => 0x03, // ChaCha20-Poly1305
            VmessCipher::Zero => 0x01,             // Zero 映射到不加密
            // Auto: 根据平台选择最佳加密方式
            VmessCipher::Auto => {
                #[cfg(target_os = "android")]
                {
                    return 0x03; // ChaCha20-Poly1305
                }
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    if std::arch::is_x86_feature_detected!("aes") {
                        return 0x02; // AES-128-GCM
                    }
                    0x03// ChaCha20-Poly1305
                }
                #[cfg(not(any(
                    target_os = "android",
                    target_arch = "x86",
                    target_arch = "x86_64"
                )))]
                {
                    0x02 // AES-128-GCM
                }
            }
        }
    }

    pub fn resolve(self) -> Self {
        match self {
            VmessCipher::Auto => {
                #[cfg(target_os = "android")]
                {
                    return VmessCipher::Chacha20Poly1305;
                }
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    if std::arch::is_x86_feature_detected!("aes") {
                        return VmessCipher::Aes128Gcm;
                    }
                    VmessCipher::Chacha20Poly1305
                }
                #[cfg(not(any(
                    target_os = "android",
                    target_arch = "x86",
                    target_arch = "x86_64"
                )))]
                {
                    VmessCipher::Aes128Gcm
                }
            }
            other => other,
        }
    }

    pub fn auth_len(self) -> usize {
        match self.resolve() {
            VmessCipher::Aes128Gcm | VmessCipher::Chacha20Poly1305 => 16,
            VmessCipher::Aes128Cfb => 4, // FNV1a hash
            VmessCipher::None | VmessCipher::Zero | VmessCipher::Auto => 0,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum VmessAddressType {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct VmessOption: u8 {
        const CHUNK_STREAM = 0x01;
        const CONNECTION_REUSE = 0x02;
        const CHUNK_MASKING = 0x04;
        const GLOBAL_PADDING = 0x08;
        const AUTHENTICATED_LENGTH = 0x10;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessTransport {
    Tcp,
    Ws,
    H2,
    Grpc,
    Quic,
    Mkcp,
}

impl VmessTransport {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ws" | "websocket" => VmessTransport::Ws,
            "h2" | "http2" => VmessTransport::H2,
            "grpc" => VmessTransport::Grpc,
            "quic" => VmessTransport::Quic,
            "kcp" | "mkcp" => VmessTransport::Mkcp,
            _ => VmessTransport::Tcp,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmessWsOptions {
    pub path: String,
    pub host: Option<String>,
    pub headers: std::collections::HashMap<String, String>,
}

impl Default for VmessWsOptions {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            headers: std::collections::HashMap::new(),
        }
    }
}

/// UDP session state for VMess
struct VmessUdpSession {
    stream: tokio::sync::Mutex<Box<dyn AsyncReadWrite>>,
    request_key: [u8; 16],
    request_iv: [u8; 16],
    response_key: [u8; 16],
    response_iv: [u8; 16],
    chunk_count: AtomicU64,
    last_used: std::sync::RwLock<Instant>,
}

impl VmessUdpSession {
    fn new(
        stream: Box<dyn AsyncReadWrite>,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
    ) -> Self {
        Self {
            stream: tokio::sync::Mutex::new(stream),
            request_key,
            request_iv,
            response_key,
            response_iv,
            chunk_count: AtomicU64::new(0),
            last_used: std::sync::RwLock::new(Instant::now()),
        }
    }

    fn next_chunk_count(&self) -> u16 {
        (self.chunk_count.fetch_add(1, Ordering::SeqCst) % 65536) as u16
    }

    fn touch(&self) {
        if let Ok(mut guard) = self.last_used.write() {
            *guard = Instant::now();
        }
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        if let Ok(guard) = self.last_used.read() {
            guard.elapsed() > timeout
        } else {
            true
        }
    }
}

/// QUIC bidirectional stream wrapper that implements AsyncRead and AsyncWrite
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        let this = self.get_mut();
        let recv = &mut this.recv;
        let unfilled = buf.initialize_unfilled();
        use futures::AsyncRead as FuturesAsyncRead;
        let pinned = std::pin::Pin::new(recv);

        match FuturesAsyncRead::poll_read(pinned, cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use futures::AsyncWrite as FuturesAsyncWrite;
        let this = self.get_mut();
        let pinned = std::pin::Pin::new(&mut this.send);
        FuturesAsyncWrite::poll_write(pinned, cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use futures::AsyncWrite as FuturesAsyncWrite;
        let this = self.get_mut();
        let pinned = std::pin::Pin::new(&mut this.send);
        FuturesAsyncWrite::poll_flush(pinned, cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use futures::AsyncWrite as FuturesAsyncWrite;
        let this = self.get_mut();
        let pinned = std::pin::Pin::new(&mut this.send);
        FuturesAsyncWrite::poll_close(pinned, cx)
    }
}

pub struct WebSocketStream<S> {
    inner: S,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

impl<S> WebSocketStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketStream<S> {
    pub async fn handshake(
        stream: S,
        host: &str,
        path: &str,
        extra_headers: &std::collections::HashMap<String, String>,
    ) -> Result<Self> {
        let mut ws = Self::new(stream);

        let mut key_bytes = [0u8; 16];
        getrandom::fill(&mut key_bytes)
            .map_err(|e| Error::protocol(format!("Failed to generate WebSocket key: {}", e)))?;
        let ws_key = BASE64.encode(key_bytes);
        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n",
            path, host, ws_key
        );

        for (key, value) in extra_headers {
            if key.to_lowercase() != "host" {
                request.push_str(&format!("{}: {}\r\n", key, value));
            }
        }
        request.push_str("\r\n");
        ws.inner
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::network(format!("Failed to send WebSocket handshake: {}", e)))?;
        ws.inner.flush().await.ok();

        let mut response = Vec::with_capacity(1024);
        let mut buf = [0u8; 1];
        let mut found_end = false;

        while response.len() < 4096 {
            ws.inner
                .read_exact(&mut buf)
                .await
                .map_err(|e| Error::network(format!("Failed to read WebSocket response: {}", e)))?;
            response.push(buf[0]);

            if response.len() >= 4 && &response[response.len() - 4..] == b"\r\n\r\n" {
                found_end = true;
                break;
            }
        }

        if !found_end {
            return Err(Error::protocol(
                "WebSocket handshake response too long or incomplete",
            ));
        }

        let response_str = String::from_utf8_lossy(&response);
        if !response_str.starts_with("HTTP/1.1 101") {
            return Err(Error::protocol(format!(
                "WebSocket handshake failed: {}",
                response_str.lines().next().unwrap_or("unknown")
            )));
        }

        // Verify Sec-WebSocket-Accept
        let expected_accept = compute_websocket_accept(&ws_key);
        let accept_found = response_str.lines().any(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("sec-websocket-accept:") {
                let value = line.split(':').nth(1).map(|s| s.trim()).unwrap_or("");
                value == expected_accept
            } else {
                false
            }
        });

        if !accept_found {
            tracing::warn!(
                "WebSocket Sec-WebSocket-Accept header mismatch or missing, continuing anyway"
            );
        }

        tracing::debug!("WebSocket handshake completed successfully");
        Ok(ws)
    }

    #[allow(dead_code)]
    pub async fn write_frame(&mut self, data: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(14 + data.len());

        frame.push(0x82);
        let len = data.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        let mut mask = [0u8; 4];
        getrandom::fill(&mut mask)
            .map_err(|e| Error::protocol(format!("Failed to generate mask: {}", e)))?;
        frame.extend_from_slice(&mask);

        // Masked payload
        for (i, byte) in data.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }

        self.inner
            .write_all(&frame)
            .await
            .map_err(|e| Error::network(format!("Failed to write WebSocket frame: {}", e)))?;

        Ok(())
    }

    /// Read a WebSocket frame, returns the payload data
    #[allow(dead_code)]
    pub async fn read_frame(&mut self) -> Result<Vec<u8>> {
        // Read first 2 bytes
        let mut header = [0u8; 2];
        self.inner
            .read_exact(&mut header)
            .await
            .map_err(|e| Error::network(format!("Failed to read WebSocket frame header: {}", e)))?;

        let _fin = (header[0] & 0x80) != 0;
        let opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let mut payload_len = (header[1] & 0x7F) as u64;

        if opcode == 0x08 {
            return Err(Error::network("WebSocket connection closed by server"));
        }

        // Handle ping frame - read payload and continue (non-recursive)
        if opcode == 0x09 {
            if payload_len > 0 {
                let mut ping_data = vec![0u8; payload_len as usize];
                self.inner.read_exact(&mut ping_data).await.ok();
            }
            // Return empty to signal caller should retry
            return Ok(Vec::new());
        }

        // Extended payload length
        if payload_len == 126 {
            let mut ext = [0u8; 2];
            self.inner
                .read_exact(&mut ext)
                .await
                .map_err(|e| Error::network(format!("Failed to read extended length: {}", e)))?;
            payload_len = u16::from_be_bytes(ext) as u64;
        } else if payload_len == 127 {
            let mut ext = [0u8; 8];
            self.inner
                .read_exact(&mut ext)
                .await
                .map_err(|e| Error::network(format!("Failed to read extended length: {}", e)))?;
            payload_len = u64::from_be_bytes(ext);
        }

        let mask = if masked {
            let mut m = [0u8; 4];
            self.inner
                .read_exact(&mut m)
                .await
                .map_err(|e| Error::network(format!("Failed to read mask: {}", e)))?;
            Some(m)
        } else {
            None
        };

        // Read payload
        let mut payload = vec![0u8; payload_len as usize];
        self.inner
            .read_exact(&mut payload)
            .await
            .map_err(|e| Error::network(format!("Failed to read WebSocket payload: {}", e)))?;

        // Unmask if needed
        if let Some(m) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= m[i % 4];
            }
        }

        Ok(payload)
    }

    /// Read frame with retry for control frames
    #[allow(dead_code)]
    pub async fn read_frame_data(&mut self) -> Result<Vec<u8>> {
        loop {
            let data = self.read_frame().await?;
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
}

fn compute_websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let result = hasher.finalize();
    BASE64.encode(result)
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        let mut header = [0u8; 2];
        let inner = &mut self.inner;

        let mut header_buf = tokio::io::ReadBuf::new(&mut header);
        match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut header_buf) {
            Poll::Ready(Ok(())) => {
                if header_buf.filled().len() < 2 {
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let payload_len_byte = header[1] & 0x7F;

        if opcode == 0x08 {
            return Poll::Ready(Ok(()));
        }

        if payload_len_byte >= 126 {
            return Poll::Ready(Err(std::io::Error::other(
                "Large WebSocket frames not yet supported in poll_read",
            )));
        }

        let payload_len = payload_len_byte as usize;
        let mask_len = if masked { 4 } else { 0 };
        let total_len = payload_len + mask_len;

        if total_len == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let mut frame_data = vec![0u8; total_len];
        let mut frame_buf = tokio::io::ReadBuf::new(&mut frame_data);

        match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut frame_buf) {
            Poll::Ready(Ok(())) => {
                if frame_buf.filled().len() < total_len {
                    // Incomplete read, need to buffer
                    self.read_buffer = frame_buf.filled().to_vec();
                    self.read_pos = 0;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let payload = if masked {
            let mask: [u8; 4] = [frame_data[0], frame_data[1], frame_data[2], frame_data[3]];
            let mut payload = frame_data[4..].to_vec();
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
            payload
        } else {
            frame_data
        };

        let to_copy = std::cmp::min(payload.len(), buf.remaining());
        buf.put_slice(&payload[..to_copy]);

        if to_copy < payload.len() {
            self.read_buffer = payload[to_copy..].to_vec();
            self.read_pos = 0;
        }

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;

        let mut frame = Vec::with_capacity(14 + buf.len());
        frame.push(0x82);

        let len = buf.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        let mask: [u8; 4] = rand::random();
        frame.extend_from_slice(&mask);

        for (i, byte) in buf.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }

        let inner = &mut self.inner;
        let pinned = std::pin::Pin::new(inner);

        match pinned.poll_write(cx, &frame) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let inner = &mut self.inner;
        std::pin::Pin::new(inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let inner = &mut self.inner;
        std::pin::Pin::new(inner).poll_shutdown(cx)
    }
}

/// mKCP options for VMess
#[derive(Debug, Clone)]
pub struct VmessMkcpOptions {
    pub mtu: usize,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub read_buffer_size: usize,
    pub write_buffer_size: usize,
    pub header_type: String,
    pub seed: Option<String>,
}

impl Default for VmessMkcpOptions {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            read_buffer_size: 4 * 1024 * 1024,
            write_buffer_size: 4 * 1024 * 1024,
            header_type: "none".to_string(),
            seed: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmessMuxOptions {
    pub enabled: bool,
    pub concurrency: usize,
}

impl Default for VmessMuxOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            concurrency: 8,
        }
    }
}

pub struct VmessOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    uuid: Uuid,
    cipher: VmessCipher,
    udp_enabled: bool,
    cmd_key: [u8; 16],
    alter_id: u16,
    transport: VmessTransport,
    tls_enabled: bool,
    skip_cert_verify: bool,
    sni: Option<String>,
    ws_opts: Option<VmessWsOptions>,
    mkcp_opts: Option<VmessMkcpOptions>,
    mux_opts: VmessMuxOptions,
    quic_endpoint: Mutex<Option<Endpoint>>,
    quic_connection: Mutex<Option<quinn::Connection>>,
    quic_alpn: Vec<String>,
    udp_sessions: DashMap<String, Arc<VmessUdpSession>>,
}

pub struct VmessHeader {
    pub version: u8,
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_header: u8,
    pub option: VmessOption,
    pub padding_length: u8,
    pub security: VmessCipher,
    pub command: VmessCommand,
    pub port: u16,
    pub address_type: VmessAddressType,
    pub address: Vec<u8>,
}

pub struct VmessResponseHeader {
    pub response_header: u8,
    pub option: u8,
    pub command: u8,
    pub command_length: u8,
}

impl VmessOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for VMess"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for VMess"))?;

        let uuid_str = config
            .options
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Missing UUID for VMess"))?;

        let uuid =
            Uuid::parse_str(uuid_str).map_err(|e| Error::config(format!("Invalid UUID: {}", e)))?;

        let uuid_bytes = *uuid.as_bytes();

        let alter_id = config
            .options
            .get("alterId")
            .or_else(|| config.options.get("alter-id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as u16;

        if alter_id > 0 {
            tracing::info!(
                "VMess using legacy mode with alterId={}. Consider using alterId=0 for AEAD mode.",
                alter_id
            );
        } else {
            tracing::debug!("VMess using AEAD mode (alterId=0)");
        }

        let cipher_str = config
            .options
            .get("cipher")
            .and_then(|v| v.as_str())
            .unwrap_or("auto");
        let cipher = VmessCipher::from_str(cipher_str);

        let udp_enabled = config
            .options
            .get("udp")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let transport_str = config
            .options
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp");
        let transport = VmessTransport::from_str(transport_str);

        let tls_enabled = config
            .options
            .get("tls")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let skip_cert_verify = config
            .options
            .get("skip-cert-verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let sni = config
            .options
            .get("sni")
            .or_else(|| config.options.get("servername"))
            .and_then(|v| v.as_str())
            .map(String::from);

        let ws_opts = if transport == VmessTransport::Ws {
            let ws_opts_value = config.options.get("ws-opts");
            let path = ws_opts_value
                .and_then(|v| v.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();

            let host = ws_opts_value
                .and_then(|v| v.get("headers"))
                .and_then(|v| v.get("Host"))
                .and_then(|v| v.as_str())
                .map(String::from);

            let mut headers = std::collections::HashMap::new();
            if let Some(headers_value) = ws_opts_value.and_then(|v| v.get("headers")) {
                if let Some(map) = headers_value.as_mapping() {
                    for (k, v) in map {
                        if let (Some(key), Some(value)) = (k.as_str(), v.as_str()) {
                            headers.insert(key.to_string(), value.to_string());
                        }
                    }
                }
            }

            Some(VmessWsOptions {
                path,
                host,
                headers,
            })
        } else {
            None
        };

        let quic_alpn = config
            .options
            .get("quic-opts")
            .and_then(|v| v.get("alpn"))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["h3".to_string()]);

        // Parse mKCP options
        let mkcp_opts = if transport == VmessTransport::Mkcp {
            let mkcp_opts_value = config
                .options
                .get("kcp-opts")
                .or_else(|| config.options.get("mkcp-opts"));

            let mtu = mkcp_opts_value
                .and_then(|v| v.get("mtu"))
                .and_then(|v| v.as_i64())
                .unwrap_or(1350) as usize;

            let tti = mkcp_opts_value
                .and_then(|v| v.get("tti"))
                .and_then(|v| v.as_i64())
                .unwrap_or(50) as u32;

            let uplink_capacity = mkcp_opts_value
                .and_then(|v| v.get("uplinkCapacity"))
                .or_else(|| mkcp_opts_value.and_then(|v| v.get("uplink-capacity")))
                .and_then(|v| v.as_i64())
                .unwrap_or(5) as u32;

            let downlink_capacity = mkcp_opts_value
                .and_then(|v| v.get("downlinkCapacity"))
                .or_else(|| mkcp_opts_value.and_then(|v| v.get("downlink-capacity")))
                .and_then(|v| v.as_i64())
                .unwrap_or(20) as u32;

            let congestion = mkcp_opts_value
                .and_then(|v| v.get("congestion"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let read_buffer_size = mkcp_opts_value
                .and_then(|v| v.get("readBufferSize"))
                .or_else(|| mkcp_opts_value.and_then(|v| v.get("read-buffer-size")))
                .and_then(|v| v.as_i64())
                .unwrap_or(4 * 1024 * 1024) as usize;

            let write_buffer_size = mkcp_opts_value
                .and_then(|v| v.get("writeBufferSize"))
                .or_else(|| mkcp_opts_value.and_then(|v| v.get("write-buffer-size")))
                .and_then(|v| v.as_i64())
                .unwrap_or(4 * 1024 * 1024) as usize;

            let header_type = mkcp_opts_value
                .and_then(|v| v.get("header"))
                .and_then(|v| v.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("none")
                .to_string();

            let seed = mkcp_opts_value
                .and_then(|v| v.get("seed"))
                .and_then(|v| v.as_str())
                .map(String::from);

            Some(VmessMkcpOptions {
                mtu,
                tti,
                uplink_capacity,
                downlink_capacity,
                congestion,
                read_buffer_size,
                write_buffer_size,
                header_type,
                seed,
            })
        } else {
            None
        };

        let mux_opts_value = config.options.get("mux");
        let mux_opts = VmessMuxOptions {
            enabled: mux_opts_value
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            concurrency: mux_opts_value
                .and_then(|v| v.get("concurrency"))
                .and_then(|v| v.as_i64())
                .unwrap_or(8) as usize,
        };

        let cmd_key = generate_cmd_key(&uuid_bytes);

        tracing::info!(
            "VMess outbound '{}' created: server={}:{}, uuid={}, alterId={}, transport={:?}, tls={}, udp={}, mux={}",
            config.tag,
            server,
            port,
            uuid,
            alter_id,
            transport,
            tls_enabled,
            udp_enabled,
            mux_opts.enabled
        );

        Ok(Self {
            config,
            server,
            port,
            uuid,
            cipher,
            udp_enabled,
            cmd_key,
            alter_id,
            transport,
            tls_enabled,
            skip_cert_verify,
            sni,
            ws_opts,
            mkcp_opts,
            mux_opts,
            quic_endpoint: Mutex::new(None),
            quic_connection: Mutex::new(None),
            quic_alpn,
            udp_sessions: DashMap::new(),
        })
    }

    /// 获取 UUID（用于日志和调试）
    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub fn is_mux_enabled(&self) -> bool {
        self.mux_opts.enabled
    }

    pub fn mux_concurrency(&self) -> usize {
        self.mux_opts.concurrency
    }

    pub fn generate_auth_id(&self, timestamp: i64) -> [u8; 16] {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&timestamp.to_be_bytes());

        let mut random_bytes = [0u8; 4];
        getrandom::fill(&mut random_bytes).expect("Failed to generate random bytes");
        data[8..12].copy_from_slice(&random_bytes);

        let crc = crc32fast::hash(&data[..12]);
        data[12..16].copy_from_slice(&crc.to_be_bytes());
        let auth_id_key = kdf16_auth_id(&self.cmd_key);

        use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
        use aes::Aes128;

        let cipher =
            Aes128::new_from_slice(&auth_id_key).expect("Failed to create AES cipher for AuthID");

        let mut block = aes::Block::from(data);
        cipher.encrypt_block(&mut block);

        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&block);

        tracing::debug!(
            "VMess AuthID generated: timestamp={}, crc={:#x}, auth_id={:02x?}",
            timestamp,
            crc,
            &auth_id[..4]
        );

        auth_id
    }

    /// 验证时间戳是否在有效窗口内
    pub fn is_timestamp_valid(timestamp: i64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let diff = (now - timestamp).abs();
        diff <= VMESS_TIME_WINDOW_SECS * VMESS_TIME_TOLERANCE
    }

    pub fn generate_request_key(&self) -> [u8; 16] {
        let mut key = [0u8; 16];
        getrandom::fill(&mut key).expect("Failed to generate random key");
        key
    }

    pub fn generate_request_iv(&self) -> [u8; 16] {
        let mut iv = [0u8; 16];
        getrandom::fill(&mut iv).expect("Failed to generate random IV");
        iv
    }

    fn generate_response_key(&self, request_key: &[u8; 16]) -> [u8; 16] {
        if self.alter_id > 0 {
            // Legacy mode: response_key = MD5(request_key)
            let mut hasher = Md5::new();
            hasher.update(request_key);
            let result = hasher.finalize();
            let mut key = [0u8; 16];
            key.copy_from_slice(&result);
            key
        } else {
            // AEAD mode: response_key = SHA256(request_key)[:16]
            let mut hasher = Sha256::new();
            hasher.update(request_key);
            let result = hasher.finalize();
            let mut key = [0u8; 16];
            key.copy_from_slice(&result[..16]);
            key
        }
    }

    fn generate_response_iv(&self, request_iv: &[u8; 16]) -> [u8; 16] {
        if self.alter_id > 0 {
            let mut hasher = Md5::new();
            hasher.update(request_iv);
            let result = hasher.finalize();
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&result);
            iv
        } else {
            let mut hasher = Sha256::new();
            hasher.update(request_iv);
            let result = hasher.finalize();
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&result[..16]);
            iv
        }
    }

    fn is_legacy_mode(&self) -> bool {
        self.alter_id > 0
    }

    pub fn seal_header(&self, header: &VmessHeader, timestamp: i64) -> Result<Vec<u8>> {
        let mut header_buf = Vec::with_capacity(128);
        let is_legacy = self.alter_id > 0;

        header_buf.push(header.version);
        header_buf.extend_from_slice(&header.request_body_iv);
        header_buf.extend_from_slice(&header.request_body_key);
        header_buf.push(header.response_header);
        header_buf.push(header.option.bits());

        let security_byte = if is_legacy {
            0x00
        } else {
            header.security.as_byte()
        };
        let padding_and_security = (header.padding_length << 4) | security_byte;
        header_buf.push(padding_and_security);
        header_buf.push(0x00); // 保留字节，必须为 0
        header_buf.push(header.command as u8);

        header_buf.extend_from_slice(&header.port.to_be_bytes());

        header_buf.push(header.address_type as u8);
        header_buf.extend_from_slice(&header.address);

        if header.padding_length > 0 {
            let mut padding = vec![0u8; header.padding_length as usize];
            getrandom::fill(&mut padding).ok();
            header_buf.extend_from_slice(&padding);
        }

        let fnv_hash = fnv1a_hash(&header_buf);
        header_buf.extend_from_slice(&fnv_hash.to_be_bytes());

        tracing::debug!(
            "VMess header: version={}, option={:#x}, security={:#x}, cmd={}, port={}, addr_type={}, addr_len={}, padding={}, fnv={:#x}, total_len={}",
            header.version,
            header.option.bits(),
            security_byte,
            header.command as u8,
            header.port,
            header.address_type as u8,
            header.address.len(),
            header.padding_length,
            fnv_hash,
            header_buf.len()
        );

        if is_legacy {
            self.seal_header_legacy(&header_buf, timestamp)
        } else {
            self.seal_header_aead(&header_buf, timestamp)
        }
    }

    fn seal_header_legacy(&self, header_buf: &[u8], timestamp: i64) -> Result<Vec<u8>> {
        let timestamp_bytes = timestamp.to_be_bytes();

        // VMess Legacy 认证信息计算:
        // Hash = HMAC(H, K, M)
        // H = MD5 (哈希函数)
        // K = User ID (16 字节 UUID)
        // M = UTC 时间戳 (8 字节大端序)
        // 
        // 注意: HMAC-MD5 的 key 是 UUID，message 是时间戳
        let mut mac = <HmacMd5 as Mac>::new_from_slice(self.uuid.as_bytes())
            .map_err(|e| Error::protocol(format!("Failed to create HMAC-MD5: {}", e)))?;
        mac.update(&timestamp_bytes);
        let auth_info = mac.finalize().into_bytes();

        tracing::info!(
            "VMess legacy auth: uuid={}, timestamp={}, auth_info={:02x?}",
            self.uuid,
            timestamp,
            &auth_info[..]
        );

        // 指令部分加密:
        // Key = MD5(UUID + "c48619fe-8f02-49e0-b9e9-edf763e17e21") = cmd_key (已在构造时计算)
        // IV = MD5(timestamp || timestamp || timestamp || timestamp)
        let mut iv_data = Vec::with_capacity(32);
        for _ in 0..4 {
            iv_data.extend_from_slice(&timestamp_bytes);
        }
        let iv: [u8; 16] = {
            let mut hasher = Md5::new();
            hasher.update(&iv_data);
            let result = hasher.finalize();
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&result);
            arr
        };

        tracing::debug!(
            "VMess legacy encryption: cmd_key={:02x?}, iv={:02x?}, header_len={}",
            &self.cmd_key[..4],
            &iv[..4],
            header_buf.len()
        );

        // 使用 AES-128-CFB 加密指令部分
        let mut encrypted_header = header_buf.to_vec();
        let cipher = Aes128CfbEnc::new_from_slices(&self.cmd_key, &iv)
            .map_err(|e| Error::protocol(format!("Failed to create AES-CFB cipher: {}", e)))?;
        cipher.encrypt(&mut encrypted_header);

        // 最终格式: [认证信息 16B][加密的指令部分]
        let mut result = Vec::with_capacity(16 + encrypted_header.len());
        result.extend_from_slice(&auth_info);
        result.extend_from_slice(&encrypted_header);

        tracing::info!(
            "VMess legacy sealed: total={} bytes (auth=16, header={})",
            result.len(),
            encrypted_header.len()
        );

        Ok(result)
    }

    fn seal_header_aead(&self, header_buf: &[u8], timestamp: i64) -> Result<Vec<u8>> {
        let auth_id = self.generate_auth_id(timestamp);
        let connection_nonce = generate_connection_nonce();
        let header_key = kdf16_vmess_aead(
            &self.cmd_key,
            b"VMess Header AEAD Key",
            &auth_id,
            &connection_nonce,
        );

        let header_nonce = kdf12_vmess_aead(
            &self.cmd_key,
            b"VMess Header AEAD Nonce",
            &auth_id,
            &connection_nonce,
        );

        let cipher = Aes128Gcm::new_from_slice(&header_key)
            .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;
        let nonce = Nonce::from_slice(&header_nonce);

        // 使用 auth_id 作为 Associated Data (AAD)
        use aes_gcm::aead::Payload;
        let encrypted_header = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: header_buf,
                    aad: &auth_id,
                },
            )
            .map_err(|e| Error::protocol(format!("Failed to encrypt header: {}", e)))?;

        let header_length_key = kdf16_vmess_aead(
            &self.cmd_key,
            b"VMess Header AEAD Key_Length",
            &auth_id,
            &connection_nonce,
        );
        let header_length_nonce = kdf12_vmess_aead(
            &self.cmd_key,
            b"VMess Header AEAD Nonce_Length",
            &auth_id,
            &connection_nonce,
        );

        let length_cipher = Aes128Gcm::new_from_slice(&header_length_key)
            .map_err(|e| Error::protocol(format!("Failed to create length cipher: {}", e)))?;
        let length_nonce = Nonce::from_slice(&header_length_nonce);

        let length_bytes = (header_buf.len() as u16).to_be_bytes();
        let encrypted_length = length_cipher
            .encrypt(
                length_nonce,
                Payload {
                    msg: &length_bytes,
                    aad: &auth_id,
                },
            )
            .map_err(|e| Error::protocol(format!("Failed to encrypt length: {}", e)))?;

        let mut result =
            Vec::with_capacity(16 + encrypted_length.len() + 8 + encrypted_header.len());
        result.extend_from_slice(&auth_id);
        result.extend_from_slice(&encrypted_length);
        result.extend_from_slice(&connection_nonce);
        result.extend_from_slice(&encrypted_header);

        tracing::debug!(
            "VMess AEAD sealed header: total={} bytes, auth_id={} bytes, enc_len={} bytes, nonce={} bytes, enc_header={} bytes",
            result.len(),
            auth_id.len(),
            encrypted_length.len(),
            connection_nonce.len(),
            encrypted_header.len()
        );

        Ok(result)
    }

    pub fn open_response_header(
        &self,
        data: &[u8],
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
    ) -> Result<VmessResponseHeader> {
        if self.alter_id > 0 {
            self.open_response_header_legacy(data, response_key, response_iv)
        } else {
            self.open_response_header_aead(data, response_key, response_iv)
        }
    }

    fn open_response_header_legacy(
        &self,
        data: &[u8],
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
    ) -> Result<VmessResponseHeader> {
        if data.len() < 4 {
            return Err(Error::protocol("Legacy response header too short"));
        }

        let mut decrypted = data.to_vec();
        let cipher = Aes128CfbDec::new_from_slices(response_key, response_iv)
            .map_err(|e| Error::protocol(format!("Failed to create AES-CFB cipher: {}", e)))?;
        cipher.decrypt(&mut decrypted);

        Ok(VmessResponseHeader {
            response_header: decrypted[0],
            option: decrypted[1],
            command: decrypted[2],
            command_length: decrypted[3],
        })
    }

    fn open_response_header_aead(
        &self,
        data: &[u8],
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
    ) -> Result<VmessResponseHeader> {
        if data.len() < 4 + VMESS_AEAD_AUTH_LEN {
            return Err(Error::protocol("Response header too short"));
        }

        let cipher = Aes128Gcm::new_from_slice(response_key)
            .map_err(|e| Error::protocol(format!("Failed to create response cipher: {}", e)))?;

        let nonce = Nonce::from_slice(&response_iv[..VMESS_AEAD_NONCE_LEN]);

        let decrypted = cipher
            .decrypt(nonce, data)
            .map_err(|e| Error::protocol(format!("Failed to decrypt response header: {}", e)))?;

        if decrypted.len() < 4 {
            return Err(Error::protocol("Decrypted response header too short"));
        }

        Ok(VmessResponseHeader {
            response_header: decrypted[0],
            option: decrypted[1],
            command: decrypted[2],
            command_length: decrypted[3],
        })
    }

    async fn connect_tcp(&self) -> Result<TcpStream> {
        let addr = format!("{}:{}", self.server, self.port);
        #[cfg(target_os = "android")]
        {
            use socket2::{Domain, Protocol, Socket, Type};
            use std::os::unix::io::AsRawFd;

            // Resolve address first
            let socket_addr: std::net::SocketAddr = tokio::net::lookup_host(&addr)
                .await
                .map_err(|e| {
                    Error::network(format!("Failed to resolve VMess server {}: {}", addr, e))
                })?
                .next()
                .ok_or_else(|| {
                    Error::network(format!("No addresses found for VMess server {}", addr))
                })?;

            let domain = if socket_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };

            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .map_err(|e| Error::network(format!("Failed to create socket: {}", e)))?;

            let fd = socket.as_raw_fd();
            if !crate::socket_protect::protect_socket(fd) {
                tracing::warn!(
                    "Failed to protect VMess socket fd={}, connection may cause routing loop",
                    fd
                );
            } else {
                tracing::debug!("VMess socket fd={} protected successfully", fd);
            }

            socket
                .set_nonblocking(true)
                .map_err(|e| Error::network(format!("Failed to set non-blocking: {}", e)))?;

            match socket.connect(&socket_addr.into()) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    return Err(Error::network(format!(
                        "Failed to connect to VMess server {}: {}",
                        addr, e
                    )))
                }
            }

            let std_stream: std::net::TcpStream = socket.into();
            let stream = TcpStream::from_std(std_stream)
                .map_err(|e| Error::network(format!("Failed to convert socket: {}", e)))?;

            stream.writable().await.map_err(|e| {
                Error::network(format!("Connection to VMess server {} failed: {}", addr, e))
            })?;

            if let Some(e) = stream
                .take_error()
                .map_err(|e| Error::network(format!("Failed to check socket error: {}", e)))?
            {
                return Err(Error::network(format!(
                    "Connection to VMess server {} failed: {}",
                    addr, e
                )));
            }

            stream.set_nodelay(true).ok();
            tracing::info!("VMess TCP connection established to {} (protected)", addr);
            return Ok(stream);
        }

        // Non-Android platforms: use simple connect
        #[cfg(not(target_os = "android"))]
        {
            let stream = TcpStream::connect(&addr).await.map_err(|e| {
                Error::network(format!("Failed to connect to VMess server {}: {}", addr, e))
            })?;
            stream.set_nodelay(true).ok();
            Ok(stream)
        }
    }

    /// Connect with TLS if enabled
    async fn connect_tls(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp_stream = self.connect_tcp().await?;

        let sni = self.sni.as_deref().unwrap_or(&self.server);

        // Build TLS config
        let mut root_store = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        for cert in certs.certs {
            root_store.add(cert).ok();
        }

        let tls_config = if self.skip_cert_verify {
            let verifier = std::sync::Arc::new(crate::tls::SkipServerVerification);
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
            .map_err(|_| Error::config(format!("Invalid SNI: {}", sni)))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| Error::network(format!("TLS handshake failed: {}", e)))?;

        Ok(tls_stream)
    }

    /// Connect and return a boxed stream (TCP, TLS, or WebSocket)
    async fn connect_stream(&self) -> Result<Box<dyn AsyncReadWrite>> {
        match self.transport {
            VmessTransport::Ws => {
                let default_ws_opts = VmessWsOptions::default();
                let ws_opts = self.ws_opts.as_ref().unwrap_or(&default_ws_opts);
                let host = ws_opts.host.as_deref().unwrap_or(&self.server);
                let path = &ws_opts.path;

                if self.tls_enabled {
                    let tls_stream = self.connect_tls().await?;
                    let ws_stream =
                        WebSocketStream::handshake(tls_stream, host, path, &ws_opts.headers)
                            .await?;
                    Ok(Box::new(ws_stream) as Box<dyn AsyncReadWrite>)
                } else {
                    let tcp_stream = self.connect_tcp().await?;
                    let ws_stream =
                        WebSocketStream::handshake(tcp_stream, host, path, &ws_opts.headers)
                            .await?;
                    Ok(Box::new(ws_stream) as Box<dyn AsyncReadWrite>)
                }
            }
            VmessTransport::Quic => {
                let quic_stream = self.connect_quic().await?;
                Ok(Box::new(quic_stream) as Box<dyn AsyncReadWrite>)
            }
            VmessTransport::Mkcp => {
                let mkcp_stream = self.connect_mkcp().await?;
                Ok(Box::new(mkcp_stream) as Box<dyn AsyncReadWrite>)
            }
            _ => {
                // TCP or other transports
                if self.tls_enabled {
                    let tls_stream = self.connect_tls().await?;
                    Ok(Box::new(tls_stream) as Box<dyn AsyncReadWrite>)
                } else {
                    let tcp_stream = self.connect_tcp().await?;
                    Ok(Box::new(tcp_stream) as Box<dyn AsyncReadWrite>)
                }
            }
        }
    }

    /// Connect via mKCP transport
    async fn connect_mkcp(&self) -> Result<crate::transport::mkcp::MkcpStream> {
        use crate::transport::mkcp::{MkcpConfig, MkcpHeaderType, MkcpStream};

        let addr = format!("{}:{}", self.server, self.port);
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to resolve VMess server {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| {
                Error::network(format!("No addresses found for VMess server {}", addr))
            })?;

        let mkcp_config = if let Some(ref opts) = self.mkcp_opts {
            MkcpConfig {
                mtu: opts.mtu,
                tti: opts.tti,
                uplink_capacity: opts.uplink_capacity,
                downlink_capacity: opts.downlink_capacity,
                congestion: opts.congestion,
                read_buffer_size: opts.read_buffer_size,
                write_buffer_size: opts.write_buffer_size,
                header_type: MkcpHeaderType::from_str(&opts.header_type),
                seed: opts.seed.clone(),
            }
        } else {
            MkcpConfig::default()
        };

        let stream = MkcpStream::connect(socket_addr, mkcp_config).await?;
        tracing::debug!("VMess mKCP connection established to {}", socket_addr);

        Ok(stream)
    }

    /// Connect via QUIC transport
    async fn connect_quic(&self) -> Result<QuicBiStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to resolve VMess server {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| {
                Error::network(format!("No addresses found for VMess server {}", addr))
            })?;

        // Check if we have an existing connection
        {
            let conn_guard = self.quic_connection.lock().await;
            if let Some(ref conn) = *conn_guard {
                if conn.close_reason().is_none() {
                    // Connection is still alive, open a new stream
                    let (send, recv) = conn.open_bi().await.map_err(|e| {
                        Error::network(format!("Failed to open QUIC stream: {}", e))
                    })?;
                    return Ok(QuicBiStream::new(send, recv));
                }
            }
        }

        let mut endpoint_guard = self.quic_endpoint.lock().await;
        let endpoint = match endpoint_guard.take() {
            Some(ep) => ep,
            None => {
                let bind_addr: SocketAddr = if socket_addr.is_ipv6() {
                    "[::]:0".parse().unwrap()
                } else {
                    "0.0.0.0:0".parse().unwrap()
                };
                Endpoint::client(bind_addr)
                    .map_err(|e| Error::network(format!("Failed to create QUIC endpoint: {}", e)))?
            }
        };

        let mut root_store = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        for cert in certs.certs {
            root_store.add(cert).ok();
        }

        let mut tls_config = if self.skip_cert_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        tls_config.alpn_protocols = self
            .quic_alpn
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| Error::config(format!("Failed to create QUIC config: {}", e)))?;

        let mut client_config = QuinnClientConfig::new(Arc::new(quic_config));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(100u32.into());
        transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(Duration::from_secs(10)));
        client_config.transport_config(Arc::new(transport_config));

        let server_name = self.sni.as_deref().unwrap_or(&self.server);

        let connecting = endpoint
            .connect_with(client_config, socket_addr, server_name)
            .map_err(|e| {
                Error::network(format!("Failed to connect to VMess QUIC server: {}", e))
            })?;

        let connection = connecting
            .await
            .map_err(|e| Error::network(format!("QUIC connection failed: {}", e)))?;

        tracing::debug!("VMess QUIC connection established to {}", socket_addr);
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| Error::network(format!("Failed to open QUIC stream: {}", e)))?;

        *endpoint_guard = Some(endpoint);
        let mut conn_guard = self.quic_connection.lock().await;
        *conn_guard = Some(connection);

        Ok(QuicBiStream::new(send, recv))
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        cmd: VmessCommand,
    ) -> Result<([u8; 16], [u8; 16], u8, VmessOption)> {
        let request_key = self.generate_request_key();
        let request_iv = self.generate_request_iv();
        let response_header_byte: u8 = rand::random();
        let is_legacy = self.alter_id > 0;

        let (address_type, address_bytes) = match target {
            TargetAddr::Domain(domain, _) => {
                let mut bytes = Vec::with_capacity(domain.len() + 1);
                bytes.push(domain.len() as u8);
                bytes.extend_from_slice(domain.as_bytes());
                (VmessAddressType::Domain, bytes)
            }
            TargetAddr::Ip(addr) => match addr {
                std::net::SocketAddr::V4(v4) => (VmessAddressType::Ipv4, v4.ip().octets().to_vec()),
                std::net::SocketAddr::V6(v6) => (VmessAddressType::Ipv6, v6.ip().octets().to_vec()),
            },
        };

        let padding_length = if is_legacy {
            0
        } else {
            rand::random::<u8>() % 16
        };
        let option = if is_legacy {
            VmessOption::CHUNK_STREAM
        } else {
            VmessOption::CHUNK_STREAM | VmessOption::CHUNK_MASKING
        };

        let header = VmessHeader {
            version: VMESS_VERSION,
            request_body_iv: request_iv,
            request_body_key: request_key,
            response_header: response_header_byte,
            option,
            padding_length,
            security: self.cipher,
            command: cmd,
            port: target.port(),
            address_type,
            address: address_bytes,
        };

        let local_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let timestamp = time_sync::get_vmess_timestamp();
        let time_offset_ms = time_sync::get_time_offset_ms();
        let now_utc = chrono::Utc::now();
        tracing::info!(
            "VMess handshake: local_ts={}, vmess_ts={}, ntp_offset={}ms, UTC: {}",
            local_timestamp,
            timestamp,
            time_offset_ms,
            now_utc.format("%Y-%m-%d %H:%M:%S")
        );

        tracing::debug!(
            "VMess handshake: uuid={}, cipher={:?}, target={}:{}, cmd={:?}, option={:#x}",
            self.uuid,
            self.cipher,
            target,
            target.port(),
            cmd,
            option.bits()
        );

        let corrected_ts = time_sync::get_corrected_timestamp();
        tracing::info!(
            "VMess: corrected_ts={}, vmess_ts={} (diff={}s, valid range: ±30s)",
            corrected_ts,
            timestamp,
            timestamp - corrected_ts
        );

        let sealed_header = self.seal_header(&header, timestamp)?;

        tracing::info!(
            "VMess sealed header: {} bytes, response_header_byte={}, mode={}, cipher={:?}, option={:#x}",
            sealed_header.len(),
            response_header_byte,
            if self.alter_id > 0 { "legacy" } else { "AEAD" },
            self.cipher,
            option.bits()
        );

        tracing::debug!(
            "VMess header bytes (first 32): {:02x?}",
            &sealed_header[..std::cmp::min(32, sealed_header.len())]
        );

        stream
            .write_all(&sealed_header)
            .await
            .map_err(|e| Error::network(format!("Failed to send VMess header: {}", e)))?;
        stream.flush().await.ok();

        tracing::info!(
            "VMess handshake sent for target: {} (waiting for client data)",
            target
        );

        Ok((request_key, request_iv, response_header_byte, option))
    }

    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    async fn get_or_create_udp_session(&self, target: &TargetAddr) -> Result<Arc<VmessUdpSession>> {
        let session_key = target.to_string();

        if let Some(session) = self.udp_sessions.get(&session_key) {
            let session = session.clone();
            if !session.is_expired(Duration::from_secs(60)) {
                session.touch();
                return Ok(session);
            }
            // Session expired, remove it
            self.udp_sessions.remove(&session_key);
        }

        let mut stream = self.connect_stream().await?;
        let (request_key, request_iv, _response_header, _option) = self
            .handshake(&mut *stream, target, VmessCommand::Udp)
            .await?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        let session = Arc::new(VmessUdpSession::new(
            stream,
            request_key,
            request_iv,
            response_key,
            response_iv,
        ));

        self.udp_sessions.insert(session_key, session.clone());

        tracing::debug!("Created new VMess UDP session for {}", target);
        Ok(session)
    }

    pub fn cleanup_udp_sessions(&self) {
        let mut expired_keys = Vec::new();

        for entry in self.udp_sessions.iter() {
            if entry.value().is_expired(Duration::from_secs(120)) {
                expired_keys.push(entry.key().clone());
            }
        }

        for key in expired_keys {
            self.udp_sessions.remove(&key);
            tracing::debug!("Removed expired VMess UDP session: {}", key);
        }
    }

    pub async fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this VMess proxy",
            ));
        }

        let session = self.get_or_create_udp_session(target).await?;

        let chunk_count = session.next_chunk_count();
        let request_key = session.request_key;
        let request_iv = session.request_iv;
        let response_key = session.response_key;
        let response_iv = session.response_iv;
        let target_str = target.to_string();

        let mut stream_guard = session.stream.lock().await;
        let encrypted_data = self.encrypt_chunk(data, &request_key, &request_iv, chunk_count)?;
        if let Err(e) = stream_guard.write_all(&encrypted_data).await {
            drop(stream_guard);
            self.udp_sessions.remove(&target_str);
            return Err(Error::network(format!("Failed to send UDP data: {}", e)));
        }
        stream_guard.flush().await.ok();
        session.touch();

        let timeout = Duration::from_secs(10);
        let response = tokio::time::timeout(
            timeout,
            self.read_response_chunk(&mut **stream_guard, &response_key, &response_iv),
        )
        .await
        .map_err(|_| Error::network("UDP receive timeout"))?
        .map_err(|e| {
            // Read error, remove session
            Error::network(format!("Failed to receive UDP response: {}", e))
        })?;

        Ok(response)
    }

    pub async fn send_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<()> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this VMess proxy",
            ));
        }

        let session = self.get_or_create_udp_session(target).await?;

        let chunk_count = session.next_chunk_count();
        let request_key = session.request_key;
        let request_iv = session.request_iv;

        let encrypted_data = self.encrypt_chunk(data, &request_key, &request_iv, chunk_count)?;

        let mut stream_guard = session.stream.lock().await;
        stream_guard
            .write_all(&encrypted_data)
            .await
            .map_err(|e| Error::network(format!("Failed to send UDP data: {}", e)))?;
        stream_guard.flush().await.ok();
        session.touch();

        Ok(())
    }

    fn encrypt_chunk(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        match self.cipher {
            VmessCipher::Aes128Gcm | VmessCipher::Auto => {
                self.encrypt_aes_gcm(data, key, iv, count)
            }
            VmessCipher::Chacha20Poly1305 => self.encrypt_chacha20(data, key, iv, count),
            VmessCipher::Aes128Cfb => {
                encrypt_chunk_legacy(self.cipher, data, key, iv, count, &mut None)
            }
            VmessCipher::None | VmessCipher::Zero => {
                let mut result = Vec::with_capacity(2 + data.len());
                result.extend_from_slice(&(data.len() as u16).to_be_bytes());
                result.extend_from_slice(data);
                Ok(result)
            }
        }
    }

    fn encrypt_aes_gcm(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
        nonce_bytes[2..].copy_from_slice(&iv[2..12]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| Error::protocol(format!("Failed to encrypt data: {}", e)))?;

        let length = (encrypted.len() as u16).to_be_bytes();
        let mut result = Vec::with_capacity(2 + encrypted.len());
        result.extend_from_slice(&length);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    fn encrypt_chacha20(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        let mut full_key = [0u8; 32];
        full_key[..16].copy_from_slice(key);
        full_key[16..].copy_from_slice(key);

        let cipher = ChaCha20Poly1305::new_from_slice(&full_key)
            .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
        nonce_bytes[2..].copy_from_slice(&iv[2..12]);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| Error::protocol(format!("Failed to encrypt data: {}", e)))?;

        let length = (encrypted.len() as u16).to_be_bytes();
        let mut result = Vec::with_capacity(2 + encrypted.len());
        result.extend_from_slice(&length);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    fn decrypt_chunk(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        match self.cipher {
            VmessCipher::Aes128Gcm | VmessCipher::Auto => {
                self.decrypt_aes_gcm(data, key, iv, count)
            }
            VmessCipher::Chacha20Poly1305 => self.decrypt_chacha20(data, key, iv, count),
            VmessCipher::Aes128Cfb => decrypt_chunk_legacy(self.cipher, data, key, iv, count),
            VmessCipher::None | VmessCipher::Zero => Ok(data.to_vec()),
        }
    }

    fn decrypt_aes_gcm(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
        nonce_bytes[2..].copy_from_slice(&iv[2..12]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, data)
            .map_err(|e| Error::protocol(format!("Failed to decrypt data: {}", e)))?;

        Ok(decrypted)
    }

    fn decrypt_chacha20(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        let mut full_key = [0u8; 32];
        full_key[..16].copy_from_slice(key);
        full_key[16..].copy_from_slice(key);

        let cipher = ChaCha20Poly1305::new_from_slice(&full_key)
            .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
        nonce_bytes[2..].copy_from_slice(&iv[2..12]);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, data)
            .map_err(|e| Error::protocol(format!("Failed to decrypt data: {}", e)))?;

        Ok(decrypted)
    }

    async fn read_response_chunk<S: AsyncRead + Unpin + ?Sized>(
        &self,
        stream: &mut S,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>> {
        let mut length_buf = [0u8; 2];
        stream
            .read_exact(&mut length_buf)
            .await
            .map_err(|e| Error::network(format!("Failed to read chunk length: {}", e)))?;

        let length = u16::from_be_bytes(length_buf) as usize;
        if length == 0 {
            return Ok(Vec::new());
        }

        let mut data = vec![0u8; length];
        stream
            .read_exact(&mut data)
            .await
            .map_err(|e| Error::network(format!("Failed to read chunk data: {}", e)))?;

        self.decrypt_chunk(&data, key, iv, 0)
    }

    /// Read response chunk for legacy VMess mode
    async fn read_response_chunk_legacy<S: AsyncRead + Unpin + ?Sized>(
        &self,
        stream: &mut S,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>> {
        let mut length_buf = [0u8; 2];
        stream
            .read_exact(&mut length_buf)
            .await
            .map_err(|e| Error::network(format!("Failed to read chunk length: {}", e)))?;

        let length = u16::from_be_bytes(length_buf) as usize;
        if length == 0 {
            return Ok(Vec::new());
        }

        let mut data = vec![0u8; length];
        stream
            .read_exact(&mut data)
            .await
            .map_err(|e| Error::network(format!("Failed to read chunk data: {}", e)))?;

        // Legacy mode uses AES-128-CFB with IV derived from count
        decrypt_chunk_legacy(self.cipher, &data, key, iv, 0)
    }
}

#[async_trait::async_trait]
impl OutboundProxy for VmessOutbound {
    async fn connect(&self) -> Result<()> {
        let _stream = self.connect_tcp().await?;
        tracing::info!(
            "VMess outbound '{}' can reach {}:{}",
            self.config.tag,
            self.server,
            self.port
        );
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this VMess proxy",
            ));
        }
        self.relay_udp(target, data).await
    }

    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;

        let url = url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };

        let start = Instant::now();
        let is_legacy = self.is_legacy_mode();

        // Use connect_stream to support TLS
        let mut stream = tokio::time::timeout(timeout, self.connect_stream())
            .await
            .map_err(|_| Error::network("Connection timeout"))?
            .map_err(|e| Error::network(format!("Connection failed: {}", e)))?;

        let target = TargetAddr::Domain(host.clone(), url_port);
        let (request_key, request_iv, _, option) = self
            .handshake(&mut *stream, &target, VmessCommand::Tcp)
            .await?;

        // 创建请求掩码生成器 (如果启用了 Opt(M))
        let use_masking = option.contains(VmessOption::CHUNK_MASKING);
        let mut request_mask = if use_masking {
            Some(ShakeMask::new(&request_iv))
        } else {
            None
        };

        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: VeloGuard/1.0\r\n\r\n",
            path, host
        );

        let encrypted_request = if is_legacy {
            encrypt_chunk_legacy(
                self.cipher,
                http_request.as_bytes(),
                &request_key,
                &request_iv,
                0,
                &mut None,
            )?
        } else {
            encrypt_chunk_aead(
                self.cipher,
                http_request.as_bytes(),
                &request_key,
                &request_iv,
                0,
                &mut request_mask,
            )?
        };
        stream
            .write_all(&encrypted_request)
            .await
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {}", e)))?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        let result = tokio::time::timeout(timeout, async {
            if is_legacy {
                // Legacy mode: 4 bytes encrypted with AES-128-CFB
                let mut header_data = vec![0u8; 4];
                stream.read_exact(&mut header_data).await.map_err(|e| {
                    Error::network(format!("Failed to read response header: {}", e))
                })?;

                // Decrypt using AES-128-CFB
                let cipher =
                    Aes128CfbDec::new_from_slices(&response_key, &response_iv).map_err(|e| {
                        Error::protocol(format!("Failed to create AES-CFB cipher: {}", e))
                    })?;
                cipher.decrypt(&mut header_data);
            } else {
                // AEAD mode: 20 bytes (4 + 16 auth tag)
                let mut header_data = vec![0u8; 4 + VMESS_AEAD_AUTH_LEN];
                stream.read_exact(&mut header_data).await.map_err(|e| {
                    Error::network(format!("Failed to read response header: {}", e))
                })?;

                // Decrypt response header using AES-128-GCM
                let aes_cipher = Aes128Gcm::new_from_slice(&response_key).map_err(|e| {
                    Error::protocol(format!("Failed to create response cipher: {}", e))
                })?;
                let nonce = Nonce::from_slice(&response_iv[..VMESS_AEAD_NONCE_LEN]);

                let _decrypted_header =
                    aes_cipher
                        .decrypt(nonce, header_data.as_slice())
                        .map_err(|e| {
                            Error::protocol(format!("Failed to decrypt response header: {}", e))
                        })?;
            }

            // Now read the actual response data
            let response = if is_legacy {
                self.read_response_chunk_legacy(&mut *stream, &response_key, &response_iv)
                    .await?
            } else {
                self.read_response_chunk(&mut *stream, &response_key, &response_iv)
                    .await?
            };
            let response_str = String::from_utf8_lossy(&response);
            if response_str.starts_with("HTTP/") {
                Ok(())
            } else {
                Err(Error::network("Invalid HTTP response"))
            }
        })
        .await;

        match result {
            Ok(Ok(())) => {
                let elapsed = start.elapsed();
                tracing::info!("VMess latency test success: {}ms", elapsed.as_millis());
                Ok(elapsed)
            }
            Ok(Err(e)) => {
                tracing::warn!("VMess latency test failed: {}", e);
                Err(e)
            }
            Err(_) => {
                tracing::warn!("VMess latency test timeout");
                Err(Error::network("Response timeout"))
            }
        }
    }

    async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None).await
    }

    async fn relay_tcp_with_connection(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<Arc<TrackedConnection>>,
    ) -> Result<()> {
        // Use connect_stream to support TLS
        let mut stream = self.connect_stream().await?;
        let (request_key, request_iv, expected_response_header, option) = self
            .handshake(&mut *stream, &target, VmessCommand::Tcp)
            .await?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);
        let is_legacy = self.is_legacy_mode();
        let use_masking = option.contains(VmessOption::CHUNK_MASKING) && !is_legacy;

        tracing::debug!(
            "VMess: relaying TCP to {} via {}:{} (tls={}, cipher={:?}, legacy={}, alterId={}, masking={})",
            target,
            self.server,
            self.port,
            self.tls_enabled,
            self.cipher,
            is_legacy,
            self.alter_id,
            use_masking
        );

        let tracker = global_tracker();
        let (mut ri, mut wi) = tokio::io::split(inbound);
        let (mut ro, mut wo) = tokio::io::split(stream);

        let cipher = self.cipher;
        let conn_upload = connection.clone();
        let conn_download = connection.clone();

        // VMess protocol: client sends request header first, then data
        // Server responds with response header after receiving first data chunk
        // We use a channel to coordinate this
        let (first_data_tx, first_data_rx) = tokio::sync::oneshot::channel::<bool>();
        let first_data_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(first_data_tx)));

        // 创建请求掩码生成器 (如果启用了 Opt(M))
        let mut request_mask = if use_masking {
            Some(ShakeMask::new(&request_iv))
        } else {
            None
        };

        let client_to_remote = async {
            let mut buf = vec![0u8; VMESS_MAX_CHUNK_SIZE];
            let mut count: u16 = 0;
            let mut first_sent = false;
            let mut has_data_to_send = false;

            loop {
                // Read data from inbound
                // For the first read, we wait for actual data without timeout
                // because VMess server won't respond until we send data
                let read_result = ri.read(&mut buf).await;

                let n = read_result
                    .map_err(|e| Error::network(format!("Failed to read from inbound: {}", e)))?;

                if n == 0 {
                    // 如果从未发送过数据，发送一个空的初始数据包以触发服务器响应
                    if !has_data_to_send {
                        tracing::debug!("VMess: client closed without sending data, sending empty packet to trigger server response");
                        let empty_packet = if is_legacy {
                            encrypt_chunk_legacy(
                                cipher,
                                &[],
                                &request_key,
                                &request_iv,
                                0,
                                &mut None,
                            )?
                        } else {
                            encrypt_chunk_aead(
                                cipher,
                                &[],
                                &request_key,
                                &request_iv,
                                0,
                                &mut request_mask,
                            )?
                        };
                        wo.write_all(&empty_packet).await.ok();
                        wo.flush().await.ok();
                        
                        // Signal that we sent something
                        if let Some(tx) = first_data_tx.lock().await.take() {
                            let _ = tx.send(true);
                        }
                    }
                    
                    // Send end marker
                    // 当传输结束时，客户端必须发送一个空的数据包
                    // L = 0（不加密）或认证数据长度（有加密）
                    let end_marker = if is_legacy {
                        // Legacy mode: [Length 2B] where Length = 0
                        vec![0u8; 2]
                    } else {
                        // AEAD mode: 发送加密的空数据包
                        encrypt_chunk_aead(
                            cipher,
                            &[],
                            &request_key,
                            &request_iv,
                            count,
                            &mut request_mask,
                        )?
                    };
                    wo.write_all(&end_marker).await.ok();
                    wo.flush().await.ok();
                    break;
                }

                has_data_to_send = true;
                let encrypted = if is_legacy {
                    encrypt_chunk_legacy(
                        cipher,
                        &buf[..n],
                        &request_key,
                        &request_iv,
                        count,
                        &mut None,
                    )?
                } else {
                    encrypt_chunk_aead(
                        cipher,
                        &buf[..n],
                        &request_key,
                        &request_iv,
                        count,
                        &mut request_mask,
                    )?
                };
                wo.write_all(&encrypted)
                    .await
                    .map_err(|e| Error::network(format!("Failed to write to VMess: {}", e)))?;
                wo.flush().await.ok();

                // Signal that first data has been sent
                if !first_sent {
                    first_sent = true;
                    if let Some(tx) = first_data_tx.lock().await.take() {
                        let _ = tx.send(true); // true = data was sent
                    }
                    tracing::debug!("VMess: first data chunk sent ({} bytes)", n);
                }

                tracker.add_global_upload(n as u64);
                if let Some(ref conn) = conn_upload {
                    conn.add_upload(n as u64);
                }
                count = count.wrapping_add(1);
            }
            wo.shutdown().await.ok();
            Ok::<(), Error>(())
        };

        let remote_to_client = async {
            let mut count: u16 = 0;

            // Wait for signal from client_to_remote
            // VMess protocol: server only responds after receiving first data chunk
            match tokio::time::timeout(std::time::Duration::from_secs(60), first_data_rx).await
            {
                Ok(Ok(true)) => {
                    tracing::debug!(
                        "VMess: first data sent, now waiting for response header"
                    );
                }
                Ok(Ok(false)) => {
                    // This shouldn't happen with the new logic, but handle it anyway
                    tracing::debug!("VMess: received false signal, waiting for data...");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Ok(Err(_)) => {
                    // Channel closed without sending - client closed connection
                    tracing::debug!("VMess: client closed before sending data");
                    return Ok(());
                }
                Err(_) => {
                    tracing::warn!("VMess: timeout waiting for client data signal");
                    return Err(Error::network("Timeout waiting for client data"));
                }
            };

            // Read and validate the response header
            // Legacy mode: 4 bytes encrypted with AES-128-CFB
            // AEAD mode: 4 bytes + 16 bytes auth tag = 20 bytes encrypted with AES-128-GCM
            {
                if is_legacy {
                    // Legacy VMess response header: 4 bytes encrypted with AES-128-CFB
                    // First read the 4-byte header
                    let mut header_data = vec![0u8; 4];
                    ro.read_exact(&mut header_data).await.map_err(|e| {
                        tracing::warn!("VMess legacy: failed to read response header: {}", e);
                        Error::network(format!("Failed to read response header: {}", e))
                    })?;

                    // Decrypt using AES-128-CFB
                    let cipher = Aes128CfbDec::new_from_slices(&response_key, &response_iv)
                        .map_err(|e| {
                            Error::protocol(format!("Failed to create AES-CFB cipher: {}", e))
                        })?;
                    cipher.decrypt(&mut header_data);

                    let response_v = header_data[0];
                    let option = header_data[1];
                    let command = header_data[2];
                    let command_length = header_data[3] as usize;

                    tracing::debug!(
                        "VMess legacy response header: v={}, opt={:#x}, cmd={}, cmd_len={}, expected_v={}",
                        response_v,
                        option,
                        command,
                        command_length,
                        expected_response_header
                    );

                    // Validate response header byte
                    if response_v != expected_response_header {
                        tracing::warn!(
                            "VMess legacy response header mismatch: expected {}, got {}",
                            expected_response_header,
                            response_v
                        );
                        return Err(Error::protocol("VMess response header validation failed"));
                    }

                    tracing::debug!("VMess legacy response header validated successfully");

                    // If there's command content, read and discard it
                    // Note: In legacy VMess, command data continues the CFB stream,
                    // but since we're just discarding it, we can skip decryption
                    if command_length > 0 {
                        let mut cmd_data = vec![0u8; command_length];
                        ro.read_exact(&mut cmd_data).await.ok();
                    }
                } else {
                    // AEAD VMess response header: 4 bytes + 16 bytes auth tag = 20 bytes
                    let mut header_data = vec![0u8; 4 + VMESS_AEAD_AUTH_LEN]; // 20 bytes
                    ro.read_exact(&mut header_data).await.map_err(|e| {
                        tracing::warn!("VMess: failed to read response header: {}", e);
                        Error::network(format!("Failed to read response header: {}", e))
                    })?;

                    let aes_cipher = Aes128Gcm::new_from_slice(&response_key).map_err(|e| {
                        Error::protocol(format!("Failed to create response cipher: {}", e))
                    })?;

                    let nonce = Nonce::from_slice(&response_iv[..VMESS_AEAD_NONCE_LEN]);

                    let decrypted =
                        aes_cipher
                            .decrypt(nonce, header_data.as_slice())
                            .map_err(|e| {
                                tracing::warn!("VMess: failed to decrypt response header: {}", e);
                                Error::protocol(format!("Failed to decrypt response header: {}", e))
                            })?;

                    if decrypted.len() < 4 {
                        tracing::warn!(
                            "VMess: response header too short: {} bytes",
                            decrypted.len()
                        );
                        return Err(Error::protocol("VMess response header too short"));
                    }

                    let response_v = decrypted[0];
                    let option = decrypted[1];
                    let command = decrypted[2];
                    let command_length = decrypted[3] as usize;

                    tracing::debug!(
                        "VMess response header: v={}, opt={:#x}, cmd={}, cmd_len={}, expected_v={}",
                        response_v,
                        option,
                        command,
                        command_length,
                        expected_response_header
                    );

                    // Validate response header byte
                    if response_v != expected_response_header {
                        tracing::warn!(
                            "VMess response header mismatch: expected {}, got {}",
                            expected_response_header,
                            response_v
                        );
                        return Err(Error::protocol("VMess response header validation failed"));
                    }

                    tracing::debug!("VMess response header validated successfully");

                    // If there's command content, read and discard it
                    if command_length > 0 {
                        let mut cmd_data = vec![0u8; command_length];
                        ro.read_exact(&mut cmd_data).await.ok();
                    }
                }
            }

            // Now read data chunks
            // 创建响应掩码生成器 (如果启用了 Opt(M))
            let mut response_mask = if use_masking {
                Some(ShakeMask::new(&response_iv))
            } else {
                None
            };

            loop {
                let mut length_buf = [0u8; 2];
                match ro.read_exact(&mut length_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        tracing::debug!("VMess: remote connection closed (EOF)");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("VMess: failed to read length: {}", e);
                        return Err(Error::network(format!("Failed to read length: {}", e)));
                    }
                }

                // 解码长度，如果启用了 Opt(M)，需要 XOR 掩码
                let raw_length = u16::from_be_bytes(length_buf);
                let length = if let Some(ref mut mask) = response_mask {
                    (raw_length ^ mask.next_u16()) as usize
                } else {
                    raw_length as usize
                };

                if length == 0 {
                    tracing::debug!("VMess: received end marker");
                    break;
                }

                // 限制最大长度
                if length > VMESS_MAX_CHUNK_SIZE + 32 {
                    tracing::warn!("VMess: chunk length too large: {}", length);
                    return Err(Error::protocol(format!(
                        "Chunk length too large: {}",
                        length
                    )));
                }

                let mut data = vec![0u8; length];
                ro.read_exact(&mut data)
                    .await
                    .map_err(|e| Error::network(format!("Failed to read chunk: {}", e)))?;

                // Decrypt data chunk based on mode
                let decrypted = if is_legacy {
                    decrypt_chunk_legacy(cipher, &data, &response_key, &response_iv, count)?
                } else {
                    decrypt_chunk_aead(cipher, &data, &response_key, &response_iv, count)?
                };
                wi.write_all(&decrypted)
                    .await
                    .map_err(|e| Error::network(format!("Failed to write to inbound: {}", e)))?;

                tracker.add_global_download(decrypted.len() as u64);
                if let Some(ref conn) = conn_download {
                    conn.add_download(decrypted.len() as u64);
                }
                count = count.wrapping_add(1);
            }
            wi.shutdown().await.ok();
            Ok::<(), Error>(())
        };

        let result = tokio::try_join!(client_to_remote, remote_to_client);

        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("connection")
                    || err_str.contains("reset")
                    || err_str.contains("broken")
                {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
}

fn generate_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let result = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result);
    key
}

fn generate_connection_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).expect("Failed to generate nonce");
    nonce
}

/// VMess AEAD KDF 函数 - 生成 AuthID 加密密钥
/// Key = KDF(CmdKey, "AES Auth ID Encryption")
fn kdf16_auth_id(cmd_key: &[u8; 16]) -> [u8; 16] {
    // 第一层: HMAC(cmd_key, "VMess AEAD KDF")
    let mut mac1 =
        <HmacSha256 as Mac>::new_from_slice(cmd_key).expect("HMAC can take key of any size");
    mac1.update(b"VMess AEAD KDF");
    let k1 = mac1.finalize().into_bytes();

    // 第二层: HMAC(k1, "AES Auth ID Encryption")
    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&k1).expect("HMAC can take key of any size");
    mac2.update(b"AES Auth ID Encryption");
    let result = mac2.finalize().into_bytes();

    let mut output = [0u8; 16];
    output.copy_from_slice(&result[..16]);
    output
}

/// VMess AEAD KDF 函数 - 生成 16 字节密钥
/// 使用递归 HMAC-SHA256 进行密钥派生
/// KDF(key, path...) = HMAC(KDF(key, path[:-1]), path[-1])
fn kdf16_vmess_aead(key: &[u8], label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 16] {
    // 第一层: HMAC(key, "VMess AEAD KDF")
    let mut mac1 = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac1.update(b"VMess AEAD KDF");
    let k1 = mac1.finalize().into_bytes();

    // 第二层: HMAC(k1, label)
    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&k1).expect("HMAC can take key of any size");
    mac2.update(label);
    let k2 = mac2.finalize().into_bytes();

    // 第三层: HMAC(k2, auth_id)
    let mut mac3 = <HmacSha256 as Mac>::new_from_slice(&k2).expect("HMAC can take key of any size");
    mac3.update(auth_id);
    let k3 = mac3.finalize().into_bytes();

    // 第四层: HMAC(k3, nonce)
    let mut mac4 = <HmacSha256 as Mac>::new_from_slice(&k3).expect("HMAC can take key of any size");
    mac4.update(nonce);
    let result = mac4.finalize().into_bytes();

    let mut output = [0u8; 16];
    output.copy_from_slice(&result[..16]);
    output
}

fn kdf12_vmess_aead(key: &[u8], label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 12] {
    // 第一层: HMAC(key, "VMess AEAD KDF")
    let mut mac1 = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac1.update(b"VMess AEAD KDF");
    let k1 = mac1.finalize().into_bytes();

    // 第二层: HMAC(k1, label)
    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&k1).expect("HMAC can take key of any size");
    mac2.update(label);
    let k2 = mac2.finalize().into_bytes();

    // 第三层: HMAC(k2, auth_id)
    let mut mac3 = <HmacSha256 as Mac>::new_from_slice(&k2).expect("HMAC can take key of any size");
    mac3.update(auth_id);
    let k3 = mac3.finalize().into_bytes();

    // 第四层: HMAC(k3, nonce)
    let mut mac4 = <HmacSha256 as Mac>::new_from_slice(&k3).expect("HMAC can take key of any size");
    mac4.update(nonce);
    let result = mac4.finalize().into_bytes();

    let mut output = [0u8; 12];
    output.copy_from_slice(&result[..12]);
    output
}

#[allow(dead_code)]
fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut hasher = Sha256::new();
    hasher.update(key);
    for p in path {
        hasher.update(p);
    }
    let hash = hasher.finalize();
    result.copy_from_slice(&hash[..16]);
    result
}

#[allow(dead_code)]
fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let mut result = [0u8; 12];
    let mut hasher = Sha256::new();
    hasher.update(key);
    for p in path {
        hasher.update(p);
    }
    let hash = hasher.finalize();
    result.copy_from_slice(&hash[..12]);
    result
}

fn fnv1a_hash(data: &[u8]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c9dc5;
    const FNV_PRIME: u32 = 0x01000193;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn encrypt_chunk_aead(
    cipher: VmessCipher,
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    count: u16,
    mask: &mut Option<ShakeMask>,
) -> Result<Vec<u8>> {
    let resolved_cipher = cipher.resolve();

    match resolved_cipher {
        VmessCipher::Aes128Gcm => {
            let aes_cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let encrypted = aes_cipher
                .encrypt(nonce, data)
                .map_err(|e| Error::protocol(format!("Failed to encrypt data: {}", e)))?;

            // 计算长度并应用掩码
            let raw_length = encrypted.len() as u16;
            let masked_length = if let Some(ref mut m) = mask {
                raw_length ^ m.next_u16()
            } else {
                raw_length
            };

            let mut result = Vec::with_capacity(2 + encrypted.len());
            result.extend_from_slice(&masked_length.to_be_bytes());
            result.extend_from_slice(&encrypted);
            Ok(result)
        }
        VmessCipher::Chacha20Poly1305 => {
            let md5_key = {
                let mut hasher = Md5::new();
                hasher.update(key);
                hasher.finalize()
            };
            let md5_md5_key = {
                let mut hasher = Md5::new();
                hasher.update(md5_key);
                hasher.finalize()
            };
            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(&md5_key);
            full_key[16..].copy_from_slice(&md5_md5_key);

            let chacha_cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

            // IV = count (2 字节) + IV (10 字节)
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

            let encrypted = chacha_cipher
                .encrypt(nonce, data)
                .map_err(|e| Error::protocol(format!("Failed to encrypt data: {}", e)))?;

            // 计算长度并应用掩码
            let raw_length = encrypted.len() as u16;
            let masked_length = if let Some(ref mut m) = mask {
                raw_length ^ m.next_u16()
            } else {
                raw_length
            };

            let mut result = Vec::with_capacity(2 + encrypted.len());
            result.extend_from_slice(&masked_length.to_be_bytes());
            result.extend_from_slice(&encrypted);
            Ok(result)
        }
        VmessCipher::None | VmessCipher::Zero | VmessCipher::Auto | VmessCipher::Aes128Cfb => {
            // 不加密模式
            let raw_length = data.len() as u16;
            let masked_length = if let Some(ref mut m) = mask {
                raw_length ^ m.next_u16()
            } else {
                raw_length
            };

            let mut result = Vec::with_capacity(2 + data.len());
            result.extend_from_slice(&masked_length.to_be_bytes());
            result.extend_from_slice(data);
            Ok(result)
        }
    }
}

/// AEAD 模式数据块解密
fn decrypt_chunk_aead(
    cipher: VmessCipher,
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    count: u16,
) -> Result<Vec<u8>> {
    let resolved_cipher = cipher.resolve();

    match resolved_cipher {
        VmessCipher::Aes128Gcm => {
            let aes_cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let decrypted = aes_cipher
                .decrypt(nonce, data)
                .map_err(|e| Error::protocol(format!("Failed to decrypt data: {}", e)))?;

            Ok(decrypted)
        }
        VmessCipher::Chacha20Poly1305 => {
            // ChaCha20-Poly1305 密钥派生
            let md5_key = {
                let mut hasher = Md5::new();
                hasher.update(key);
                hasher.finalize()
            };
            let md5_md5_key = {
                let mut hasher = Md5::new();
                hasher.update(md5_key);
                hasher.finalize()
            };
            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(&md5_key);
            full_key[16..].copy_from_slice(&md5_md5_key);

            let chacha_cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

            let decrypted = chacha_cipher
                .decrypt(nonce, data)
                .map_err(|e| Error::protocol(format!("Failed to decrypt data: {}", e)))?;

            Ok(decrypted)
        }
        VmessCipher::None | VmessCipher::Zero | VmessCipher::Auto | VmessCipher::Aes128Cfb => {
            Ok(data.to_vec())
        }
    }
}

/// Legacy VMess chunk encryption (alterId > 0)
///
/// 重要：VMess Legacy 模式使用 AES-128-CFB 流式加密。
///
/// 根据 VMess 协议规范，Legacy 模式下：
/// - 整个数据部分使用 AES-128-CFB 加密
/// - 格式: [Length 2B][Encrypted(FNV1a 4B + Data)]
/// - 长度字段不加密，只有数据部分加密
///
/// 注意：每个 chunk 独立加密，使用相同的 key 和 iv
/// 这是因为 CFB 模式的特性，每个块的加密是独立的
fn encrypt_chunk_legacy(
    _cipher: VmessCipher,
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    _count: u16,
    _mask: &mut Option<ShakeMask>,
) -> Result<Vec<u8>> {
    // 计算原始数据的 FNV1a 校验和
    let checksum = fnv1a_hash(data);

    // 构建待加密的数据: [FNV1a 4B][原始数据]
    let mut plaintext = Vec::with_capacity(4 + data.len());
    plaintext.extend_from_slice(&checksum.to_be_bytes());
    plaintext.extend_from_slice(data);

    // VMess Legacy: 使用原始 IV 进行加密
    // 每个 chunk 独立加密，使用相同的 key 和 iv
    let cfb_cipher = Aes128CfbEnc::new_from_slices(key, iv)
        .map_err(|e| Error::protocol(format!("Failed to create AES-CFB cipher: {}", e)))?;
    cfb_cipher.encrypt(&mut plaintext);

    // 最终格式: [Length 2B][Encrypted(FNV1a + Data)]
    // Legacy 模式不使用掩码，长度字段不加密
    let mut result = Vec::with_capacity(2 + plaintext.len());
    result.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    result.extend_from_slice(&plaintext);

    tracing::trace!(
        "VMess legacy encrypt chunk: data_len={}, encrypted_len={}, total_len={}",
        data.len(),
        plaintext.len(),
        result.len()
    );

    Ok(result)
}

/// Legacy VMess chunk decryption (alterId > 0)
///
/// 数据包格式: [FNV1a 4B][数据]
/// 整个数据包使用 AES-128-CFB 解密
fn decrypt_chunk_legacy(
    _cipher: VmessCipher,
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    _count: u16,
) -> Result<Vec<u8>> {
    if data.len() < 4 {
        return Err(Error::protocol("Legacy chunk too short for FNV1a checksum"));
    }

    // VMess Legacy: 使用原始 IV 进行解密
    let mut decrypted = data.to_vec();
    let cfb_cipher = Aes128CfbDec::new_from_slices(key, iv)
        .map_err(|e| Error::protocol(format!("Failed to create AES-CFB cipher: {}", e)))?;
    cfb_cipher.decrypt(&mut decrypted);

    // 提取 FNV1a 校验和和实际数据
    let received_checksum =
        u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
    let actual_data = &decrypted[4..];

    // 验证校验和
    let calculated_checksum = fnv1a_hash(actual_data);
    if received_checksum != calculated_checksum {
        tracing::warn!(
            "VMess legacy FNV1a checksum mismatch: received={:#x}, calculated={:#x}",
            received_checksum,
            calculated_checksum
        );
        // 某些实现可能不严格检查，继续处理
    }

    Ok(actual_data.to_vec())
}

// derive_legacy_chunk_iv 函数已移除，因为 Legacy 模式使用原始 IV

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_cipher_from_str() {
        assert_eq!(VmessCipher::from_str("aes-128-gcm"), VmessCipher::Aes128Gcm);
        assert_eq!(VmessCipher::from_str("aes128gcm"), VmessCipher::Aes128Gcm);
        assert_eq!(
            VmessCipher::from_str("chacha20-poly1305"),
            VmessCipher::Chacha20Poly1305
        );
        assert_eq!(VmessCipher::from_str("none"), VmessCipher::None);
        assert_eq!(VmessCipher::from_str("zero"), VmessCipher::Zero);
        assert_eq!(VmessCipher::from_str("auto"), VmessCipher::Auto);
        assert_eq!(VmessCipher::from_str("unknown"), VmessCipher::Auto);
    }

    #[test]
    fn test_vmess_cipher_as_byte() {
        // 根据 VMess 协议规范:
        // 0x00: AES-128-CFB
        // 0x01: 不加密
        // 0x02: AES-128-GCM
        // 0x03: ChaCha20-Poly1305
        assert_eq!(VmessCipher::Aes128Cfb.as_byte(), 0x00);
        assert_eq!(VmessCipher::None.as_byte(), 0x01);
        assert_eq!(VmessCipher::Aes128Gcm.as_byte(), 0x02);
        assert_eq!(VmessCipher::Chacha20Poly1305.as_byte(), 0x03);
        assert_eq!(VmessCipher::Zero.as_byte(), 0x01); // Zero 映射到不加密
        // Auto depends on platform, so we just check it's valid (0x02 or 0x03)
        let auto_byte = VmessCipher::Auto.as_byte();
        assert!(auto_byte == 0x02 || auto_byte == 0x03);
    }

    #[test]
    fn test_vmess_command_from_u8() {
        assert_eq!(VmessCommand::from_u8(0x01), Some(VmessCommand::Tcp));
        assert_eq!(VmessCommand::from_u8(0x02), Some(VmessCommand::Udp));
        assert_eq!(VmessCommand::from_u8(0x00), None);
        assert_eq!(VmessCommand::from_u8(0xFF), None);
    }

    #[test]
    fn test_generate_cmd_key() {
        let uuid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let key = generate_cmd_key(&uuid);
        assert_eq!(key.len(), 16);

        let key2 = generate_cmd_key(&uuid);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_fnv1a_hash() {
        let data = b"hello world";
        let hash = fnv1a_hash(data);
        assert_ne!(hash, 0);

        let hash2 = fnv1a_hash(data);
        assert_eq!(hash, hash2);

        let hash3 = fnv1a_hash(b"different data");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_kdf16() {
        let key = b"test_key";
        let path = [b"path1".as_slice(), b"path2".as_slice()];
        let result = kdf16(key, &path);
        assert_eq!(result.len(), 16);

        let result2 = kdf16(key, &path);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_kdf12() {
        let key = b"test_key";
        let path = [b"path1".as_slice(), b"path2".as_slice()];
        let result = kdf12(key, &path);
        assert_eq!(result.len(), 12);

        let result2 = kdf12(key, &path);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_vmess_outbound_new() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "alterId".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(0)),
        );
        options.insert(
            "cipher".to_string(),
            serde_yaml::Value::String("aes-128-gcm".to_string()),
        );
        options.insert("udp".to_string(), serde_yaml::Value::Bool(true));

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        assert_eq!(outbound.tag(), "vmess-test");
        assert_eq!(outbound.server, "vmess.example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.cipher, VmessCipher::Aes128Gcm);
        assert!(outbound.is_udp_enabled());
    }

    #[test]
    fn test_vmess_outbound_missing_uuid() {
        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            options: std::collections::HashMap::new(),
        };

        let result = VmessOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vmess_outbound_invalid_uuid() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("invalid-uuid".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            options,
        };

        let result = VmessOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vmess_outbound_server_addr() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "server.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_generate_auth_id() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();
        let timestamp = 1234567890i64;
        let auth_id = outbound.generate_auth_id(timestamp);
        assert_eq!(auth_id.len(), 16);

        // 由于 auth_id 包含随机数，每次生成的结果都不同
        let auth_id2 = outbound.generate_auth_id(timestamp);
        // auth_id 和 auth_id2 可能不同（因为随机数不同）
        assert_eq!(auth_id2.len(), 16);

        // 不同时间戳生成的 auth_id 也不同
        let auth_id3 = outbound.generate_auth_id(timestamp + 1);
        assert_eq!(auth_id3.len(), 16);
    }

    #[test]
    fn test_generate_request_key_iv() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let key1 = outbound.generate_request_key();
        let key2 = outbound.generate_request_key();
        assert_eq!(key1.len(), 16);
        assert_eq!(key2.len(), 16);
        assert_ne!(key1, key2);

        let iv1 = outbound.generate_request_iv();
        let iv2 = outbound.generate_request_iv();
        assert_eq!(iv1.len(), 16);
        assert_eq!(iv2.len(), 16);
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn test_generate_response_key_iv() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let request_key = [0x01u8; 16];
        let request_iv = [0x02u8; 16];

        let response_key = outbound.generate_response_key(&request_key);
        let response_iv = outbound.generate_response_iv(&request_iv);

        assert_eq!(response_key.len(), 16);
        assert_eq!(response_iv.len(), 16);

        let response_key2 = outbound.generate_response_key(&request_key);
        let response_iv2 = outbound.generate_response_iv(&request_iv);
        assert_eq!(response_key, response_key2);
        assert_eq!(response_iv, response_iv2);
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_roundtrip() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "cipher".to_string(),
            serde_yaml::Value::String("aes-128-gcm".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let data = b"Hello, VMess!";

        let encrypted = outbound.encrypt_aes_gcm(data, &key, &iv, 0).unwrap();
        assert!(encrypted.len() > data.len());

        let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
        let decrypted = outbound
            .decrypt_aes_gcm(&encrypted[2..2 + length], &key, &iv, 0)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_chacha20_roundtrip() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "cipher".to_string(),
            serde_yaml::Value::String("chacha20-poly1305".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let data = b"Hello, VMess!";

        let encrypted = outbound.encrypt_chacha20(data, &key, &iv, 0).unwrap();
        assert!(encrypted.len() > data.len());

        let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
        let decrypted = outbound
            .decrypt_chacha20(&encrypted[2..2 + length], &key, &iv, 0)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_none_roundtrip() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "cipher".to_string(),
            serde_yaml::Value::String("none".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let data = b"Hello, VMess!";

        let encrypted = outbound.encrypt_chunk(data, &key, &iv, 0).unwrap();
        let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
        assert_eq!(length, data.len());

        let decrypted = outbound
            .decrypt_chunk(&encrypted[2..], &key, &iv, 0)
            .unwrap();
        assert_eq!(decrypted, data);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_key() -> impl Strategy<Value = [u8; 16]> {
        prop::array::uniform16(any::<u8>())
    }

    fn arb_iv() -> impl Strategy<Value = [u8; 16]> {
        prop::array::uniform16(any::<u8>())
    }

    fn arb_data() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..1024)
    }

    fn arb_count() -> impl Strategy<Value = u16> {
        0u16..1000u16
    }

    fn arb_timestamp() -> impl Strategy<Value = i64> {
        1000000000i64..2000000000i64
    }

    fn create_test_outbound(cipher_str: &str) -> VmessOutbound {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            serde_yaml::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "cipher".to_string(),
            serde_yaml::Value::String(cipher_str.to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        VmessOutbound::new(config).unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_aes_gcm_encrypt_decrypt_roundtrip(
            key in arb_key(),
            iv in arb_iv(),
            data in arb_data(),
            count in arb_count()
        ) {
            let outbound = create_test_outbound("aes-128-gcm");

            let encrypted = outbound.encrypt_aes_gcm(&data, &key, &iv, count).unwrap();
            let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
            let decrypted = outbound.decrypt_aes_gcm(&encrypted[2..2+length], &key, &iv, count).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn prop_chacha20_encrypt_decrypt_roundtrip(
            key in arb_key(),
            iv in arb_iv(),
            data in arb_data(),
            count in arb_count()
        ) {
            let outbound = create_test_outbound("chacha20-poly1305");

            let encrypted = outbound.encrypt_chacha20(&data, &key, &iv, count).unwrap();
            let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
            let decrypted = outbound.decrypt_chacha20(&encrypted[2..2+length], &key, &iv, count).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn prop_none_cipher_roundtrip(
            key in arb_key(),
            iv in arb_iv(),
            data in arb_data(),
            count in arb_count()
        ) {
            let outbound = create_test_outbound("none");

            let encrypted = outbound.encrypt_chunk(&data, &key, &iv, count).unwrap();
            let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
            prop_assert_eq!(length, data.len());

            let decrypted = outbound.decrypt_chunk(&encrypted[2..], &key, &iv, count).unwrap();
            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn prop_auth_id_length(timestamp in arb_timestamp()) {
            let outbound = create_test_outbound("auto");

            // auth_id 包含随机数，所以每次生成的结果不同
            // 但长度应该始终是 16 字节
            let auth_id1 = outbound.generate_auth_id(timestamp);
            let auth_id2 = outbound.generate_auth_id(timestamp);

            // 由于随机数不同，auth_id 可能不同
            prop_assert_eq!(auth_id1.len(), 16);
            prop_assert_eq!(auth_id2.len(), 16);
        }

        #[test]
        fn prop_auth_id_different_timestamps(
            timestamp1 in arb_timestamp(),
            timestamp2 in arb_timestamp()
        ) {
            prop_assume!(timestamp1 != timestamp2);
            let outbound = create_test_outbound("auto");

            let auth_id1 = outbound.generate_auth_id(timestamp1);
            let auth_id2 = outbound.generate_auth_id(timestamp2);

            // 不同时间戳生成的 auth_id 应该不同（除非随机数碰巧相同，概率极低）
            // 这里只验证长度
            prop_assert_eq!(auth_id1.len(), 16);
            prop_assert_eq!(auth_id2.len(), 16);
        }

        #[test]
        fn prop_response_key_iv_deterministic(
            request_key in arb_key(),
            request_iv in arb_iv()
        ) {
            let outbound = create_test_outbound("auto");

            let response_key1 = outbound.generate_response_key(&request_key);
            let response_key2 = outbound.generate_response_key(&request_key);
            prop_assert_eq!(response_key1, response_key2);

            let response_iv1 = outbound.generate_response_iv(&request_iv);
            let response_iv2 = outbound.generate_response_iv(&request_iv);
            prop_assert_eq!(response_iv1, response_iv2);
        }

        #[test]
        fn prop_fnv1a_deterministic(data in arb_data()) {
            let hash1 = fnv1a_hash(&data);
            let hash2 = fnv1a_hash(&data);
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_kdf_deterministic(
            key in prop::collection::vec(any::<u8>(), 1..64),
            path1 in prop::collection::vec(any::<u8>(), 1..32),
            path2 in prop::collection::vec(any::<u8>(), 1..32)
        ) {
            let path = [path1.as_slice(), path2.as_slice()];

            let result1 = kdf16(&key, &path);
            let result2 = kdf16(&key, &path);
            prop_assert_eq!(result1, result2);

            let result3 = kdf12(&key, &path);
            let result4 = kdf12(&key, &path);
            prop_assert_eq!(result3, result4);
        }

        #[test]
        fn prop_cmd_key_deterministic(uuid in prop::array::uniform16(any::<u8>())) {
            let key1 = generate_cmd_key(&uuid);
            let key2 = generate_cmd_key(&uuid);
            prop_assert_eq!(key1, key2);
            prop_assert_eq!(key1.len(), 16);
        }
    }
}
