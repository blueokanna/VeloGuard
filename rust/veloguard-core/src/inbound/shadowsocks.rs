use crate::config::InboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha1::Sha1;
use md5::Digest as Md5Digest;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const SS_AEAD_TAG_LEN: usize = 16;
const SS_MAX_PAYLOAD_LEN: usize = 0x3FFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl SsCipher {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" => Some(SsCipher::Aes128Gcm),
            "aes-256-gcm" => Some(SsCipher::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(SsCipher::Chacha20Poly1305),
            _ => None,
        }
    }
    pub fn key_len(&self) -> usize {
        match self {
            SsCipher::Aes128Gcm => 16,
            SsCipher::Aes256Gcm | SsCipher::Chacha20Poly1305 => 32,
        }
    }
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }
    pub fn nonce_len(&self) -> usize {
        12
    }
}

pub struct ShadowsocksInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
    cipher: SsCipher,
    key: Vec<u8>,
}

#[async_trait::async_trait]
impl InboundListener for ShadowsocksInbound {
    async fn start(&self) -> Result<()> {
        self.start_listener().await
    }
    async fn stop(&self) -> Result<()> {
        self.stop_listener().await
    }
    fn tag(&self) -> &str {
        &self.config.tag
    }
}

impl ShadowsocksInbound {
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Self> {
        let cipher_str = config.options.get("cipher")
            .and_then(|v| v.as_str())
            .unwrap_or("aes-256-gcm");
        let cipher = SsCipher::from_str(cipher_str)
            .ok_or_else(|| Error::config(format!("Unsupported cipher: {}", cipher_str)))?;
        let password = config.options.get("password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Missing password for Shadowsocks"))?;
        let key = derive_key(password.as_bytes(), cipher.key_len());
        Ok(Self {
            config,
            router,
            outbound_manager,
            cancel_token: CancellationToken::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cipher,
            key,
        })
    }

    async fn start_listener(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        let addr: SocketAddr = format!("{}:{}", self.config.listen, self.config.port)
            .parse()
            .map_err(|e| Error::config(format!("Invalid listen address: {}", e)))?;
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ).map_err(|e| Error::network(format!("Failed to create socket: {}", e)))?;
        socket.set_reuse_address(true).ok();
        socket.set_nonblocking(true).ok();
        socket.bind(&addr.into())
            .map_err(|e| Error::network(format!("Failed to bind: {}", e)))?;
        socket.listen(1024)
            .map_err(|e| Error::network(format!("Failed to listen: {}", e)))?;
        let listener: TcpListener = TcpListener::from_std(socket.into())
            .map_err(|e| Error::network(format!("Failed to create listener: {}", e)))?;
        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let cancel_token = self.cancel_token.clone();
        let running = Arc::clone(&self.running);
        let cipher = self.cipher;
        let key = self.key.clone();
        running.store(true, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                let router = Arc::clone(&router);
                                let outbound_manager = Arc::clone(&outbound_manager);
                                let key = key.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(
                                        stream, peer_addr, router, outbound_manager, cipher, key
                                    ).await {
                                        tracing::debug!("Shadowsocks inbound error from {}: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => tracing::error!("Shadowsocks accept error: {}", e),
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
        });
        tracing::info!("Shadowsocks inbound listening on {}", addr);
        Ok(())
    }

    async fn stop_listener(&self) -> Result<()> {
        self.cancel_token.cancel();
        let mut attempts = 0;
        while self.running.load(std::sync::atomic::Ordering::Relaxed) && attempts < 50 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            attempts += 1;
        }
        Ok(())
    }

    async fn handle_connection(
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        cipher: SsCipher,
        key: Vec<u8>,
    ) -> Result<()> {
        let salt_len = cipher.salt_len();
        let mut salt = vec![0u8; salt_len];
        stream.read_exact(&mut salt).await
            .map_err(|e| Error::network(format!("Failed to read salt: {}", e)))?;
        let subkey = derive_subkey(&key, &salt, cipher.key_len());
        let mut nonce = vec![0u8; cipher.nonce_len()];
        let mut length_buf = vec![0u8; 2 + SS_AEAD_TAG_LEN];
        stream.read_exact(&mut length_buf).await
            .map_err(|e| Error::network(format!("Failed to read length: {}", e)))?;
        let length_plain = decrypt_aead(cipher, &subkey, &nonce, &length_buf)?;
        increment_nonce(&mut nonce);
        let payload_len = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
        if payload_len > SS_MAX_PAYLOAD_LEN {
            return Err(Error::protocol("Payload too large"));
        }
        let mut payload_buf = vec![0u8; payload_len + SS_AEAD_TAG_LEN];
        stream.read_exact(&mut payload_buf).await
            .map_err(|e| Error::network(format!("Failed to read payload: {}", e)))?;
        let payload = decrypt_aead(cipher, &subkey, &nonce, &payload_buf)?;
        increment_nonce(&mut nonce);
        if payload.is_empty() {
            return Err(Error::protocol("Empty payload"));
        }
        let addr_type = payload[0];
        let (target, header_len) = match addr_type {
            0x01 => {
                if payload.len() < 7 {
                    return Err(Error::protocol("IPv4 address too short"));
                }
                let ip = Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]);
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                (TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7)
            }
            0x03 => {
                if payload.len() < 2 {
                    return Err(Error::protocol("Domain length missing"));
                }
                let len = payload[1] as usize;
                if payload.len() < 2 + len + 2 {
                    return Err(Error::protocol("Domain too short"));
                }
                let domain = String::from_utf8(payload[2..2 + len].to_vec())
                    .map_err(|_| Error::protocol("Invalid domain encoding"))?;
                let port = u16::from_be_bytes([payload[2 + len], payload[3 + len]]);
                (TargetAddr::Domain(domain, port), 4 + len)
            }
            0x04 => {
                if payload.len() < 19 {
                    return Err(Error::protocol("IPv6 address too short"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&payload[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([payload[17], payload[18]]);
                (TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port)), 19)
            }
            _ => return Err(Error::protocol(format!("Unknown address type: {}", addr_type))),
        };
        let initial_data = if payload.len() > header_len {
            Some(payload[header_len..].to_vec())
        } else {
            None
        };
        let outbound_tag = router.match_outbound(
            Some(&target.host()), None, Some(target.port()), None
        ).await;
        tracing::info!("Shadowsocks {} -> {} from {}", target, outbound_tag, peer_addr);
        let outbound = outbound_manager.get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;
        let tracked_conn = TrackedConnection::new_with_ip(
            "shadowsocks".to_string(), outbound_tag.clone(), target.host(), None,
            target.port(), "Shadowsocks".to_string(), "tcp".to_string(),
            "Shadowsocks".to_string(), target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);
        let ss_stream = SsStream::new(stream, cipher, subkey, nonce, initial_data);
        if let Err(e) = outbound.relay_tcp_with_connection(
            Box::new(ss_stream), target.clone(), Some(conn_arc)
        ).await {
            tracing::debug!("Shadowsocks relay error: {}", e);
        }
        tracker.untrack(&tracked.id);
        Ok(())
    }
}

fn derive_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev = Vec::new();
    while key.len() < key_len {
        let mut hasher = md5::Md5::new();
        hasher.update(&prev);
        hasher.update(password);
        let hash = hasher.finalize();
        key.extend_from_slice(&hash);
        prev = hash.to_vec();
    }
    key.truncate(key_len);
    key
}

fn derive_subkey(key: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), key);
    let mut subkey = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut subkey).expect("HKDF expand failed");
    subkey
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn decrypt_aead(cipher: SsCipher, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let nonce_arr = Nonce::from_slice(nonce);
    match cipher {
        SsCipher::Aes128Gcm => {
            let c = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
            c.decrypt(nonce_arr, data)
                .map_err(|e| Error::protocol(format!("Decrypt error: {}", e)))
        }
        SsCipher::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
            c.decrypt(nonce_arr, data)
                .map_err(|e| Error::protocol(format!("Decrypt error: {}", e)))
        }
        SsCipher::Chacha20Poly1305 => {
            let c = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
            let nonce_arr = chacha20poly1305::Nonce::from_slice(nonce);
            c.decrypt(nonce_arr, data)
                .map_err(|e| Error::protocol(format!("Decrypt error: {}", e)))
        }
    }
}

fn encrypt_aead(cipher: SsCipher, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let nonce_arr = Nonce::from_slice(nonce);
    match cipher {
        SsCipher::Aes128Gcm => {
            let c = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
            c.encrypt(nonce_arr, data)
                .map_err(|e| Error::protocol(format!("Encrypt error: {}", e)))
        }
        SsCipher::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
            c.encrypt(nonce_arr, data)
                .map_err(|e| Error::protocol(format!("Encrypt error: {}", e)))
        }
        SsCipher::Chacha20Poly1305 => {
            let c = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
            let nonce_arr = chacha20poly1305::Nonce::from_slice(nonce);
            c.encrypt(nonce_arr, data)
                .map_err(|e| Error::protocol(format!("Encrypt error: {}", e)))
        }
    }
}

struct SsStream {
    inner: tokio::net::TcpStream,
    cipher: SsCipher,
    key: Vec<u8>,
    read_nonce: Vec<u8>,
    write_nonce: Vec<u8>,
    write_salt_sent: bool,
    read_buf: Vec<u8>,
    read_pos: usize,
    initial_data: Option<Vec<u8>>,
}

impl SsStream {
    fn new(
        inner: tokio::net::TcpStream,
        cipher: SsCipher,
        key: Vec<u8>,
        read_nonce: Vec<u8>,
        initial_data: Option<Vec<u8>>,
    ) -> Self {
        let write_nonce = vec![0u8; cipher.nonce_len()];
        Self {
            inner, cipher, key, read_nonce, write_nonce,
            write_salt_sent: false, read_buf: Vec::new(), read_pos: 0, initial_data,
        }
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if let Some(data) = self.initial_data.take() {
            let to_copy = std::cmp::min(data.len(), buf.remaining());
            buf.put_slice(&data[..to_copy]);
            if to_copy < data.len() {
                self.read_buf = data[to_copy..].to_vec();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let mut length_buf = [0u8; 2 + SS_AEAD_TAG_LEN];
        let mut length_read_buf = tokio::io::ReadBuf::new(&mut length_buf);
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut length_read_buf) {
            Poll::Ready(Ok(())) => {
                if length_read_buf.filled().len() < 2 + SS_AEAD_TAG_LEN {
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let this = self.get_mut();
        let length_plain = match decrypt_aead(this.cipher, &this.key, &this.read_nonce, &length_buf) {
            Ok(p) => p,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e.to_string()))),
        };
        increment_nonce(&mut this.read_nonce);
        let payload_len = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
        if payload_len == 0 || payload_len > SS_MAX_PAYLOAD_LEN {
            return Poll::Ready(Ok(()));
        }
        let mut payload_buf = vec![0u8; payload_len + SS_AEAD_TAG_LEN];
        let mut payload_read_buf = tokio::io::ReadBuf::new(&mut payload_buf);
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut payload_read_buf) {
            Poll::Ready(Ok(())) => {
                if payload_read_buf.filled().len() < payload_len + SS_AEAD_TAG_LEN {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let payload = match decrypt_aead(this.cipher, &this.key, &this.read_nonce, &payload_buf) {
            Ok(p) => p,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e.to_string()))),
        };
        increment_nonce(&mut this.read_nonce);
        let to_copy = std::cmp::min(payload.len(), buf.remaining());
        buf.put_slice(&payload[..to_copy]);
        if to_copy < payload.len() {
            this.read_buf = payload[to_copy..].to_vec();
            this.read_pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();
        let mut output = Vec::new();
        if !this.write_salt_sent {
            let mut salt = vec![0u8; this.cipher.salt_len()];
            getrandom::fill(&mut salt).ok();
            let new_key = derive_subkey(&this.key, &salt, this.cipher.key_len());
            this.key = new_key;
            output.extend_from_slice(&salt);
            this.write_salt_sent = true;
        }
        let length_bytes = (buf.len() as u16).to_be_bytes();
        let length_encrypted = match encrypt_aead(this.cipher, &this.key, &this.write_nonce, &length_bytes) {
            Ok(e) => e,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e.to_string()))),
        };
        increment_nonce(&mut this.write_nonce);
        output.extend_from_slice(&length_encrypted);
        let payload_encrypted = match encrypt_aead(this.cipher, &this.key, &this.write_nonce, buf) {
            Ok(e) => e,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e.to_string()))),
        };
        increment_nonce(&mut this.write_nonce);
        output.extend_from_slice(&payload_encrypted);
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &output) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
