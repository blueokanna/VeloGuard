use crate::config::InboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const VMESS_AEAD_AUTH_LEN: usize = 16;
const VMESS_AEAD_NONCE_LEN: usize = 12;
#[allow(dead_code)]
const VMESS_TIME_WINDOW_SECS: i64 = 120;

#[derive(Debug, Clone)]
struct VmessUser {
    #[allow(dead_code)]
    uuid: Uuid,
    cmd_key: [u8; 16],
}

impl VmessUser {
    fn new(uuid: Uuid) -> Self {
        let cmd_key = generate_cmd_key(uuid.as_bytes());
        Self { uuid, cmd_key }
    }
}

pub struct VmessInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
    users: Arc<RwLock<HashMap<Uuid, VmessUser>>>,
}

#[async_trait::async_trait]
impl InboundListener for VmessInbound {
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

impl VmessInbound {
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        let mut users_map = HashMap::new();
        if let Some(users) = config.options.get("users") {
            if let Some(users_arr) = users.as_sequence() {
                for user in users_arr {
                    if let Some(uuid_str) = user.get("uuid").and_then(|v| v.as_str()) {
                        if let Ok(uuid) = Uuid::parse_str(uuid_str) {
                            users_map.insert(uuid, VmessUser::new(uuid));
                        }
                    }
                }
            }
        }
        Self {
            config,
            router,
            outbound_manager,
            cancel_token: CancellationToken::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            users: Arc::new(RwLock::new(users_map)),
        }
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
        let users = Arc::clone(&self.users);
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
                                let users = Arc::clone(&users);
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(
                                        stream, peer_addr, router, outbound_manager, users
                                    ).await {
                                        tracing::debug!("VMess inbound error from {}: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => tracing::error!("VMess accept error: {}", e),
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
        });
        tracing::info!("VMess inbound listening on {}", addr);
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
        users: Arc<RwLock<HashMap<Uuid, VmessUser>>>,
    ) -> Result<()> {
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await
            .map_err(|e| Error::network(format!("Failed to read auth_id: {}", e)))?;
        let mut encrypted_length = [0u8; 18];
        stream.read_exact(&mut encrypted_length).await
            .map_err(|e| Error::network(format!("Failed to read encrypted length: {}", e)))?;
        let mut nonce = [0u8; 8];
        stream.read_exact(&mut nonce).await
            .map_err(|e| Error::network(format!("Failed to read nonce: {}", e)))?;
        let users_read = users.read().await;
        let mut matched_user: Option<&VmessUser> = None;
        let mut header_length: usize = 0;
        for user in users_read.values() {
            if let Some(len) = Self::try_decrypt_length(&user.cmd_key, &auth_id, &nonce, &encrypted_length) {
                matched_user = Some(user);
                header_length = len;
                break;
            }
        }
        let user = matched_user.ok_or_else(|| Error::protocol("No matching VMess user"))?;
        let cmd_key = user.cmd_key;
        drop(users_read);
        let mut encrypted_header = vec![0u8; header_length + VMESS_AEAD_AUTH_LEN];
        stream.read_exact(&mut encrypted_header).await
            .map_err(|e| Error::network(format!("Failed to read header: {}", e)))?;
        let header = Self::decrypt_header(&cmd_key, &auth_id, &nonce, &encrypted_header)?;
        if header.len() < 41 {
            return Err(Error::protocol("Header too short"));
        }
        let request_iv: [u8; 16] = header[1..17].try_into().unwrap();
        let request_key: [u8; 16] = header[17..33].try_into().unwrap();
        let response_header = header[33];
        let option = header[34];
        let security = header[35] & 0x0F;
        let command = header[37];
        let port = u16::from_be_bytes([header[38], header[39]]);
        let addr_type = header[40];
        let (target, _addr_end) = Self::parse_address(&header[40..], addr_type, port)?;
        let response_key = Self::generate_response_key(&request_key);
        let response_iv = Self::generate_response_iv(&request_iv);
        let outbound_tag = router.match_outbound(
            Some(&target.host()), None, Some(target.port()), None
        ).await;
        tracing::info!("VMess {} -> {} from {}", target, outbound_tag, peer_addr);
        let outbound = outbound_manager.get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;
        let tracked_conn = TrackedConnection::new_with_ip(
            "vmess".to_string(), outbound_tag.clone(), target.host(), None,
            target.port(), "VMess".to_string(), "tcp".to_string(),
            "VMess".to_string(), target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);
        Self::send_response_header(&mut stream, &response_key, &response_iv, response_header).await?;
        let vmess_stream = VmessStream::new(
            stream, request_key, request_iv, response_key, response_iv,
            security, option, command,
        );
        if let Err(e) = outbound.relay_tcp_with_connection(
            Box::new(vmess_stream), target.clone(), Some(conn_arc)
        ).await {
            tracing::debug!("VMess relay error: {}", e);
        }
        tracker.untrack(&tracked.id);
        Ok(())
    }

    fn try_decrypt_length(cmd_key: &[u8; 16], auth_id: &[u8; 16], nonce: &[u8; 8], data: &[u8; 18]) -> Option<usize> {
        let length_key = kdf16_vmess_aead(cmd_key, b"VMess Header AEAD Key_Length", auth_id, nonce);
        let length_nonce = kdf12_vmess_aead(cmd_key, b"VMess Header AEAD Nonce_Length", auth_id, nonce);
        let cipher = Aes128Gcm::new_from_slice(&length_key).ok()?;
        let nonce_obj = Nonce::from_slice(&length_nonce);
        use aes_gcm::aead::Payload;
        let decrypted = cipher.decrypt(nonce_obj, Payload { msg: data, aad: auth_id }).ok()?;
        if decrypted.len() != 2 {
            return None;
        }
        Some(u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize)
    }

    fn decrypt_header(cmd_key: &[u8; 16], auth_id: &[u8; 16], nonce: &[u8; 8], data: &[u8]) -> Result<Vec<u8>> {
        let header_key = kdf16_vmess_aead(cmd_key, b"VMess Header AEAD Key", auth_id, nonce);
        let header_nonce = kdf12_vmess_aead(cmd_key, b"VMess Header AEAD Nonce", auth_id, nonce);
        let cipher = Aes128Gcm::new_from_slice(&header_key)
            .map_err(|e| Error::protocol(format!("Failed to create cipher: {}", e)))?;
        let nonce_obj = Nonce::from_slice(&header_nonce);
        use aes_gcm::aead::Payload;
        cipher.decrypt(nonce_obj, Payload { msg: data, aad: auth_id })
            .map_err(|e| Error::protocol(format!("Failed to decrypt header: {}", e)))
    }

    fn parse_address(data: &[u8], addr_type: u8, port: u16) -> Result<(TargetAddr, usize)> {
        match addr_type {
            0x01 => {
                if data.len() < 5 {
                    return Err(Error::protocol("IPv4 address too short"));
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                Ok((TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 5))
            }
            0x02 => {
                if data.len() < 2 {
                    return Err(Error::protocol("Domain length missing"));
                }
                let len = data[1] as usize;
                if data.len() < 2 + len {
                    return Err(Error::protocol("Domain too short"));
                }
                let domain = String::from_utf8(data[2..2 + len].to_vec())
                    .map_err(|_| Error::protocol("Invalid domain encoding"))?;
                Ok((TargetAddr::Domain(domain, port), 2 + len))
            }
            0x03 => {
                if data.len() < 17 {
                    return Err(Error::protocol("IPv6 address too short"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = Ipv6Addr::from(octets);
                Ok((TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port)), 17))
            }
            _ => Err(Error::protocol(format!("Unknown address type: {}", addr_type))),
        }
    }

    fn generate_response_key(request_key: &[u8; 16]) -> [u8; 16] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(request_key);
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result[..16]);
        key
    }

    fn generate_response_iv(request_iv: &[u8; 16]) -> [u8; 16] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(request_iv);
        let result = hasher.finalize();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&result[..16]);
        iv
    }

    async fn send_response_header<W: AsyncWrite + Unpin>(
        stream: &mut W,
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
        response_header: u8,
    ) -> Result<()> {
        let header = [response_header, 0x00, 0x00, 0x00];
        let cipher = Aes128Gcm::new_from_slice(response_key)
            .map_err(|e| Error::protocol(format!("Failed to create cipher: {}", e)))?;
        let nonce = Nonce::from_slice(&response_iv[..VMESS_AEAD_NONCE_LEN]);
        let encrypted = cipher.encrypt(nonce, header.as_slice())
            .map_err(|e| Error::protocol(format!("Failed to encrypt response: {}", e)))?;
        stream.write_all(&encrypted).await
            .map_err(|e| Error::network(format!("Failed to write response: {}", e)))?;
        Ok(())
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

fn kdf16_vmess_aead(key: &[u8], label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 16] {
    let mut mac1 = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC error");
    mac1.update(b"VMess AEAD KDF");
    let k1 = mac1.finalize().into_bytes();
    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&k1).expect("HMAC error");
    mac2.update(label);
    let k2 = mac2.finalize().into_bytes();
    let mut mac3 = <HmacSha256 as Mac>::new_from_slice(&k2).expect("HMAC error");
    mac3.update(auth_id);
    let k3 = mac3.finalize().into_bytes();
    let mut mac4 = <HmacSha256 as Mac>::new_from_slice(&k3).expect("HMAC error");
    mac4.update(nonce);
    let result = mac4.finalize().into_bytes();
    let mut output = [0u8; 16];
    output.copy_from_slice(&result[..16]);
    output
}

fn kdf12_vmess_aead(key: &[u8], label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 12] {
    let mut mac1 = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC error");
    mac1.update(b"VMess AEAD KDF");
    let k1 = mac1.finalize().into_bytes();
    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&k1).expect("HMAC error");
    mac2.update(label);
    let k2 = mac2.finalize().into_bytes();
    let mut mac3 = <HmacSha256 as Mac>::new_from_slice(&k2).expect("HMAC error");
    mac3.update(auth_id);
    let k3 = mac3.finalize().into_bytes();
    let mut mac4 = <HmacSha256 as Mac>::new_from_slice(&k3).expect("HMAC error");
    mac4.update(nonce);
    let result = mac4.finalize().into_bytes();
    let mut output = [0u8; 12];
    output.copy_from_slice(&result[..12]);
    output
}

struct VmessStream {
    inner: tokio::net::TcpStream,
    request_key: [u8; 16],
    request_iv: [u8; 16],
    response_key: [u8; 16],
    response_iv: [u8; 16],
    security: u8,
    read_count: u16,
    write_count: u16,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl VmessStream {
    fn new(
        inner: tokio::net::TcpStream,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
        security: u8,
        _option: u8,
        _command: u8,
    ) -> Self {
        Self {
            inner, request_key, request_iv, response_key, response_iv,
            security, read_count: 0, write_count: 0, read_buf: Vec::new(), read_pos: 0,
        }
    }

    fn decrypt_chunk(&self, data: &[u8], count: u16) -> Result<Vec<u8>> {
        match self.security {
            0x01 => {
                let cipher = Aes128Gcm::new_from_slice(&self.request_key)
                    .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
                nonce_bytes[2..].copy_from_slice(&self.request_iv[2..12]);
                let nonce = Nonce::from_slice(&nonce_bytes);
                cipher.decrypt(nonce, data)
                    .map_err(|e| Error::protocol(format!("Decrypt error: {}", e)))
            }
            0x02 => {
                let mut full_key = [0u8; 32];
                full_key[..16].copy_from_slice(&self.request_key);
                full_key[16..].copy_from_slice(&self.request_key);
                let cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                    .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
                nonce_bytes[2..].copy_from_slice(&self.request_iv[2..12]);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                cipher.decrypt(nonce, data)
                    .map_err(|e| Error::protocol(format!("Decrypt error: {}", e)))
            }
            _ => Ok(data.to_vec()),
        }
    }

    fn encrypt_chunk(&self, data: &[u8], count: u16) -> Result<Vec<u8>> {
        match self.security {
            0x01 => {
                let cipher = Aes128Gcm::new_from_slice(&self.response_key)
                    .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
                nonce_bytes[2..].copy_from_slice(&self.response_iv[2..12]);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher.encrypt(nonce, data)
                    .map_err(|e| Error::protocol(format!("Encrypt error: {}", e)))?;
                let mut result = Vec::with_capacity(2 + encrypted.len());
                result.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
                result.extend_from_slice(&encrypted);
                Ok(result)
            }
            0x02 => {
                let mut full_key = [0u8; 32];
                full_key[..16].copy_from_slice(&self.response_key);
                full_key[16..].copy_from_slice(&self.response_key);
                let cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                    .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
                nonce_bytes[2..].copy_from_slice(&self.response_iv[2..12]);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher.encrypt(nonce, data)
                    .map_err(|e| Error::protocol(format!("Encrypt error: {}", e)))?;
                let mut result = Vec::with_capacity(2 + encrypted.len());
                result.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
                result.extend_from_slice(&encrypted);
                Ok(result)
            }
            _ => {
                let mut result = Vec::with_capacity(2 + data.len());
                result.extend_from_slice(&(data.len() as u16).to_be_bytes());
                result.extend_from_slice(data);
                Ok(result)
            }
        }
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
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
        let mut length_buf = [0u8; 2];
        let mut length_read_buf = tokio::io::ReadBuf::new(&mut length_buf);
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut length_read_buf) {
            Poll::Ready(Ok(())) => {
                if length_read_buf.filled().len() < 2 {
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let length = u16::from_be_bytes(length_buf) as usize;
        if length == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let count = this.read_count;
        this.read_count = this.read_count.wrapping_add(1);
        let mut data = vec![0u8; length];
        let mut data_read_buf = tokio::io::ReadBuf::new(&mut data);
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut data_read_buf) {
            Poll::Ready(Ok(())) => {
                if data_read_buf.filled().len() < length {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        match this.decrypt_chunk(&data, count) {
            Ok(decrypted) => {
                let to_copy = std::cmp::min(decrypted.len(), buf.remaining());
                buf.put_slice(&decrypted[..to_copy]);
                if to_copy < decrypted.len() {
                    this.read_buf = decrypted[to_copy..].to_vec();
                    this.read_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();
        let count = this.write_count;
        this.write_count = this.write_count.wrapping_add(1);
        match this.encrypt_chunk(buf, count) {
            Ok(encrypted) => {
                match std::pin::Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
            Err(e) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
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
