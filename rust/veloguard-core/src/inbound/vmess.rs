use crate::config::InboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::inbound::InboundListener;
use crate::outbound::{OutboundManager, TargetAddr};
use crate::routing::Router;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use chacha20poly1305::ChaCha20Poly1305;
use dashmap::DashSet;
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
type HmacMd5 = Hmac<Md5>;
type Aes128CfbBufEnc = cfb_mode::BufEncryptor<aes::Aes128>;
type Aes128CfbBufDec = cfb_mode::BufDecryptor<aes::Aes128>;

const VMESS_AEAD_AUTH_LEN: usize = 16;
#[allow(dead_code)]
const VMESS_AEAD_NONCE_LEN: usize = 12;
const VMESS_TIME_WINDOW_SECS: i64 = 30; // 30 秒更安全，防止重放攻击
const VMESS_MAX_CHUNK_SIZE: usize = 16384; // 16 KB 最大块大小，防止 OOM
const VMESS_AUTH_ID_EXPIRY_SECS: u64 = 30; // AuthID 过期时间（30秒，与时间窗口一致）

// VMess security types (P & Sec 低 4 位)
const SECURITY_AES_128_GCM: u8 = 0x03;
const SECURITY_CHACHA20_POLY1305: u8 = 0x04;
const SECURITY_NONE: u8 = 0x05;

// ============================================================================
// VMess 模式宏（Legacy / AEAD 分开处理）
// ============================================================================

macro_rules! vmess_mode_str {
    (aead) => {
        "AEAD"
    };
    (legacy) => {
        "Legacy"
    };
}

macro_rules! vmess_response_keys {
    (aead, $request_key:expr, $request_iv:expr) => {{
        (
            Self::generate_response_body_key_aead($request_key),
            Self::generate_response_body_iv_aead($request_iv),
        )
    }};
    (legacy, $request_key:expr, $request_iv:expr) => {{
        (
            Self::generate_response_key_legacy($request_key),
            Self::generate_response_iv_legacy($request_iv),
        )
    }};
}

macro_rules! vmess_send_response_header {
    (aead, $stream:expr, $request_key:expr, $request_iv:expr, $response_header:expr) => {{
        Self::send_aead_response_header($stream, &$request_key, &$request_iv, $response_header)
            .await
    }};
    (legacy, $stream:expr, $response_key:expr, $response_iv:expr, $response_header:expr) => {{
        Self::send_legacy_response_header($stream, &$response_key, &$response_iv, $response_header)
            .await
    }};
}

macro_rules! vmess_build_stream {
    (aead, $stream:expr, $request_key:expr, $request_iv:expr, $response_key:expr, $response_iv:expr, $security:expr, $option:expr, $command:expr) => {{
        VmessStream::new_aead(
            $stream,
            $request_key,
            $request_iv,
            $response_key,
            $response_iv,
            $security,
            $option,
            $command,
        )
    }};
    (legacy, $stream:expr, $request_key:expr, $request_iv:expr, $response_key:expr, $response_iv:expr, $security:expr, $option:expr, $command:expr) => {{
        VmessStream::new_legacy(
            $stream,
            $request_key,
            $request_iv,
            $response_key,
            $response_iv,
            $security,
            $option,
            $command,
        )
    }};
}

#[derive(Debug, Clone)]
struct VmessUser {
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
    seen_auth_ids: Arc<DashSet<[u8; 16]>>,
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

        let seen_auth_ids: Arc<DashSet<[u8; 16]>> = Arc::new(DashSet::new());
        let cleanup_set = Arc::clone(&seen_auth_ids);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(VMESS_AUTH_ID_EXPIRY_SECS));
            loop {
                interval.tick().await;
                // 简单策略：定期清空（因为 AuthID 包含时间戳，过期的自然无法验证）
                cleanup_set.clear();
            }
        });

        Self {
            config,
            router,
            outbound_manager,
            cancel_token: CancellationToken::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            users: Arc::new(RwLock::new(users_map)),
            seen_auth_ids,
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
        )
        .map_err(|e| Error::network(format!("Failed to create socket: {}", e)))?;
        socket.set_reuse_address(true).ok();
        socket.set_nonblocking(true).ok();
        socket
            .bind(&addr.into())
            .map_err(|e| Error::network(format!("Failed to bind: {}", e)))?;
        socket
            .listen(1024)
            .map_err(|e| Error::network(format!("Failed to listen: {}", e)))?;
        let listener: TcpListener = TcpListener::from_std(socket.into())
            .map_err(|e| Error::network(format!("Failed to create listener: {}", e)))?;
        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let cancel_token = self.cancel_token.clone();
        let running = Arc::clone(&self.running);
        let users = Arc::clone(&self.users);
        let seen_auth_ids = Arc::clone(&self.seen_auth_ids);
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
                                let seen_auth_ids = Arc::clone(&seen_auth_ids);
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(
                                        stream, peer_addr, router, outbound_manager, users, seen_auth_ids
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
        seen_auth_ids: Arc<DashSet<[u8; 16]>>,
    ) -> Result<()> {
        // Read AuthID (16 bytes) - used by both AEAD and Legacy
        let mut auth_id = [0u8; 16];
        stream
            .read_exact(&mut auth_id)
            .await
            .map_err(|e| Error::network(format!("Failed to read auth_id: {}", e)))?;

        // 防重放攻击：检查 AuthID 是否已被使用
        if !seen_auth_ids.insert(auth_id) {
            return Err(Error::protocol(
                "Replay attack detected: AuthID already used",
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Try AEAD mode first
        // In AEAD mode, AuthID = AES-128-ECB(cmd_key, timestamp || random || crc32)
        // We need to try decrypting and validating the AuthID
        let users_read = users.read().await;
        let mut aead_match: Option<(VmessUser, i64)> = None;

        for user in users_read.values() {
            if let Some(ts) = Self::try_validate_aead_auth_id(&user.cmd_key, &auth_id, now) {
                aead_match = Some((user.clone(), ts));
                break;
            }
        }
        drop(users_read);

        if let Some((user, _matched_ts)) = aead_match {
            // AEAD mode confirmed
            return Self::handle_aead_connection(
                stream,
                peer_addr,
                router,
                outbound_manager,
                user,
                auth_id,
            )
            .await;
        }

        // Try Legacy mode (alterId > 0)
        // In Legacy mode, AuthID = HMAC-MD5(uuid, timestamp)
        let users_read = users.read().await;
        let mut legacy_match: Option<(VmessUser, i64)> = None;

        for user in users_read.values() {
            for offset in -VMESS_TIME_WINDOW_SECS..=VMESS_TIME_WINDOW_SECS {
                let ts = now + offset;
                let ts_bytes = ts.to_be_bytes();
                let mut mac =
                    <HmacMd5 as Mac>::new_from_slice(user.uuid.as_bytes()).expect("HMAC-MD5 new");
                mac.update(&ts_bytes);
                let calc = mac.finalize().into_bytes();
                if calc.as_slice() == auth_id {
                    legacy_match = Some((user.clone(), ts));
                    break;
                }
            }
            if legacy_match.is_some() {
                break;
            }
        }
        drop(users_read);

        if let Some((user, ts)) = legacy_match {
            return Self::handle_legacy_connection(
                stream,
                peer_addr,
                router,
                outbound_manager,
                user,
                ts,
            )
            .await;
        }

        Err(Error::protocol("No matching VMess user found"))
    }

    fn try_validate_aead_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16], now: i64) -> Option<i64> {
        use aes::cipher::{BlockDecrypt, KeyInit as AesKeyInit};
        use aes::Aes128;

        // Derive the AuthID encryption key using KDF
        let auth_id_key = kdf16_auth_id(cmd_key);

        let cipher = Aes128::new_from_slice(&auth_id_key).ok()?;
        let mut block = aes::Block::clone_from_slice(auth_id);
        cipher.decrypt_block(&mut block);

        let decrypted = block.as_slice();
        let ts = i64::from_be_bytes(decrypted[0..8].try_into().ok()?);

        // Check timestamp within window
        if (ts - now).abs() > VMESS_TIME_WINDOW_SECS {
            return None;
        }

        // Verify CRC32
        let received_crc = u32::from_be_bytes(decrypted[12..16].try_into().ok()?);
        let calculated_crc = crc32fast::hash(&decrypted[0..12]);
        if received_crc != calculated_crc {
            return None;
        }

        Some(ts)
    }

    async fn handle_aead_connection(
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        user: VmessUser,
        auth_id: [u8; 16],
    ) -> Result<()> {
        // ===========================
        // AEAD 模式说明
        // - AuthID: AES-128-ECB( KDF(cmd_key), timestamp || random || crc32 )
        // - 头部: AEAD 方式加密
        // - 数据: AEAD 分块加密 (AES-128-GCM / ChaCha20-Poly1305)
        // ===========================
        // Read AEAD header: encrypted_length[18] + nonce[8]
        let mut buf26 = [0u8; 26];
        stream
            .read_exact(&mut buf26)
            .await
            .map_err(|e| Error::network(format!("Failed to read AEAD header prefix: {}", e)))?;

        let mut encrypted_length = [0u8; 18];
        encrypted_length.copy_from_slice(&buf26[..18]);
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&buf26[18..]);

        // Decrypt header length
        let header_length =
            Self::decrypt_aead_length(&user.cmd_key, &auth_id, &nonce, &encrypted_length)?;

        // Read and decrypt header
        let mut encrypted_header = vec![0u8; header_length + VMESS_AEAD_AUTH_LEN];
        stream
            .read_exact(&mut encrypted_header)
            .await
            .map_err(|e| Error::network(format!("Failed to read AEAD header: {}", e)))?;

        let header = Self::decrypt_aead_header(&user.cmd_key, &auth_id, &nonce, &encrypted_header)?;

        if header.len() < 41 {
            return Err(Error::protocol("AEAD header too short"));
        }

        // Parse header fields
        let _version = header[0];
        let request_iv: [u8; 16] = header[1..17].try_into().unwrap();
        let request_key: [u8; 16] = header[17..33].try_into().unwrap();
        let response_header = header[33];
        let option = header[34];
        let padding_and_security = header[35];
        let _padding_len = padding_and_security >> 4;
        let security = padding_and_security & 0x0F;
        let _reserved = header[36];
        let command = header[37];
        let port = u16::from_be_bytes([header[38], header[39]]);
        let addr_type = header[40];

        let (target, _addr_end) = Self::parse_address(&header[40..], addr_type, port)?;

        // AEAD 响应体密钥派生（SHA256）
        let (response_key, response_iv) = vmess_response_keys!(aead, &request_key, &request_iv);

        let outbound_tag = router
            .match_outbound(Some(&target.host()), None, Some(target.port()), None)
            .await;
        tracing::info!(
            "VMess {} -> {} from {} ({})",
            target,
            outbound_tag,
            peer_addr,
            vmess_mode_str!(aead)
        );

        let outbound = outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        let tracked_conn = TrackedConnection::new_with_ip(
            "vmess".to_string(),
            outbound_tag.clone(),
            target.host(),
            None,
            target.port(),
            "VMess".to_string(),
            "tcp".to_string(),
            "VMess-AEAD".to_string(),
            target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);

        // Send AEAD response header
        vmess_send_response_header!(
            aead,
            &mut stream,
            request_key,
            request_iv,
            response_header
        )?;

        let vmess_stream = vmess_build_stream!(
            aead,
            stream,
            request_key,
            request_iv,
            response_key,
            response_iv,
            security,
            option,
            command
        );

        if let Err(e) = outbound
            .relay_tcp_with_connection(Box::new(vmess_stream), target.clone(), Some(conn_arc))
            .await
        {
            tracing::debug!("VMess AEAD relay error: {}", e);
        }
        tracker.untrack(&tracked.id);
        Ok(())
    }

    async fn handle_legacy_connection(
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        user: VmessUser,
        ts: i64,
    ) -> Result<()> {
        // ===========================
        // Legacy 模式说明
        // - AuthID: HMAC-MD5( uuid, timestamp )
        // - 头部: AES-128-CFB 解密
        // - 数据: AES-128-CFB 分块加密 + FNV1a 校验
        // ===========================
        // Derive IV for legacy: MD5(timestamp repeated 4 times)
        let mut iv_data = Vec::with_capacity(32);
        for _ in 0..4 {
            iv_data.extend_from_slice(&ts.to_be_bytes());
        }
        let mut hasher = Md5::new();
        hasher.update(&iv_data);
        let iv_md5 = hasher.finalize();
        let mut legacy_iv = [0u8; 16];
        legacy_iv.copy_from_slice(&iv_md5);

        // Create CFB decryptor for legacy header
        let mut cipher = Aes128CfbBufDec::new_from_slices(&user.cmd_key, &legacy_iv)
            .map_err(|e| Error::protocol(format!("Failed to create legacy cipher: {}", e)))?;

        // Read and decrypt header incrementally
        let mut dec_buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 64];

        // Read initial chunk
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| Error::network(format!("Failed to read legacy header: {}", e)))?;
        if n == 0 {
            return Err(Error::network("Connection closed".to_string()));
        }
        let mut chunk = tmp[..n].to_vec();
        cipher.decrypt(&mut chunk);
        dec_buf.extend_from_slice(&chunk);

        // Continue reading until we have enough data
        let mut expected_len = Self::legacy_header_length_hint(&dec_buf)?;
        while expected_len.is_none_or(|len| dec_buf.len() < len) {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| Error::network(format!("Failed to read legacy header: {}", e)))?;
            if n == 0 {
                return Err(Error::network(
                    "Connection closed while reading legacy header".to_string(),
                ));
            }
            let mut chunk = tmp[..n].to_vec();
            cipher.decrypt(&mut chunk);
            dec_buf.extend_from_slice(&chunk);
            if dec_buf.len() > 1024 {
                return Err(Error::protocol("Legacy header too large"));
            }
            if expected_len.is_none() {
                expected_len = Self::legacy_header_length_hint(&dec_buf)?;
            }
        }

        let total_len = expected_len.unwrap();
        if dec_buf.len() < total_len {
            return Err(Error::protocol("Legacy header incomplete"));
        }

        let (
            request_iv,
            request_key,
            response_header,
            option,
            security,
            command,
            target,
            _consumed,
        ) = Self::parse_legacy_header(&dec_buf[..total_len])?;

        // Legacy 响应密钥派生（MD5）
        let (response_key, response_iv) = vmess_response_keys!(legacy, &request_key, &request_iv);

        let outbound_tag = router
            .match_outbound(Some(&target.host()), None, Some(target.port()), None)
            .await;
        tracing::info!(
            "VMess {} -> {} from {} ({})",
            target,
            outbound_tag,
            peer_addr,
            vmess_mode_str!(legacy)
        );

        let outbound = outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        let tracked_conn = TrackedConnection::new_with_ip(
            "vmess".to_string(),
            outbound_tag.clone(),
            target.host(),
            None,
            target.port(),
            "VMess".to_string(),
            "tcp".to_string(),
            "VMess-Legacy".to_string(),
            target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);

        // Send Legacy response header (CFB encrypted)
        vmess_send_response_header!(
            legacy,
            &mut stream,
            response_key,
            response_iv,
            response_header
        )?;

        let vmess_stream = vmess_build_stream!(
            legacy,
            stream,
            request_key,
            request_iv,
            response_key,
            response_iv,
            security,
            option,
            command
        );

        if let Err(e) = outbound
            .relay_tcp_with_connection(Box::new(vmess_stream), target.clone(), Some(conn_arc))
            .await
        {
            tracing::debug!("VMess Legacy relay error: {}", e);
        }
        tracker.untrack(&tracked.id);
        Ok(())
    }

    fn decrypt_aead_length(
        cmd_key: &[u8; 16],
        auth_id: &[u8; 16],
        nonce: &[u8; 8],
        data: &[u8; 18],
    ) -> Result<usize> {
        let length_key = kdf16_vmess_aead(cmd_key, b"VMess Header AEAD Key_Length", auth_id, nonce);
        let length_nonce =
            kdf12_vmess_aead(cmd_key, b"VMess Header AEAD Nonce_Length", auth_id, nonce);
        let cipher = Aes128Gcm::new_from_slice(&length_key)
            .map_err(|e| Error::protocol(format!("Failed to create length cipher: {}", e)))?;
        let nonce_obj = Nonce::from_slice(&length_nonce);
        use aes_gcm::aead::Payload;
        let decrypted = cipher
            .decrypt(
                nonce_obj,
                Payload {
                    msg: data,
                    aad: auth_id,
                },
            )
            .map_err(|e| Error::protocol(format!("Failed to decrypt length: {}", e)))?;
        if decrypted.len() != 2 {
            return Err(Error::protocol("Invalid length decryption result"));
        }
        Ok(u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize)
    }

    fn decrypt_aead_header(
        cmd_key: &[u8; 16],
        auth_id: &[u8; 16],
        nonce: &[u8; 8],
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let header_key = kdf16_vmess_aead(cmd_key, b"VMess Header AEAD Key", auth_id, nonce);
        let header_nonce = kdf12_vmess_aead(cmd_key, b"VMess Header AEAD Nonce", auth_id, nonce);
        let cipher = Aes128Gcm::new_from_slice(&header_key)
            .map_err(|e| Error::protocol(format!("Failed to create header cipher: {}", e)))?;
        let nonce_obj = Nonce::from_slice(&header_nonce);
        use aes_gcm::aead::Payload;
        cipher
            .decrypt(
                nonce_obj,
                Payload {
                    msg: data,
                    aad: auth_id,
                },
            )
            .map_err(|e| Error::protocol(format!("Failed to decrypt header: {}", e)))
    }

    fn legacy_header_length_hint(decrypted: &[u8]) -> Result<Option<usize>> {
        if decrypted.len() < 41 {
            return Ok(None);
        }
        let padding_len = decrypted[35] >> 4;
        let addr_type = decrypted[40];
        let addr_len = match addr_type {
            0x01 => 4,  // IPv4
            0x03 => 16, // IPv6
            0x02 => {
                // Domain
                if decrypted.len() < 42 {
                    return Ok(None);
                }
                let len = decrypted[41] as usize;
                1 + len
            }
            _ => {
                return Err(Error::protocol(format!(
                    "Unknown address type: {}",
                    addr_type
                )))
            }
        };

        // Header structure: version[1] + iv[16] + key[16] + response_header[1] + option[1] +
        // padding_security[1] + reserved[1] + command[1] + port[2] + addr_type[1] + addr[addr_len] +
        // padding[padding_len] + fnv[4]
        let total_len = 41 + addr_len + padding_len as usize + 4;
        Ok(Some(total_len))
    }

    #[allow(clippy::type_complexity)]
    fn parse_legacy_header(
        decrypted: &[u8],
    ) -> Result<([u8; 16], [u8; 16], u8, u8, u8, u8, TargetAddr, usize)> {
        if decrypted.len() < 41 {
            return Err(Error::protocol("Legacy header too short"));
        }

        let _version = decrypted[0];
        let request_iv: [u8; 16] = decrypted[1..17].try_into().unwrap();
        let request_key: [u8; 16] = decrypted[17..33].try_into().unwrap();
        let response_header = decrypted[33];
        let option = decrypted[34];
        let padding_and_security = decrypted[35];
        let padding_len = padding_and_security >> 4;
        let security = padding_and_security & 0x0F;
        let _reserved = decrypted[36];
        let command = decrypted[37];
        let port = u16::from_be_bytes([decrypted[38], decrypted[39]]);
        let addr_type = decrypted[40];

        let (target, addr_consumed) = Self::parse_address(&decrypted[40..], addr_type, port)?;
        let padding_start = 41 + addr_consumed;
        let total_len = padding_start + padding_len as usize + 4;
        if decrypted.len() < total_len {
            return Err(Error::protocol("Legacy header truncated"));
        }

        // Verify FNV1a checksum
        let fnv_start = total_len - 4;
        let received_fnv = u32::from_be_bytes(decrypted[fnv_start..total_len].try_into().unwrap());
        let calculated_fnv = fnv1a_hash(&decrypted[..fnv_start]);
        if received_fnv != calculated_fnv {
            return Err(Error::protocol(format!(
                "VMess legacy FNV mismatch: received={:#x}, calculated={:#x}",
                received_fnv, calculated_fnv
            )));
        }

        Ok((
            request_iv,
            request_key,
            response_header,
            option,
            security,
            command,
            target,
            total_len,
        ))
    }

    fn parse_address(data: &[u8], addr_type: u8, port: u16) -> Result<(TargetAddr, usize)> {
        match addr_type {
            0x01 => {
                // IPv4
                if data.len() < 5 {
                    return Err(Error::protocol("IPv4 address too short"));
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                Ok((TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 5))
            }
            0x02 => {
                // Domain
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
                // IPv6
                if data.len() < 17 {
                    return Err(Error::protocol("IPv6 address too short"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = Ipv6Addr::from(octets);
                Ok((TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port)), 17))
            }
            _ => Err(Error::protocol(format!(
                "Unknown address type: {}",
                addr_type
            ))),
        }
    }

    // AEAD mode: use SHA256 for response body key derivation
    // 响应体密钥 = SHA256(request_key)[:16]
    fn generate_response_body_key_aead(request_key: &[u8; 16]) -> [u8; 16] {
        let result = sha256_hash(request_key);
        let mut key = [0u8; 16];
        key.copy_from_slice(&result[..16]);
        key
    }

    // AEAD mode: use SHA256 for response body IV derivation
    // 响应体 IV = SHA256(request_iv)[:16]
    fn generate_response_body_iv_aead(request_iv: &[u8; 16]) -> [u8; 16] {
        let result = sha256_hash(request_iv);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&result[..16]);
        iv
    }

    // Legacy mode: use MD5 for response key/iv derivation
    fn generate_response_key_legacy(request_key: &[u8; 16]) -> [u8; 16] {
        let mut hasher = Md5::new();
        hasher.update(request_key);
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result);
        key
    }

    fn generate_response_iv_legacy(request_iv: &[u8; 16]) -> [u8; 16] {
        let mut hasher = Md5::new();
        hasher.update(request_iv);
        let result = hasher.finalize();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&result);
        iv
    }

    async fn send_aead_response_header<W: AsyncWrite + Unpin>(
        stream: &mut W,
        request_key: &[u8; 16],
        request_iv: &[u8; 16],
        response_header: u8,
    ) -> Result<()> {
        let header = [response_header, 0x00, 0x00, 0x00];

        // Encrypt response header length (2 bytes)
        let length_key = kdf(request_key, &[b"AEAD Resp Header Len Key"]);
        let length_iv = kdf(request_iv, &[b"AEAD Resp Header Len IV"]);
        let length_cipher = Aes128Gcm::new_from_slice(&length_key[..16]).map_err(|e| {
            Error::protocol(format!("Failed to create AEAD response length cipher: {}", e))
        })?;
        let length_encrypted = length_cipher
            .encrypt(Nonce::from_slice(&length_iv[..12]), header.len().to_be_bytes().as_ref())
            .map_err(|e| {
                Error::protocol(format!("Failed to encrypt AEAD response length: {}", e))
            })?;

        // Encrypt response header payload
        let header_key = kdf(request_key, &[b"AEAD Resp Header Key"]);
        let header_iv = kdf(request_iv, &[b"AEAD Resp Header IV"]);
        let cipher = Aes128Gcm::new_from_slice(&header_key[..16]).map_err(|e| {
            Error::protocol(format!("Failed to create AEAD response cipher: {}", e))
        })?;
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&header_iv[..12]), header.as_slice())
            .map_err(|e| Error::protocol(format!("Failed to encrypt AEAD response: {}", e)))?;

        stream
            .write_all(&length_encrypted)
            .await
            .map_err(|e| Error::network(format!("Failed to write AEAD response length: {}", e)))?;
        stream
            .write_all(&encrypted)
            .await
            .map_err(|e| Error::network(format!("Failed to write AEAD response: {}", e)))?;
        Ok(())
    }

    async fn send_legacy_response_header<W: AsyncWrite + Unpin>(
        stream: &mut W,
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
        response_header: u8,
    ) -> Result<()> {
        let header = [response_header, 0x00, 0x00, 0x00];
        let cipher = cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(response_key, response_iv)
            .map_err(|e| {
                Error::protocol(format!("Failed to create legacy response cipher: {}", e))
            })?;
        let mut encrypted = header.to_vec();
        cipher.encrypt(&mut encrypted);
        stream
            .write_all(&encrypted)
            .await
            .map_err(|e| Error::network(format!("Failed to write legacy response: {}", e)))?;
        Ok(())
    }
}

// Helper functions

fn generate_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let result = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result);
    key
}

/// VMess AEAD KDF 函数
///
/// 根据 VMess AEAD 协议规范，KDF 使用递归 HMAC-SHA256：
/// K1 = HMAC("VMess AEAD KDF", key)  // "VMess AEAD KDF" 作为 HMAC 密钥
/// K2 = HMAC(K1, path[0])
/// K3 = HMAC(K2, path[1])
/// ...
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    // K1 = HMAC("VMess AEAD KDF", key)
    let mut current_key = {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(b"VMess AEAD KDF")
            .expect("HMAC can take key of any size");
        mac.update(key);
        mac.finalize().into_bytes()
    };

    // K(n+1) = HMAC(K(n), path[n])
    for p in path {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&current_key)
            .expect("HMAC can take key of any size");
        mac.update(p);
        current_key = mac.finalize().into_bytes();
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&current_key);
    result
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn kdf16_auth_id(cmd_key: &[u8; 16]) -> [u8; 16] {
    let result = kdf(cmd_key, &[b"AES Auth ID Encryption"]);
    let mut output = [0u8; 16];
    output.copy_from_slice(&result[..16]);
    output
}

fn kdf16_vmess_aead(key: &[u8], label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 16] {
    let result = kdf(key, &[label, auth_id, nonce]);
    let mut output = [0u8; 16];
    output.copy_from_slice(&result[..16]);
    output
}

fn kdf12_vmess_aead(key: &[u8], label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 12] {
    let result = kdf(key, &[label, auth_id, nonce]);
    let mut output = [0u8; 12];
    output.copy_from_slice(&result[..12]);
    output
}

fn fnv1a_hash(data: &[u8]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// VmessStream implementation with proper state machine for reading

/// Read state for VmessStream
enum ReadState {
    /// Waiting to read length prefix
    ReadingLength { buf: [u8; 2], pos: usize },
    /// Waiting to read chunk data
    ReadingData {
        length: usize,
        buf: Vec<u8>,
        pos: usize,
    },
}

/// Write state for VmessStream - 处理部分写入
struct WriteBuffer {
    data: Vec<u8>,
    written: usize,
    original_len: usize, // 原始明文长度，用于返回给调用者
}

struct VmessStream {
    inner: tokio::net::TcpStream,
    request_key: [u8; 16],
    request_iv: [u8; 16],
    response_key: [u8; 16],
    response_iv: [u8; 16],
    security: u8,
    is_aead: bool,
    read_count: u16,
    write_count: u16,
    // Decrypted data buffer
    read_buf: Vec<u8>,
    read_pos: usize,
    // Read state machine
    read_state: ReadState,
    // Write buffer for partial writes
    write_buffer: Option<WriteBuffer>,
    // Legacy mode ciphers
    legacy_enc: Option<Aes128CfbBufEnc>,
    legacy_dec: Option<Aes128CfbBufDec>,
}

impl VmessStream {
    #[allow(clippy::too_many_arguments)]
    fn new_aead(
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
            inner,
            request_key,
            request_iv,
            response_key,
            response_iv,
            security,
            is_aead: true,
            read_count: 0,
            write_count: 0,
            read_buf: Vec::new(),
            read_pos: 0,
            read_state: ReadState::ReadingLength {
                buf: [0u8; 2],
                pos: 0,
            },
            write_buffer: None,
            legacy_enc: None,
            legacy_dec: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_legacy(
        inner: tokio::net::TcpStream,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
        security: u8,
        _option: u8,
        _command: u8,
    ) -> Self {
        // Legacy mode uses CFB for data encryption
        let enc = Aes128CfbBufEnc::new_from_slices(&response_key, &response_iv)
            .expect("Legacy response cipher init failed");
        let dec = Aes128CfbBufDec::new_from_slices(&request_key, &request_iv)
            .expect("Legacy request cipher init failed");

        Self {
            inner,
            request_key,
            request_iv,
            response_key,
            response_iv,
            security,
            is_aead: false,
            read_count: 0,
            write_count: 0,
            read_buf: Vec::new(),
            read_pos: 0,
            read_state: ReadState::ReadingLength {
                buf: [0u8; 2],
                pos: 0,
            },
            write_buffer: None,
            legacy_enc: Some(enc),
            legacy_dec: Some(dec),
        }
    }

    fn decrypt_aead_chunk(&self, data: &[u8], count: u16) -> Result<Vec<u8>> {
        match self.security {
            SECURITY_AES_128_GCM => {
                // AES-128-GCM
                let cipher = Aes128Gcm::new_from_slice(&self.request_key)
                    .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
                // VMess 协议：nonce = count(2B) + iv[2..12]
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[0..2].copy_from_slice(&count.to_be_bytes());
                nonce_bytes[2..12].copy_from_slice(&self.request_iv[2..12]);
                let nonce = Nonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, data)
                    .map_err(|e| Error::protocol(format!("Decrypt error: {}", e)))
            }
            SECURITY_CHACHA20_POLY1305 => {
                // ChaCha20-Poly1305
                // VMess 协议：ChaCha20 key = MD5(key) + MD5(MD5(key))
                let md5_key = {
                    let mut hasher = Md5::new();
                    hasher.update(self.request_key);
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

                let cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                    .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
                // VMess 协议：nonce = count(2B) + iv[2..12]
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[0..2].copy_from_slice(&count.to_be_bytes());
                nonce_bytes[2..12].copy_from_slice(&self.request_iv[2..12]);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, data)
                    .map_err(|e| Error::protocol(format!("Decrypt error: {}", e)))
            }
            SECURITY_NONE => {
                // 0x05: None (no encryption)
                Ok(data.to_vec())
            }
            _ => Ok(data.to_vec()),
        }
    }

    fn encrypt_aead_chunk(&self, data: &[u8], count: u16) -> Result<Vec<u8>> {
        match self.security {
            SECURITY_AES_128_GCM => {
                // AES-128-GCM
                let cipher = Aes128Gcm::new_from_slice(&self.response_key)
                    .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
                // VMess 协议：nonce = count(2B) + iv[2..12]
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[0..2].copy_from_slice(&count.to_be_bytes());
                nonce_bytes[2..12].copy_from_slice(&self.response_iv[2..12]);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher
                    .encrypt(nonce, data)
                    .map_err(|e| Error::protocol(format!("Encrypt error: {}", e)))?;
                let mut result = Vec::with_capacity(2 + encrypted.len());
                result.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
                result.extend_from_slice(&encrypted);
                Ok(result)
            }
            SECURITY_CHACHA20_POLY1305 => {
                // ChaCha20-Poly1305
                // VMess 协议：ChaCha20 key = MD5(key) + MD5(MD5(key))
                let md5_key = {
                    let mut hasher = Md5::new();
                    hasher.update(self.response_key);
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

                let cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                    .map_err(|e| Error::protocol(format!("Cipher error: {}", e)))?;
                // VMess 协议：nonce = count(2B) + iv[2..12]
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[0..2].copy_from_slice(&count.to_be_bytes());
                nonce_bytes[2..12].copy_from_slice(&self.response_iv[2..12]);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher
                    .encrypt(nonce, data)
                    .map_err(|e| Error::protocol(format!("Encrypt error: {}", e)))?;
                let mut result = Vec::with_capacity(2 + encrypted.len());
                result.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
                result.extend_from_slice(&encrypted);
                Ok(result)
            }
            SECURITY_NONE => {
                // No encryption
                let mut result = Vec::with_capacity(2 + data.len());
                result.extend_from_slice(&(data.len() as u16).to_be_bytes());
                result.extend_from_slice(data);
                Ok(result)
            }
            _ => {
                // Unknown security -> passthrough
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

        // Return buffered data first
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

        let this = self.get_mut();

        loop {
            match &mut this.read_state {
                ReadState::ReadingLength { buf: len_buf, pos } => {
                    // Read remaining bytes for length
                    while *pos < 2 {
                        let mut tmp_buf = [0u8; 2];
                        let remaining = 2 - *pos;
                        let mut read_buf = tokio::io::ReadBuf::new(&mut tmp_buf[..remaining]);
                        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    // EOF
                                    return Poll::Ready(Ok(()));
                                }
                                len_buf[*pos..*pos + n].copy_from_slice(read_buf.filled());
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Got full length
                    let mut length_bytes = *len_buf;

                    // For legacy mode, decrypt the length
                    if !this.is_aead {
                        if let Some(cipher) = this.legacy_dec.as_mut() {
                            cipher.decrypt(&mut length_bytes);
                        }
                    }

                    let length = u16::from_be_bytes(length_bytes) as usize;

                    if length == 0 {
                        // End of stream
                        this.read_state = ReadState::ReadingLength {
                            buf: [0u8; 2],
                            pos: 0,
                        };
                        return Poll::Ready(Ok(()));
                    }

                    // 检查块大小限制，防止 OOM
                    if length > VMESS_MAX_CHUNK_SIZE {
                        return Poll::Ready(Err(std::io::Error::other(format!(
                            "Chunk too large: {} > {}",
                            length, VMESS_MAX_CHUNK_SIZE
                        ))));
                    }

                    // Transition to reading data
                    this.read_state = ReadState::ReadingData {
                        length,
                        buf: vec![0u8; length],
                        pos: 0,
                    };
                }

                ReadState::ReadingData {
                    length,
                    buf: data_buf,
                    pos,
                } => {
                    // Read remaining bytes for data
                    while *pos < *length {
                        let remaining = *length - *pos;
                        let mut read_buf = tokio::io::ReadBuf::new(&mut data_buf[*pos..]);
                        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    // Unexpected EOF
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        format!("Expected {} more bytes, got EOF", remaining),
                                    )));
                                }
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Got full data, decrypt it
                    let data = std::mem::take(data_buf);
                    let _length = *length;

                    let decrypted = if !this.is_aead {
                        // Legacy mode: decrypt with CFB and verify FNV checksum
                        let mut decrypted_data = data;
                        if let Some(cipher) = this.legacy_dec.as_mut() {
                            cipher.decrypt(&mut decrypted_data);
                        }

                        if decrypted_data.len() < 4 {
                            return Poll::Ready(Err(std::io::Error::other(
                                "Legacy chunk too short",
                            )));
                        }

                        let received_checksum =
                            u32::from_be_bytes(decrypted_data[..4].try_into().unwrap());
                        let payload = decrypted_data[4..].to_vec();
                        let calculated_checksum = fnv1a_hash(&payload);

                        if received_checksum != calculated_checksum {
                            return Poll::Ready(Err(std::io::Error::other(
                                "Legacy checksum mismatch",
                            )));
                        }

                        payload
                    } else {
                        // AEAD mode
                        let count = this.read_count;
                        this.read_count = this.read_count.wrapping_add(1);

                        match this.decrypt_aead_chunk(&data, count) {
                            Ok(d) => d,
                            Err(e) => {
                                return Poll::Ready(Err(std::io::Error::other(e.to_string())))
                            }
                        }
                    };

                    // Reset state for next chunk
                    this.read_state = ReadState::ReadingLength {
                        buf: [0u8; 2],
                        pos: 0,
                    };

                    // Return decrypted data
                    let to_copy = std::cmp::min(decrypted.len(), buf.remaining());
                    buf.put_slice(&decrypted[..to_copy]);

                    if to_copy < decrypted.len() {
                        this.read_buf = decrypted[to_copy..].to_vec();
                        this.read_pos = 0;
                    }

                    return Poll::Ready(Ok(()));
                }
            }
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

        // 如果有未完成的写缓冲，先完成它
        if let Some(ref mut wb) = this.write_buffer {
            while wb.written < wb.data.len() {
                match std::pin::Pin::new(&mut this.inner).poll_write(cx, &wb.data[wb.written..]) {
                    Poll::Ready(Ok(0)) => {
                        this.write_buffer = None;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "Failed to write encrypted data: write returned 0",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        wb.written += n;
                    }
                    Poll::Ready(Err(e)) => {
                        this.write_buffer = None;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            // 缓冲写完了
            let original_len = wb.original_len;
            this.write_buffer = None;
            return Poll::Ready(Ok(original_len));
        }

        let encrypted = if !this.is_aead {
            // Legacy mode: CFB encrypted chunks with FNV checksum
            let cipher = this.legacy_enc.as_mut().expect("Legacy encryptor missing");
            let checksum = fnv1a_hash(buf);
            let chunk_len = (4 + buf.len()) as u16; // 转换为 u16
            let mut plaintext = Vec::with_capacity(2 + chunk_len as usize);
            plaintext.extend_from_slice(&chunk_len.to_be_bytes());
            plaintext.extend_from_slice(&checksum.to_be_bytes());
            plaintext.extend_from_slice(buf);
            cipher.encrypt(&mut plaintext);
            plaintext
        } else {
            // AEAD mode
            let count = this.write_count;
            this.write_count = this.write_count.wrapping_add(1);
            match this.encrypt_aead_chunk(buf, count) {
                Ok(enc) => enc,
                Err(e) => return Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            }
        };

        // 尝试写入加密数据
        let mut written = 0;
        while written < encrypted.len() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &encrypted[written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Failed to write encrypted data: write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    written += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if written > 0 {
                        // 部分写入后 Pending，缓存剩余数据
                        this.write_buffer = Some(WriteBuffer {
                            data: encrypted,
                            written,
                            original_len: buf.len(),
                        });
                    }
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(buf.len()))
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
