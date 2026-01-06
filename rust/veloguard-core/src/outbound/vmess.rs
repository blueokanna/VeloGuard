use crate::config::OutboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

const VMESS_VERSION: u8 = 1;
const VMESS_AEAD_AUTH_LEN: usize = 16;
const VMESS_AEAD_NONCE_LEN: usize = 12;

#[allow(dead_code)]
const VMESS_AEAD_KEY_LEN: usize = 16;

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
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

impl VmessCipher {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" | "aes128gcm" => VmessCipher::Aes128Gcm,
            "chacha20-poly1305" | "chacha20poly1305" => VmessCipher::Chacha20Poly1305,
            "none" => VmessCipher::None,
            "zero" => VmessCipher::Zero,
            _ => VmessCipher::Auto,
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            VmessCipher::Aes128Gcm => 0x03,
            VmessCipher::Chacha20Poly1305 => 0x04,
            VmessCipher::None => 0x02,
            VmessCipher::Zero => 0x05,
            VmessCipher::Auto => 0x03,
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

pub struct VmessOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    uuid: Uuid,
    uuid_bytes: [u8; 16],
    #[allow(dead_code)]
    alter_id: u16,
    cipher: VmessCipher,
    udp_enabled: bool,
    cmd_key: [u8; 16],
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

        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|e| Error::config(format!("Invalid UUID: {}", e)))?;

        let uuid_bytes = *uuid.as_bytes();

        let alter_id = config
            .options
            .get("alterId")
            .or_else(|| config.options.get("alter-id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as u16;

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
            .unwrap_or(false);

        let cmd_key = generate_cmd_key(&uuid_bytes);

        Ok(Self {
            config,
            server,
            port,
            uuid,
            uuid_bytes,
            alter_id,
            cipher,
            udp_enabled,
            cmd_key,
        })
    }

    pub fn generate_auth_id(&self, timestamp: i64) -> [u8; 16] {
        let mut hasher = Md5::new();
        hasher.update(self.uuid_bytes);
        hasher.update(timestamp.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        let result = hasher.finalize();
        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&result);
        auth_id
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
        let mut hasher = Sha256::new();
        hasher.update(request_key);
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result[..16]);
        key
    }

    fn generate_response_iv(&self, request_iv: &[u8; 16]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(request_iv);
        let result = hasher.finalize();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&result[..16]);
        iv
    }

    pub fn seal_header(&self, header: &VmessHeader, timestamp: i64) -> Result<Vec<u8>> {
        let mut header_buf = Vec::with_capacity(128);

        header_buf.push(header.version);
        header_buf.extend_from_slice(&header.request_body_iv);
        header_buf.extend_from_slice(&header.request_body_key);
        header_buf.push(header.response_header);
        header_buf.push(header.option.bits());

        let padding_and_security = (header.padding_length << 4) | header.security.as_byte();
        header_buf.push(padding_and_security);
        header_buf.push(0x00);
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

        let auth_id = self.generate_auth_id(timestamp);
        let connection_nonce = generate_connection_nonce();

        let header_key = kdf16(&self.cmd_key, &[b"VMess Header AEAD Key", &auth_id, &connection_nonce]);
        let header_nonce = kdf12(&self.cmd_key, &[b"VMess Header AEAD Nonce", &auth_id, &connection_nonce]);

        let cipher = Aes128Gcm::new_from_slice(&header_key)
            .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;
        let nonce = Nonce::from_slice(&header_nonce);

        let encrypted_header = cipher
            .encrypt(nonce, header_buf.as_ref())
            .map_err(|e| Error::protocol(format!("Failed to encrypt header: {}", e)))?;

        let header_length_key = kdf16(&self.cmd_key, &[b"VMess Header AEAD Key Length", &auth_id, &connection_nonce]);
        let header_length_nonce = kdf12(&self.cmd_key, &[b"VMess Header AEAD Nonce Length", &auth_id, &connection_nonce]);

        let length_cipher = Aes128Gcm::new_from_slice(&header_length_key)
            .map_err(|e| Error::protocol(format!("Failed to create length cipher: {}", e)))?;
        let length_nonce = Nonce::from_slice(&header_length_nonce);

        let length_bytes = (encrypted_header.len() as u16).to_be_bytes();
        let encrypted_length = length_cipher
            .encrypt(length_nonce, length_bytes.as_ref())
            .map_err(|e| Error::protocol(format!("Failed to encrypt length: {}", e)))?;

        let mut result = Vec::with_capacity(16 + 8 + encrypted_length.len() + encrypted_header.len());
        result.extend_from_slice(&auth_id);
        result.extend_from_slice(&encrypted_length);
        result.extend_from_slice(&connection_nonce);
        result.extend_from_slice(&encrypted_header);

        Ok(result)
    }

    pub fn open_response_header(
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
        let stream = TcpStream::connect(&addr).await.map_err(|e| {
            Error::network(format!("Failed to connect to VMess server {}: {}", addr, e))
        })?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        cmd: VmessCommand,
    ) -> Result<([u8; 16], [u8; 16], u8)> {
        let request_key = self.generate_request_key();
        let request_iv = self.generate_request_iv();
        let response_header_byte: u8 = rand::random();

        let (address_type, address_bytes) = match target {
            TargetAddr::Domain(domain, _) => {
                let mut bytes = Vec::with_capacity(domain.len() + 1);
                bytes.push(domain.len() as u8);
                bytes.extend_from_slice(domain.as_bytes());
                (VmessAddressType::Domain, bytes)
            }
            TargetAddr::Ip(addr) => match addr {
                std::net::SocketAddr::V4(v4) => {
                    (VmessAddressType::Ipv4, v4.ip().octets().to_vec())
                }
                std::net::SocketAddr::V6(v6) => {
                    (VmessAddressType::Ipv6, v6.ip().octets().to_vec())
                }
            },
        };

        let header = VmessHeader {
            version: VMESS_VERSION,
            request_body_iv: request_iv,
            request_body_key: request_key,
            response_header: response_header_byte,
            option: VmessOption::CHUNK_STREAM | VmessOption::CHUNK_MASKING | VmessOption::GLOBAL_PADDING | VmessOption::AUTHENTICATED_LENGTH,
            padding_length: rand::random::<u8>() % 16,
            security: self.cipher,
            command: cmd,
            port: target.port(),
            address_type,
            address: address_bytes,
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let sealed_header = self.seal_header(&header, timestamp)?;

        stream.write_all(&sealed_header).await.map_err(|e| {
            Error::network(format!("Failed to send VMess header: {}", e))
        })?;
        stream.flush().await.ok();

        tracing::debug!("VMess handshake sent for target: {}", target);

        Ok((request_key, request_iv, response_header_byte))
    }

    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    pub async fn relay_udp(
        &self,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config("UDP relay is not enabled for this VMess proxy"));
        }

        let mut stream = self.connect_tcp().await?;
        let (request_key, request_iv, _response_header) = 
            self.handshake(&mut stream, target, VmessCommand::Udp).await?;

        let encrypted_data = self.encrypt_chunk(data, &request_key, &request_iv, 0)?;
        stream.write_all(&encrypted_data).await.map_err(|e| {
            Error::network(format!("Failed to send UDP data: {}", e))
        })?;
        stream.flush().await.ok();

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        let timeout = std::time::Duration::from_secs(30);
        let response = tokio::time::timeout(timeout, self.read_response_chunk(&mut stream, &response_key, &response_iv))
            .await
            .map_err(|_| Error::network("UDP receive timeout"))?
            .map_err(|e| Error::network(format!("Failed to receive UDP response: {}", e)))?;

        Ok(response)
    }

    fn encrypt_chunk(&self, data: &[u8], key: &[u8; 16], iv: &[u8; 16], count: u16) -> Result<Vec<u8>> {
        match self.cipher {
            VmessCipher::Aes128Gcm | VmessCipher::Auto => {
                self.encrypt_aes_gcm(data, key, iv, count)
            }
            VmessCipher::Chacha20Poly1305 => {
                self.encrypt_chacha20(data, key, iv, count)
            }
            VmessCipher::None | VmessCipher::Zero => {
                let mut result = Vec::with_capacity(2 + data.len());
                result.extend_from_slice(&(data.len() as u16).to_be_bytes());
                result.extend_from_slice(data);
                Ok(result)
            }
        }
    }

    fn encrypt_aes_gcm(&self, data: &[u8], key: &[u8; 16], iv: &[u8; 16], count: u16) -> Result<Vec<u8>> {
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

    fn encrypt_chacha20(&self, data: &[u8], key: &[u8; 16], iv: &[u8; 16], count: u16) -> Result<Vec<u8>> {
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

    fn decrypt_chunk(&self, data: &[u8], key: &[u8; 16], iv: &[u8; 16], count: u16) -> Result<Vec<u8>> {
        match self.cipher {
            VmessCipher::Aes128Gcm | VmessCipher::Auto => {
                self.decrypt_aes_gcm(data, key, iv, count)
            }
            VmessCipher::Chacha20Poly1305 => {
                self.decrypt_chacha20(data, key, iv, count)
            }
            VmessCipher::None | VmessCipher::Zero => {
                Ok(data.to_vec())
            }
        }
    }

    fn decrypt_aes_gcm(&self, data: &[u8], key: &[u8; 16], iv: &[u8; 16], count: u16) -> Result<Vec<u8>> {
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

    fn decrypt_chacha20(&self, data: &[u8], key: &[u8; 16], iv: &[u8; 16], count: u16) -> Result<Vec<u8>> {
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

    async fn read_response_chunk<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>> {
        let mut length_buf = [0u8; 2];
        stream.read_exact(&mut length_buf).await.map_err(|e| {
            Error::network(format!("Failed to read chunk length: {}", e))
        })?;

        let length = u16::from_be_bytes(length_buf) as usize;
        if length == 0 {
            return Ok(Vec::new());
        }

        let mut data = vec![0u8; length];
        stream.read_exact(&mut data).await.map_err(|e| {
            Error::network(format!("Failed to read chunk data: {}", e))
        })?;

        self.decrypt_chunk(&data, key, iv, 0)
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
        let path = if url.path().is_empty() { "/" } else { url.path() };

        let start = Instant::now();

        let mut stream = tokio::time::timeout(timeout, self.connect_tcp())
            .await
            .map_err(|_| Error::network("Connection timeout"))?
            .map_err(|e| Error::network(format!("TCP connection failed: {}", e)))?;

        let target = TargetAddr::Domain(host.clone(), url_port);
        let (request_key, request_iv, _) = self.handshake(&mut stream, &target, VmessCommand::Tcp).await?;

        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: VeloGuard/1.0\r\n\r\n",
            path, host
        );

        let encrypted_request = self.encrypt_chunk(http_request.as_bytes(), &request_key, &request_iv, 0)?;
        stream.write_all(&encrypted_request).await.map_err(|e| {
            Error::network(format!("Failed to send HTTP request: {}", e))
        })?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        let result = tokio::time::timeout(timeout, async {
            let response = self.read_response_chunk(&mut stream, &response_key, &response_iv).await?;
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
        let mut stream = self.connect_tcp().await?;
        let (request_key, request_iv, _response_header) = 
            self.handshake(&mut stream, &target, VmessCommand::Tcp).await?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        tracing::debug!(
            "VMess: relaying TCP to {} via {}:{}",
            target,
            self.server,
            self.port
        );

        let tracker = global_tracker();
        let (mut ri, mut wi) = tokio::io::split(inbound);
        let (mut ro, mut wo) = tokio::io::split(stream);

        let cipher = self.cipher;
        let conn_upload = connection.clone();
        let conn_download = connection.clone();

        let client_to_remote = async {
            let mut buf = vec![0u8; 16 * 1024];
            let mut count: u16 = 0;
            loop {
                let n = ri.read(&mut buf).await.map_err(|e| {
                    Error::network(format!("Failed to read from inbound: {}", e))
                })?;
                if n == 0 {
                    let end_chunk = [0u8; 2];
                    wo.write_all(&end_chunk).await.ok();
                    break;
                }

                let encrypted = encrypt_chunk_static(cipher, &buf[..n], &request_key, &request_iv, count)?;
                wo.write_all(&encrypted).await.map_err(|e| {
                    Error::network(format!("Failed to write to VMess: {}", e))
                })?;

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
            loop {
                let mut length_buf = [0u8; 2];
                match ro.read_exact(&mut length_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(Error::network(format!("Failed to read length: {}", e))),
                }

                let length = u16::from_be_bytes(length_buf) as usize;
                if length == 0 {
                    break;
                }

                let mut data = vec![0u8; length];
                ro.read_exact(&mut data).await.map_err(|e| {
                    Error::network(format!("Failed to read chunk: {}", e))
                })?;

                let decrypted = decrypt_chunk_static(cipher, &data, &response_key, &response_iv, count)?;
                wi.write_all(&decrypted).await.map_err(|e| {
                    Error::network(format!("Failed to write to inbound: {}", e))
                })?;

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

fn encrypt_chunk_static(cipher: VmessCipher, data: &[u8], key: &[u8; 16], iv: &[u8; 16], count: u16) -> Result<Vec<u8>> {
    match cipher {
        VmessCipher::Aes128Gcm | VmessCipher::Auto => {
            let aes_cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let encrypted = aes_cipher
                .encrypt(nonce, data)
                .map_err(|e| Error::protocol(format!("Failed to encrypt data: {}", e)))?;

            let length = (encrypted.len() as u16).to_be_bytes();
            let mut result = Vec::with_capacity(2 + encrypted.len());
            result.extend_from_slice(&length);
            result.extend_from_slice(&encrypted);
            Ok(result)
        }
        VmessCipher::Chacha20Poly1305 => {
            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(key);
            full_key[16..].copy_from_slice(key);

            let chacha_cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

            let encrypted = chacha_cipher
                .encrypt(nonce, data)
                .map_err(|e| Error::protocol(format!("Failed to encrypt data: {}", e)))?;

            let length = (encrypted.len() as u16).to_be_bytes();
            let mut result = Vec::with_capacity(2 + encrypted.len());
            result.extend_from_slice(&length);
            result.extend_from_slice(&encrypted);
            Ok(result)
        }
        VmessCipher::None | VmessCipher::Zero => {
            let mut result = Vec::with_capacity(2 + data.len());
            result.extend_from_slice(&(data.len() as u16).to_be_bytes());
            result.extend_from_slice(data);
            Ok(result)
        }
    }
}

fn decrypt_chunk_static(cipher: VmessCipher, data: &[u8], key: &[u8; 16], iv: &[u8; 16], count: u16) -> Result<Vec<u8>> {
    match cipher {
        VmessCipher::Aes128Gcm | VmessCipher::Auto => {
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
            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(key);
            full_key[16..].copy_from_slice(key);

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
        VmessCipher::None | VmessCipher::Zero => {
            Ok(data.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_cipher_from_str() {
        assert_eq!(VmessCipher::from_str("aes-128-gcm"), VmessCipher::Aes128Gcm);
        assert_eq!(VmessCipher::from_str("aes128gcm"), VmessCipher::Aes128Gcm);
        assert_eq!(VmessCipher::from_str("chacha20-poly1305"), VmessCipher::Chacha20Poly1305);
        assert_eq!(VmessCipher::from_str("none"), VmessCipher::None);
        assert_eq!(VmessCipher::from_str("zero"), VmessCipher::Zero);
        assert_eq!(VmessCipher::from_str("auto"), VmessCipher::Auto);
        assert_eq!(VmessCipher::from_str("unknown"), VmessCipher::Auto);
    }

    #[test]
    fn test_vmess_cipher_as_byte() {
        assert_eq!(VmessCipher::Aes128Gcm.as_byte(), 0x03);
        assert_eq!(VmessCipher::Chacha20Poly1305.as_byte(), 0x04);
        assert_eq!(VmessCipher::None.as_byte(), 0x02);
        assert_eq!(VmessCipher::Zero.as_byte(), 0x05);
        assert_eq!(VmessCipher::Auto.as_byte(), 0x03);
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
        let uuid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
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

        let auth_id2 = outbound.generate_auth_id(timestamp);
        assert_eq!(auth_id, auth_id2);

        let auth_id3 = outbound.generate_auth_id(timestamp + 1);
        assert_ne!(auth_id, auth_id3);
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
        let decrypted = outbound.decrypt_aes_gcm(&encrypted[2..2+length], &key, &iv, 0).unwrap();
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
        let decrypted = outbound.decrypt_chacha20(&encrypted[2..2+length], &key, &iv, 0).unwrap();
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

        let decrypted = outbound.decrypt_chunk(&encrypted[2..], &key, &iv, 0).unwrap();
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
        fn prop_auth_id_deterministic(timestamp in arb_timestamp()) {
            let outbound = create_test_outbound("auto");

            let auth_id1 = outbound.generate_auth_id(timestamp);
            let auth_id2 = outbound.generate_auth_id(timestamp);

            prop_assert_eq!(auth_id1, auth_id2);
            prop_assert_eq!(auth_id1.len(), 16);
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

            prop_assert_ne!(auth_id1, auth_id2);
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
