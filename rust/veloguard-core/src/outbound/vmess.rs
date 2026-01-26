use crate::config::OutboundConfig;
use crate::connection_tracker::TrackedConnection;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use crate::time_sync;
use crate::tls::SkipServerVerification;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::{Buf, BufMut, BytesMut};
use dashmap::DashMap;
use hmac::Mac;
use http;
use md5::Md5;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

// ============================================================================
// 类型别名和常量 - VMess 协议规范
// ============================================================================

type HmacSha256 = hmac::Hmac<Sha256>;
type HmacMd5 = hmac::Hmac<Md5>;

/// VMess 协议版本 (固定为 0x01)
const VERSION: u8 = 0x01;

/// 数据块大小 (16KB)
const CHUNK_SIZE: usize = 1 << 14;

/// 最大数据块大小 (17KB)
const MAX_CHUNK_SIZE: usize = 17 * 1024;

/// VMess 选项: 分块流 (标准流模式)
const OPTION_CHUNK_STREAM: u8 = 0x01;

/// VMess 选项: 分块掩码 (元数据混淆, 可选)
#[allow(dead_code)]
const OPTION_CHUNK_MASK: u8 = 0x02;

/// 安全类型 (加密方式) - P & Sec 字段的低4位
/// 0x03: AES-128-GCM (推荐, x86_64/aarch64 架构)
const SECURITY_AES_128_GCM: u8 = 0x03;

/// 0x04: ChaCha20-Poly1305 (推荐, 其他架构)
const SECURITY_CHACHA20_POLY1305: u8 = 0x04;

/// 0x05: 无加密 (不推荐)
const SECURITY_NONE: u8 = 0x05;

/// 指令 (Cmd) - 0x01: TCP
const COMMAND_TCP: u8 = 0x01;

/// 指令 (Cmd) - 0x02: UDP
const COMMAND_UDP: u8 = 0x02;

// KDF 常量 - 用于密钥派生
const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_SALT_CONST_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce_Length";

// HMAC 常量
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;
const HMAC_BLOCK_LEN: usize = 64;
const HMAC_TAG_LEN: usize = 32;

// ============================================================================
// KDF 实现
// ============================================================================

/// VMess KDF 第一层
#[derive(Clone)]
struct VmessKdf1 {
    okey: [u8; HMAC_BLOCK_LEN],
    hasher: HmacSha256,
    hasher_outer: HmacSha256,
}

impl VmessKdf1 {
    fn new(mut hasher: HmacSha256, key: &[u8]) -> Self {
        let mut ikey = [0u8; HMAC_BLOCK_LEN];
        let mut okey = [0u8; HMAC_BLOCK_LEN];
        let hasher_outer = hasher.clone();

        if key.len() > HMAC_BLOCK_LEN {
            let mut hh = hasher.clone();
            hh.update(key);
            let hkey = hh.finalize().into_bytes();
            ikey[..HMAC_TAG_LEN].copy_from_slice(&hkey[..HMAC_TAG_LEN]);
            okey[..HMAC_TAG_LEN].copy_from_slice(&hkey[..HMAC_TAG_LEN]);
        } else {
            ikey[..key.len()].copy_from_slice(key);
            okey[..key.len()].copy_from_slice(key);
        }

        for idx in 0..HMAC_BLOCK_LEN {
            ikey[idx] ^= IPAD;
            okey[idx] ^= OPAD;
        }
        hasher.update(&ikey);
        Self {
            okey,
            hasher,
            hasher_outer,
        }
    }

    fn update(&mut self, m: &[u8]) {
        self.hasher.update(m);
    }

    fn finalize(mut self) -> [u8; HMAC_TAG_LEN] {
        let h1 = self.hasher.finalize().into_bytes();
        self.hasher_outer.update(&self.okey);
        self.hasher_outer.update(&h1);
        self.hasher_outer.finalize().into_bytes().into()
    }
}

/// 宏: 生成嵌套 KDF 结构
macro_rules! impl_vmess_kdf {
    ($name:ident, $inner:ty) => {
        #[derive(Clone)]
        struct $name {
            okey: [u8; HMAC_BLOCK_LEN],
            hasher: $inner,
            hasher_outer: $inner,
        }

        impl $name {
            fn new(mut hasher: $inner, key: &[u8]) -> Self {
                let mut ikey = [0u8; HMAC_BLOCK_LEN];
                let mut okey = [0u8; HMAC_BLOCK_LEN];
                let hasher_outer = hasher.clone();

                if key.len() > HMAC_BLOCK_LEN {
                    let mut hh = hasher.clone();
                    hh.update(key);
                    let hkey = hh.finalize();
                    ikey[..HMAC_TAG_LEN].copy_from_slice(&hkey[..HMAC_TAG_LEN]);
                    okey[..HMAC_TAG_LEN].copy_from_slice(&hkey[..HMAC_TAG_LEN]);
                } else {
                    ikey[..key.len()].copy_from_slice(key);
                    okey[..key.len()].copy_from_slice(key);
                }

                for idx in 0..HMAC_BLOCK_LEN {
                    ikey[idx] ^= IPAD;
                    okey[idx] ^= OPAD;
                }
                hasher.update(&ikey);
                Self {
                    okey,
                    hasher,
                    hasher_outer,
                }
            }

            fn update(&mut self, m: &[u8]) {
                self.hasher.update(m);
            }

            fn finalize(mut self) -> [u8; HMAC_TAG_LEN] {
                let h1 = self.hasher.finalize();
                self.hasher_outer.update(&self.okey);
                self.hasher_outer.update(&h1);
                self.hasher_outer.finalize()
            }
        }
    };
}

impl_vmess_kdf!(VmessKdf2, VmessKdf1);
impl_vmess_kdf!(VmessKdf3, VmessKdf2);

#[inline]
fn get_vmess_kdf_1(key1: &[u8]) -> VmessKdf1 {
    VmessKdf1::new(
        <HmacSha256 as Mac>::new_from_slice(KDF_SALT_CONST_VMESS_AEAD_KDF).unwrap(),
        key1,
    )
}

/// VMess KDF 1-shot 函数
pub fn vmess_kdf_1_one_shot(id: &[u8], key1: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_1(key1);
    h.update(id);
    h.finalize()
}

#[inline]
fn get_vmess_kdf_2(key1: &[u8], key2: &[u8]) -> VmessKdf2 {
    VmessKdf2::new(get_vmess_kdf_1(key1), key2)
}

#[inline]
fn get_vmess_kdf_3(key1: &[u8], key2: &[u8], key3: &[u8]) -> VmessKdf3 {
    VmessKdf3::new(get_vmess_kdf_2(key1, key2), key3)
}

/// VMess KDF 3-shot 函数
pub fn vmess_kdf_3_one_shot(id: &[u8], key1: &[u8], key2: &[u8], key3: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_3(key1, key2, key3);
    h.update(id);
    h.finalize()
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 生成 cmd_key
fn generate_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    use md5::Digest;
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let result = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result);
    key
}

/// FNV1a 哈希
fn fnv1a_hash(data: &[u8]) -> u32 {
    const FNV_OFFSET: u32 = 0x811c9dc5;
    const FNV_PRIME: u32 = 0x01000193;
    data.iter().fold(FNV_OFFSET, |hash, &byte| {
        (hash ^ byte as u32).wrapping_mul(FNV_PRIME)
    })
}

/// 生成随机字节
fn rand_fill(buf: &mut [u8]) {
    getrandom::fill(buf).unwrap_or_else(|_| {
        for b in buf.iter_mut() {
            *b = rand::random();
        }
    });
}

/// 生成随机范围
fn rand_range(range: std::ops::Range<usize>) -> usize {
    use rand::Rng;
    rand::rng().random_range(range)
}

/// MD5 哈希
fn md5_hash(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    let result = Md5::digest(data);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// SHA256 哈希
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let result = Sha256::digest(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// 时间戳哈希 (用于非 AEAD 模式的 IV 生成)
///
/// VMess 协议要求将时间戳重复4次后进行 MD5 哈希
/// 时间戳使用大端序 (Big-Endian)
fn hash_timestamp(timestamp: u64) -> [u8; 16] {
    use md5::Digest;
    let mut hasher = Md5::new();
    let ts_bytes = timestamp.to_be_bytes(); // 大端序
    hasher.update(ts_bytes);
    hasher.update(ts_bytes);
    hasher.update(ts_bytes);
    hasher.update(ts_bytes);
    hasher.finalize().into()
}

// ============================================================================
// 用户 ID 管理
// ============================================================================

/// VMess 用户 ID
#[derive(Clone)]
pub struct VmessId {
    pub uuid: Uuid,
    pub cmd_key: [u8; 16],
}

impl VmessId {
    pub fn new(uuid: &Uuid) -> Self {
        Self {
            uuid: *uuid,
            cmd_key: generate_cmd_key(uuid.as_bytes()),
        }
    }
}

/// 生成 alter ID 列表
pub fn new_alter_id_list(primary: &VmessId, alter_id_count: u16) -> Vec<VmessId> {
    let mut list = Vec::with_capacity(alter_id_count as usize + 1);
    let mut prev_id = primary.uuid;

    for _ in 0..alter_id_count {
        let new_id = next_id(&prev_id);
        list.push(VmessId {
            uuid: new_id,
            cmd_key: primary.cmd_key,
        });
        prev_id = new_id;
    }

    list.push(primary.clone());
    list
}

/// 生成下一个 ID
fn next_id(uuid: &Uuid) -> Uuid {
    use md5::Digest;
    let mut hasher = Md5::new();
    hasher.update(uuid.as_bytes());
    hasher.update(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
    let buf: [u8; 16] = hasher.finalize().into();
    Uuid::from_bytes(buf)
}

// ============================================================================
// 加密类型定义
// ============================================================================

/// VMess 加密方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCipher {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

impl VmessCipher {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" | "aes128gcm" => Self::Aes128Gcm,
            "chacha20-poly1305" | "chacha20poly1305" => Self::Chacha20Poly1305,
            "none" | "zero" => Self::None,
            _ => Self::Auto,
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => SECURITY_AES_128_GCM,
            Self::Chacha20Poly1305 => SECURITY_CHACHA20_POLY1305,
            Self::None => SECURITY_NONE,
            Self::Auto => self.resolve().as_byte(),
        }
    }

    /// 解析 Auto 为具体加密方式
    pub fn resolve(self) -> Self {
        match self {
            Self::Auto => {
                // 根据 CPU 架构选择最优加密方式
                match std::env::consts::ARCH {
                    "x86_64" | "s390x" | "aarch64" => Self::Aes128Gcm,
                    _ => Self::Chacha20Poly1305,
                }
            }
            other => other,
        }
    }

    /// 获取加密开销长度 (用于计算数据块大小)
    #[allow(dead_code)]
    pub fn overhead_len(self) -> usize {
        match self.resolve() {
            Self::Aes128Gcm | Self::Chacha20Poly1305 => 16,
            Self::None => 0,
            Self::Auto => unreachable!(),
        }
    }
}

/// VMess 传输层类型
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
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ws" | "websocket" => Self::Ws,
            "h2" | "http2" | "http/2" => Self::H2,
            "grpc" => Self::Grpc,
            "quic" => Self::Quic,
            "kcp" | "mkcp" => Self::Mkcp,
            _ => Self::Tcp,
        }
    }
}

// ============================================================================
// AEAD 加密器
// ============================================================================

/// VMess 安全层
#[allow(clippy::large_enum_variant)]
pub enum VmessSecurity {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(chacha20poly1305::ChaCha20Poly1305),
}

impl VmessSecurity {
    #[inline(always)]
    pub fn overhead_len(&self) -> usize {
        16
    }

    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        12
    }
}

/// AEAD 加密器
pub struct AeadCipher {
    pub security: VmessSecurity,
    nonce: [u8; 32],
    iv: bytes::Bytes,
    count: u16,
}

impl AeadCipher {
    pub fn new(iv: &[u8], security: VmessSecurity) -> Self {
        Self {
            security,
            nonce: [0u8; 32],
            iv: bytes::Bytes::copy_from_slice(iv),
            count: 0,
        }
    }

    pub fn decrypt_inplace(&mut self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        let mut nonce = self.nonce;
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        nonce[2..12].copy_from_slice(&self.iv[2..12]);
        self.count = self.count.wrapping_add(1);

        let nonce_slice = &nonce[..self.security.nonce_len()];
        match &self.security {
            VmessSecurity::Aes128Gcm(cipher) => {
                use aes_gcm::aead::AeadInPlace;
                cipher
                    .decrypt_in_place(Nonce::from_slice(nonce_slice), &[], buf)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                use chacha20poly1305::aead::AeadInPlace;
                cipher
                    .decrypt_in_place(chacha20poly1305::Nonce::from_slice(nonce_slice), &[], buf)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
        }
        Ok(())
    }

    pub fn encrypt_inplace(&mut self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        let mut nonce = self.nonce;
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        nonce[2..12].copy_from_slice(&self.iv[2..12]);
        self.count = self.count.wrapping_add(1);

        let nonce_slice = &nonce[..self.security.nonce_len()];
        match &self.security {
            VmessSecurity::Aes128Gcm(cipher) => {
                use aes_gcm::aead::AeadInPlace;
                cipher
                    .encrypt_in_place(Nonce::from_slice(nonce_slice), &[], buf)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                use chacha20poly1305::aead::AeadInPlace;
                cipher
                    .encrypt_in_place(chacha20poly1305::Nonce::from_slice(nonce_slice), &[], buf)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
        }
        Ok(())
    }
}

// ============================================================================
// 配置结构
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct VmessWsOptions {
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    /// WebSocket 早期数据大小 (用于 0-RTT)
    #[allow(dead_code)]
    pub max_early_data: usize,
    /// 早期数据头部名称
    #[allow(dead_code)]
    pub early_data_header_name: String,
}

#[derive(Debug, Clone)]
pub struct VmessH2Options {
    pub hosts: Vec<String>,
    pub path: String,
    pub headers: HashMap<String, String>,
}

impl Default for VmessH2Options {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            path: "/".to_string(),
            headers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmessGrpcOptions {
    pub service_name: String,
}

impl Default for VmessGrpcOptions {
    fn default() -> Self {
        Self {
            service_name: "GunService".to_string(),
        }
    }
}

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
            header_type: "none".into(),
            seed: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct VmessMuxOptions {
    pub enabled: bool,
    pub concurrency: usize,
}

// ============================================================================
// 地址序列化 - VMess 协议地址格式 (大端序)
// ============================================================================

/// VMess 地址序列化宏
///
/// 格式 (所有多字节数值使用大端序):
/// - 端口 (Port): 2字节, 大端序
/// - 地址类型 (T): 1字节
///   - 0x01: IPv4 (4字节)
///   - 0x02: 域名 (1字节长度 + N字节域名)
///   - 0x03: IPv6 (16字节)
/// - 地址 (A): 变长
macro_rules! write_vmess_address {
    ($buf:expr, $target:expr) => {
        match $target {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                // 端口: 2字节大端序
                $buf.put_u16(addr.port());
                // 地址类型: IPv4 = 0x01
                $buf.put_u8(0x01);
                // IPv4 地址: 4字节
                $buf.put_slice(&addr.ip().octets());
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                // 端口: 2字节大端序
                $buf.put_u16(addr.port());
                // 地址类型: IPv6 = 0x03
                $buf.put_u8(0x03);
                // IPv6 地址: 16字节 (每个 segment 2字节大端序)
                for seg in addr.ip().segments() {
                    $buf.put_u16(seg);
                }
            }
            TargetAddr::Domain(domain, port) => {
                // 端口: 2字节大端序
                $buf.put_u16(*port);
                // 地址类型: 域名 = 0x02
                $buf.put_u8(0x02);
                // 域名长度: 1字节
                $buf.put_u8(domain.len() as u8);
                // 域名: N字节
                $buf.put_slice(domain.as_bytes());
            }
        }
    };
}

// ============================================================================
// VMess 头部密封 - AEAD 模式
// ============================================================================

/// 创建 auth_id (AEAD 模式认证 ID)
///
/// 格式 (16字节, 大端序):
/// - 时间戳: 8字节, 大端序
/// - 随机数: 4字节
/// - CRC32: 4字节, 大端序
///
/// 然后使用 AES-128 加密整个 16 字节块
fn create_auth_id(cmd_key: [u8; 16], timestamp: u64) -> [u8; 16] {
    let mut buf = BytesMut::new();

    // 时间戳: 8字节大端序
    buf.put_u64(timestamp); // put_u64 默认大端序

    // 随机数: 4字节
    let mut random = [0u8; 4];
    rand_fill(&mut random);
    buf.put_slice(&random);

    // CRC32 校验: 4字节大端序
    let crc = crc32fast::hash(buf.as_ref());
    buf.put_u32(crc); // put_u32 默认大端序

    // 使用 KDF 派生的密钥进行 AES 加密
    let pk = vmess_kdf_1_one_shot(&cmd_key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
    let pk: [u8; 16] = pk[..16].try_into().unwrap();

    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
    let cipher = aes::Aes128::new_from_slice(&pk).unwrap();
    let mut block = [0u8; 16];
    buf.copy_to_slice(&mut block);
    let mut block = aes::Block::from(block);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// 密封 VMess AEAD 头部
///
/// AEAD 头部格式:
/// - auth_id: 16字节 (加密的认证 ID)
/// - header_len_encrypted: 18字节 (2字节长度 + 16字节 AEAD tag)
/// - connection_nonce: 8字节
/// - header_payload_encrypted: 变长 (头部数据 + 16字节 AEAD tag)
pub fn seal_vmess_aead_header(
    key: [u8; 16],
    data: Vec<u8>,
    timestamp: u64,
) -> std::io::Result<Vec<u8>> {
    let auth_id = create_auth_id(key, timestamp);
    let mut connection_nonce = [0u8; 8];
    rand_fill(&mut connection_nonce);

    // 加密头部长度
    let payload_header_length_aead_key = vmess_kdf_3_one_shot(
        &key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        &auth_id,
        &connection_nonce,
    );
    let payload_header_length_aead_nonce = vmess_kdf_3_one_shot(
        &key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        &auth_id,
        &connection_nonce,
    );

    let len_cipher = Aes128Gcm::new_from_slice(&payload_header_length_aead_key[..16]).unwrap();
    use aes_gcm::aead::Payload;
    let header_len_encrypted = len_cipher
        .encrypt(
            Nonce::from_slice(&payload_header_length_aead_nonce[..12]),
            Payload {
                msg: &(data.len() as u16).to_be_bytes(),
                aad: &auth_id,
            },
        )
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // 加密头部内容
    let payload_header_aead_key = vmess_kdf_3_one_shot(
        &key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
        &auth_id,
        &connection_nonce,
    );
    let payload_header_aead_nonce = vmess_kdf_3_one_shot(
        &key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
        &auth_id,
        &connection_nonce,
    );

    let payload_cipher = Aes128Gcm::new_from_slice(&payload_header_aead_key[..16]).unwrap();
    let payload_encrypted = payload_cipher
        .encrypt(
            Nonce::from_slice(&payload_header_aead_nonce[..12]),
            Payload {
                msg: &data,
                aad: &auth_id,
            },
        )
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // 组装结果
    let mut out = BytesMut::new();
    out.put_slice(&auth_id);
    out.put_slice(&header_len_encrypted);
    out.put_slice(&connection_nonce);
    out.put_slice(&payload_encrypted);

    Ok(out.freeze().to_vec())
}

// ============================================================================
// VMess 流 - 核心协议实现
// ============================================================================

/// 读取状态
enum ReadState {
    AeadWaitingHeaderSize,
    AeadWaitingHeader(usize),
    LegacyWaitingHeader,       // Legacy模式等待响应头
    StreamWaitingLength,
    StreamWaitingData(usize),
    StreamFlushingData(usize),
}

/// 写入状态
enum WriteState {
    BuildingData,
    FlushingData(usize, (usize, usize)),
}

/// AES-CFB 解密器状态（用于 Legacy 模式）
struct AesCfbDecryptor {
    cipher: aes::Aes128,
    prev_block: [u8; 16],
}

impl AesCfbDecryptor {
    fn new(key: &[u8], iv: &[u8]) -> std::io::Result<Self> {
        use aes::cipher::KeyInit as AesKeyInit;
        let cipher = aes::Aes128::new_from_slice(key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut prev_block = [0u8; 16];
        prev_block.copy_from_slice(iv);
        Ok(Self { cipher, prev_block })
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        use aes::cipher::BlockEncrypt;
        for chunk in data.chunks_mut(16) {
            let mut block = aes::Block::from(self.prev_block);
            self.cipher.encrypt_block(&mut block);

            // 保存密文用于下一轮
            let mut next_prev = [0u8; 16];
            next_prev[..chunk.len()].copy_from_slice(chunk);

            // 解密
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= block[i];
            }

            self.prev_block = next_prev;
        }
    }
}

/// AES-CFB 加密器状态（用于 Legacy 模式写入）
struct AesCfbEncryptor {
    cipher: aes::Aes128,
    prev_block: [u8; 16],
}

impl AesCfbEncryptor {
    fn new(key: &[u8], iv: &[u8]) -> std::io::Result<Self> {
        use aes::cipher::KeyInit as AesKeyInit;
        let cipher = aes::Aes128::new_from_slice(key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut prev_block = [0u8; 16];
        prev_block.copy_from_slice(iv);
        Ok(Self { cipher, prev_block })
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        use aes::cipher::BlockEncrypt;
        for chunk in data.chunks_mut(16) {
            let mut block = aes::Block::from(self.prev_block);
            self.cipher.encrypt_block(&mut block);

            // 加密并保存密文
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= block[i];
                self.prev_block[i] = *byte;
            }
        }
    }
}

/// VMess 流
pub struct VmessStream<S> {
    stream: S,
    aead_read_cipher: Option<AeadCipher>,
    aead_write_cipher: Option<AeadCipher>,
    // Legacy 模式的 AES-CFB 流加密器
    legacy_read_cipher: Option<AesCfbDecryptor>,
    legacy_write_cipher: Option<AesCfbEncryptor>,
    #[allow(dead_code)]
    dst: TargetAddr,
    #[allow(dead_code)]
    id: VmessId,
    req_body_iv: Vec<u8>,
    req_body_key: Vec<u8>,
    resp_header_key: Vec<u8>,
    resp_header_iv: Vec<u8>,
    resp_body_iv: Vec<u8>,
    resp_body_key: Vec<u8>,
    resp_v: u8,
    security: u8,
    is_aead: bool,
    #[allow(dead_code)]
    is_udp: bool,

    read_state: ReadState,
    #[allow(dead_code)]
    read_pos: usize,
    read_buf: BytesMut,

    write_state: WriteState,
    write_buf: BytesMut,
}

impl<S: std::fmt::Debug> std::fmt::Debug for VmessStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessStream")
            .field("dst", &self.dst)
            .field("is_aead", &self.is_aead)
            .field("is_udp", &self.is_udp)
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VmessStream<S> {
    /// 创建新的 VMess 流
    ///
    /// VMess 协议中有两套密钥体系：
    /// 1. 响应头解密密钥 (resp_header_key/iv)：用于解密服务器响应头
    ///    - AEAD 模式: SHA256(req_body_key/iv)[0..16]
    ///    - 非 AEAD 模式: MD5(req_body_key/iv)
    /// 2. 数据分块加密密钥：用于加密/解密数据流
    ///    - 发送方向: 直接使用 req_body_key/iv
    ///    - 接收方向:
    ///      - AEAD 模式: SHA256(req_body_key/iv)[0..16]
    ///      - 非 AEAD 模式: MD5(req_body_key/iv)
    pub async fn new(
        stream: S,
        id: &VmessId,
        dst: &TargetAddr,
        security: &u8,
        is_aead: bool,
        is_udp: bool,
    ) -> std::io::Result<Self> {
        let mut rand_bytes = [0u8; 33];
        rand_fill(&mut rand_bytes);
        let req_body_iv = rand_bytes[0..16].to_vec();
        let req_body_key = rand_bytes[16..32].to_vec();
        let resp_v = rand_bytes[32];

        // 响应密钥派生（用于响应头解密和数据分块解密）
        // AEAD 模式: SHA256 派生
        // 非 AEAD 模式: MD5 派生
        //
        // 根据 V2Ray 官方协议：
        // 1. responseBodyKey = SHA256(requestBodyKey)[:16]
        // 2. responseBodyIV = SHA256(requestBodyIV)[:16]
        // 3. 响应头密钥 = KDF(responseBodyKey, "AEAD Resp Header Key")[:16]
        // 4. 响应头 IV = KDF(responseBodyIV, "AEAD Resp Header IV")[:12]
        let (resp_body_key, resp_body_iv) = if is_aead {
            (
                sha256_hash(&req_body_key)[0..16].to_vec(),
                sha256_hash(&req_body_iv)[0..16].to_vec(),
            )
        } else {
            (md5_hash(&req_body_key).to_vec(), md5_hash(&req_body_iv).to_vec())
        };

        // 响应头密钥需要从 resp_body_key/iv 派生
        // 注意：AEAD 响应头 IV 只需要 12 字节 (GCM nonce 长度)
        let (resp_header_key, resp_header_iv) = if is_aead {
            (
                vmess_kdf_1_one_shot(&resp_body_key, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY)
                    [..16]
                    .to_vec(),
                vmess_kdf_1_one_shot(&resp_body_iv, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV)
                    [..12]  // 修复：AEAD nonce 长度为 12 字节
                    .to_vec(),
            )
        } else {
            (resp_body_key.clone(), resp_body_iv.clone())
        };

        // 创建数据分块加密器
        // 注意：AEAD cipher 只用于 AEAD 模式
        //       Legacy 模式使用 AES-CFB 流加密，不使用 AEAD
        //
        // 发送方向始终使用原始 req_body_key/iv
        // 接收方向使用派生后的 resp_body_key/iv
        let (aead_read_cipher, aead_write_cipher) = if is_aead {
            // AEAD 模式：使用 GCM 或 ChaCha20-Poly1305 加密数据块
            match *security {
                SECURITY_NONE => (None, None),
                SECURITY_AES_128_GCM => {
                    // 发送：使用原始 req_body_key/iv
                    let write_cipher =
                        VmessSecurity::Aes128Gcm(Aes128Gcm::new_from_slice(&req_body_key).unwrap());
                    let write_cipher = AeadCipher::new(&req_body_iv, write_cipher);
                    // 接收：使用派生后的 resp_body_key/iv
                    let read_cipher =
                        VmessSecurity::Aes128Gcm(Aes128Gcm::new_from_slice(&resp_body_key).unwrap());
                    let read_cipher = AeadCipher::new(&resp_body_iv, read_cipher);
                    (Some(read_cipher), Some(write_cipher))
                }
                SECURITY_CHACHA20_POLY1305 => {
                    use chacha20poly1305::KeyInit as ChaChaKeyInit;

                    // ChaCha20-Poly1305 需要 32 字节密钥，通过 MD5 扩展
                    // 发送密钥：MD5(req_body_key) + MD5(MD5(req_body_key))
                    let mut write_key = [0u8; 32];
                    write_key[..16].copy_from_slice(&md5_hash(&req_body_key));
                    let tmp = md5_hash(&write_key[..16]);
                    write_key[16..].copy_from_slice(&tmp);

                    let write_cipher = VmessSecurity::ChaCha20Poly1305(
                        chacha20poly1305::ChaCha20Poly1305::new_from_slice(&write_key).unwrap(),
                    );
                    let write_cipher = AeadCipher::new(&req_body_iv, write_cipher);

                    // 接收密钥：MD5(resp_body_key) + MD5(MD5(resp_body_key))
                    let mut read_key = [0u8; 32];
                    read_key[..16].copy_from_slice(&md5_hash(&resp_body_key));
                    let tmp = md5_hash(&read_key[..16]);
                    read_key[16..].copy_from_slice(&tmp);

                    let read_cipher = VmessSecurity::ChaCha20Poly1305(
                        chacha20poly1305::ChaCha20Poly1305::new_from_slice(&read_key).unwrap(),
                    );
                    let read_cipher = AeadCipher::new(&resp_body_iv, read_cipher);

                    (Some(read_cipher), Some(write_cipher))
                }
                _ => {
                    return Err(std::io::Error::other("unsupported security"));
                }
            }
        } else {
            // Legacy 模式：不使用 AEAD，使用 AES-CFB 流加密
            // security 字段会被忽略，数据用 AES-CFB + FNV1a 保护
            (None, None)
        };

        // 确定初始读取状态
        let initial_read_state = if is_aead {
            ReadState::AeadWaitingHeaderSize
        } else {
            ReadState::LegacyWaitingHeader
        };

        let mut stream = Self {
            stream,
            aead_read_cipher,
            aead_write_cipher,
            legacy_read_cipher: None,  // 将在读取响应头后初始化
            legacy_write_cipher: None, // 将在需要写入时初始化
            dst: dst.clone(),
            id: id.clone(),
            req_body_iv: req_body_iv.clone(),
            req_body_key: req_body_key.clone(),
            resp_header_key,
            resp_header_iv,
            resp_body_iv,
            resp_body_key,
            resp_v,
            security: *security,
            is_aead,
            is_udp,
            read_state: initial_read_state,
            read_pos: 0,
            read_buf: BytesMut::new(),
            write_state: WriteState::BuildingData,
            write_buf: BytesMut::new(),
        };

        stream
            .send_handshake_request(
                id,
                dst,
                is_udp,
                &req_body_iv,
                &req_body_key,
                resp_v,
                *security,
            )
            .await?;
        Ok(stream)
    }

    /// 发送握手请求
    ///
    /// VMess 协议头部格式 (大端序):
    /// - 版本号 (Ver): 1字节, 固定为 0x01
    /// - 数据加密 IV: 16字节, 随机生成
    /// - 数据加密 Key: 16字节, 随机生成
    /// - 响应认证 (V): 1字节, 随机值用于校验服务器响应
    /// - 选项 (Opt): 1字节, 位标志位
    /// - P & Sec: 1字节, 高4位为填充长度P, 低4位为加密方式
    /// - 保留字段: 1字节, 固定为 0x00
    /// - 指令 (Cmd): 1字节, 0x01=TCP, 0x02=UDP
    /// - 端口 (Port): 2字节, 大端序
    /// - 地址类型 (T): 1字节, 0x01=IPv4, 0x02=域名, 0x03=IPv6
    /// - 地址 (A): 变长
    /// - 随机填充: P字节
    /// - 校验值 (F): 4字节, FNV1a hash (大端序)
    #[allow(clippy::too_many_arguments)]
    async fn send_handshake_request(
        &mut self,
        id: &VmessId,
        dst: &TargetAddr,
        is_udp: bool,
        req_body_iv: &[u8],
        req_body_key: &[u8],
        resp_v: u8,
        security: u8,
    ) -> std::io::Result<()> {
        // 使用 NTP 校正后的时间戳，VMess 协议要求时间差在 ±90 秒内
        let (now, diag) = time_sync::get_vmess_timestamp_with_diagnostics();
        let now = now as u64;

        if diag.needs_resync {
            tracing::warn!(
                "VMess timestamp may be stale, last NTP sync: {}s ago",
                diag.local_timestamp_secs - diag.last_sync_time_secs
            );
        }
        if diag.suspected_milliseconds_error {
            tracing::error!(
                "CRITICAL: VMess timestamp {} looks like milliseconds! Auth will fail.",
                now
            );
        }
        tracing::debug!(
            "VMess handshake: timestamp={}, ntp_offset={}ms, jitter={}s",
            now,
            diag.ntp_offset_ms,
            diag.jitter_secs
        );

        let mut mbuf = BytesMut::new();

        if !self.is_aead {
            let mut mac = <HmacMd5 as Mac>::new_from_slice(id.uuid.as_bytes())
                .expect("key len expected to be 16");
            mac.update(&now.to_be_bytes());
            mbuf.put_slice(&mac.finalize().into_bytes());
        }

        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_slice(req_body_iv);
        buf.put_slice(req_body_key);
        buf.put_u8(resp_v);
        buf.put_u8(OPTION_CHUNK_STREAM);

        let p = rand_range(0..16) as u8;
        buf.put_u8((p << 4) | security);
        buf.put_u8(0);

        if is_udp {
            buf.put_u8(COMMAND_UDP);
        } else {
            buf.put_u8(COMMAND_TCP);
        }

        write_vmess_address!(buf, dst);

        if p > 0 {
            let mut padding = vec![0u8; p as usize];
            rand_fill(&mut padding);
            buf.put_slice(&padding);
        }

        let sum = fnv1a_hash(&buf);
        buf.put_u32(sum);

        if !self.is_aead {
            tracing::debug!("[VMess] Using legacy (non-AEAD) header encryption");
            let mut data = buf.to_vec();
            aes_cfb_encrypt(&id.cmd_key, &hash_timestamp(now), &mut data)?;
            mbuf.put_slice(&data);
            let out = mbuf.freeze();
            tracing::debug!("[VMess] Sending legacy header: {} bytes", out.len());
            self.stream.write_all(&out).await?;
        } else {
            tracing::debug!("[VMess] Using AEAD header encryption");
            let out = seal_vmess_aead_header(id.cmd_key, buf.freeze().to_vec(), now)?;
            tracing::debug!("[VMess] Sending AEAD header: {} bytes", out.len());
            self.stream.write_all(&out).await?;
        }

        self.stream.flush().await?;
        tracing::debug!("[VMess] Handshake request sent successfully");
        Ok(())
    }
}

/// AES-CFB 加密 (用于非 AEAD 模式)
fn aes_cfb_encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> std::io::Result<()> {
    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};

    let cipher =
        aes::Aes128::new_from_slice(key).map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);

    for chunk in data.chunks_mut(16) {
        let mut block = aes::Block::from(prev);
        cipher.encrypt_block(&mut block);

        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= block[i];
            prev[i] = *byte;
        }
    }

    Ok(())
}

// ============================================================================
// VmessStream AsyncRead 实现
// ============================================================================

trait ReadExact {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context<'_>,
        n: usize,
    ) -> std::task::Poll<std::io::Result<()>>;
}

impl<S: AsyncRead + Unpin> ReadExact for VmessStream<S> {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context<'_>,
        n: usize,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        while self.read_buf.len() < n {
            let mut tmp = vec![0u8; n - self.read_buf.len()];
            let mut read_buf = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "unexpected eof",
                        )));
                    }
                    self.read_buf.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin + Send> AsyncRead for VmessStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use futures::ready;
        use std::task::Poll;

        loop {
            match &self.read_state {
                ReadState::LegacyWaitingHeader => {
                    // Legacy 模式：读取并解密 4 字节响应头
                    let this = &mut *self;
                    let resp_v = this.resp_v;
                    
                    ready!(this.poll_read_exact(cx, 4))?;
                    let mut data = this.read_buf.split().freeze().to_vec();
                    
                    // 创建 AES-CFB 解密器并解密响应头
                    // 这个解密器会持续用于后续数据流
                    let mut cfb_decryptor = AesCfbDecryptor::new(&this.resp_body_key, &this.resp_body_iv)?;
                    cfb_decryptor.decrypt(&mut data);
                    
                    tracing::debug!(
                        "[VMess Legacy] Response header decrypted: resp_v={:02x} (expected {:02x}), opt={:02x}, cmd={:02x}, cmd_len={:02x}",
                        data[0], resp_v, data[1], data[2], data[3]
                    );

                    if data[0] != resp_v {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("invalid response - resp_v mismatch: got {:02x}, expected {:02x}", data[0], resp_v),
                        )));
                    }

                    if data[2] != 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response - dynamic port not supported",
                        )));
                    }

                    // 保存解密器，其状态已经正确同步到响应头之后
                    this.legacy_read_cipher = Some(cfb_decryptor);
                    
                    tracing::debug!("[VMess Legacy] Response header validated, switching to data streaming mode");
                    this.read_state = ReadState::StreamWaitingLength;
                }
                
                ReadState::AeadWaitingHeaderSize => {
                    let this = &mut *self;
                    
                    // AEAD 模式
                    // 根据 V2Ray 协议，响应头密钥需要使用派生后的 responseBodyKey/IV
                    // responseBodyKey = SHA256(requestBodyKey)[:16]
                    // responseBodyIV = SHA256(requestBodyIV)[:16]
                    // 然后再用 responseBodyKey/IV 做 KDF 派生
                    ready!(this.poll_read_exact(cx, 18))?;

                    let resp_body_key = &this.resp_body_key;
                    let resp_body_iv = &this.resp_body_iv;

                    let aead_response_header_length_encryption_key = &vmess_kdf_1_one_shot(
                        resp_body_key,
                        KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
                    )[..16];
                    let aead_response_header_length_encryption_iv = &vmess_kdf_1_one_shot(
                        resp_body_iv,
                        KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
                    )[..12];

                    let cipher =
                        Aes128Gcm::new_from_slice(aead_response_header_length_encryption_key)
                            .map_err(|e| std::io::Error::other(e.to_string()))?;

                    let decrypted_response_header_len = cipher
                        .decrypt(
                            Nonce::from_slice(aead_response_header_length_encryption_iv),
                            this.read_buf.split().as_ref(),
                        )
                        .map_err(|e| {
                            std::io::Error::other(format!("decrypt header len failed: {}", e))
                        })?;

                    if decrypted_response_header_len.len() < 2 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response header length",
                        )));
                    }

                    let header_size = u16::from_be_bytes(
                        decrypted_response_header_len[..2].try_into().unwrap(),
                    ) as usize;

                    this.read_state = ReadState::AeadWaitingHeader(header_size);
                }

                ReadState::AeadWaitingHeader(header_size) => {
                    let header_size = *header_size;
                    let this = &mut *self;
                    ready!(this.poll_read_exact(cx, header_size + 16))?;

                    let resp_header_key = this.resp_header_key.clone();
                    let resp_header_iv = this.resp_header_iv.clone();

                    let cipher = Aes128Gcm::new_from_slice(&resp_header_key)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;

                    let decrypted_buf = cipher
                        .decrypt(
                            Nonce::from_slice(&resp_header_iv[..12]),
                            this.read_buf.split().as_ref(),
                        )
                        .map_err(|e| {
                            std::io::Error::other(format!("decrypt header failed: {}", e))
                        })?;

                    if decrypted_buf.len() < 4 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response - header too short",
                        )));
                    }

                    if decrypted_buf[0] != this.resp_v {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response - version mismatch",
                        )));
                    }

                    if decrypted_buf[2] != 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response - dynamic port not supported",
                        )));
                    }

                    this.read_state = ReadState::StreamWaitingLength;
                }

                ReadState::StreamWaitingLength => {
                    let this = &mut *self;
                    ready!(this.poll_read_exact(cx, 2))?;

                    // Legacy 模式: 长度字段也在 AES-CFB 流加密中
                    let mut len_buf = this.read_buf.split().freeze().to_vec();
                    if let Some(ref mut cfb) = this.legacy_read_cipher {
                        cfb.decrypt(&mut len_buf);
                    }
                    
                    let len = u16::from_be_bytes(len_buf[..2].try_into().unwrap()) as usize;
                    
                    tracing::trace!("[VMess] Chunk length: {}", len);

                    if len == 0 {
                        // 长度为 0 表示流结束
                        return Poll::Ready(Ok(()));
                    }

                    if len > MAX_CHUNK_SIZE {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("invalid response - chunk size too large: {}", len),
                        )));
                    }

                    this.read_state = ReadState::StreamWaitingData(len);
                }

                ReadState::StreamWaitingData(size) => {
                    let size = *size;
                    let this = &mut *self;
                    ready!(this.poll_read_exact(cx, size))?;

                    let mut data = this.read_buf.split().to_vec();
                    
                    // Legacy 模式: 数据也在 AES-CFB 流加密中
                    if let Some(ref mut cfb) = this.legacy_read_cipher {
                        cfb.decrypt(&mut data);
                        
                        // Legacy 模式下数据格式: [4字节 FNV1a] [N字节 payload]
                        // FNV1a overhead = 4 bytes
                        if size < 4 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid chunk: too small for FNV header",
                            )));
                        }
                        
                        let fnv_hash = u32::from_be_bytes(data[0..4].try_into().unwrap());
                        let payload = &data[4..];
                        let computed_hash = fnv1a_hash(payload);
                        
                        if fnv_hash != computed_hash {
                            tracing::warn!(
                                "[VMess Legacy] FNV hash mismatch: expected {:08x}, got {:08x}",
                                computed_hash, fnv_hash
                            );
                            // 可以选择继续或返回错误，这里选择继续但记录警告
                        }
                        
                        let payload_len = size - 4;
                        this.read_buf = BytesMut::from(&data[4..]);
                        this.read_state = ReadState::StreamFlushingData(payload_len);
                    } else if let Some(ref mut cipher) = this.aead_read_cipher {
                        // AEAD 模式
                        cipher.decrypt_inplace(&mut data)?;
                        let data_len = size - cipher.security.overhead_len();
                        data.truncate(data_len);
                        this.read_buf = BytesMut::from(&data[..]);
                        this.read_state = ReadState::StreamFlushingData(data_len);
                    } else {
                        // 无加密模式
                        this.read_buf = BytesMut::from(&data[..]);
                        this.read_state = ReadState::StreamFlushingData(size);
                    }
                }

                ReadState::StreamFlushingData(size) => {
                    let size = *size;
                    let to_read = std::cmp::min(buf.remaining(), size);
                    let payload = self.read_buf.split_to(to_read);
                    buf.put_slice(&payload);

                    if to_read < size {
                        self.read_state = ReadState::StreamFlushingData(size - to_read);
                    } else {
                        self.read_state = ReadState::StreamWaitingLength;
                    }

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

// ============================================================================
// VmessStream AsyncWrite 实现
// ============================================================================

impl<S: AsyncWrite + Unpin + Send> AsyncWrite for VmessStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use futures::ready;
        use std::task::Poll;

        loop {
            match &self.write_state {
                WriteState::BuildingData => {
                    let this = &mut *self;
                    
                    // 确定 overhead 长度
                    let overhead_len = if !this.is_aead && this.security != SECURITY_NONE {
                        // Legacy 模式: FNV1a 4 字节
                        4
                    } else if let Some(ref cipher) = this.aead_write_cipher {
                        // AEAD 模式: 16 字节 tag
                        cipher.security.overhead_len()
                    } else {
                        0
                    };

                    let max_payload_size = CHUNK_SIZE - overhead_len;
                    let consume_len = std::cmp::min(buf.len(), max_payload_size);
                    let chunk_len = consume_len + overhead_len;

                    this.write_buf.clear();
                    this.write_buf.reserve(2 + chunk_len);
                    
                    // 构建数据块
                    if !this.is_aead {
                        // Legacy 模式: 需要 AES-CFB 加密整个数据流
                        // 确保写入加密器已初始化
                        if this.legacy_write_cipher.is_none() {
                            this.legacy_write_cipher = Some(
                                AesCfbEncryptor::new(&this.req_body_key, &this.req_body_iv)
                                    .map_err(|e| std::io::Error::other(e.to_string()))?
                            );
                        }
                        
                        // 构建明文: [2字节长度][4字节FNV][数据]
                        let mut plaintext = BytesMut::new();
                        plaintext.put_u16(chunk_len as u16);
                        
                        // 计算 FNV1a
                        let fnv = fnv1a_hash(&buf[..consume_len]);
                        plaintext.put_u32(fnv);
                        plaintext.put_slice(&buf[..consume_len]);
                        
                        // AES-CFB 加密
                        let mut encrypted = plaintext.to_vec();
                        if let Some(ref mut cfb) = this.legacy_write_cipher {
                            cfb.encrypt(&mut encrypted);
                        }
                        
                        this.write_buf.extend_from_slice(&encrypted);
                    } else {
                        // AEAD 模式
                        this.write_buf.put_u16(chunk_len as u16);

                        let mut piece2 = this.write_buf.split_off(2);
                        piece2.put_slice(&buf[..consume_len]);

                        if let Some(ref mut cipher) = this.aead_write_cipher {
                            piece2.extend_from_slice(&vec![0u8; cipher.security.overhead_len()]);
                            let mut piece2_vec = piece2.to_vec();
                            cipher.encrypt_inplace(&mut piece2_vec)?;
                            piece2 = BytesMut::from(&piece2_vec[..]);
                        }

                        this.write_buf.unsplit(piece2);
                    }
                    
                    this.write_state =
                        WriteState::FlushingData(consume_len, (this.write_buf.len(), 0));
                }

                WriteState::FlushingData(consumed, (total, written)) => {
                    let consumed = *consumed;
                    let total = *total;
                    let written = *written;
                    let this = &mut *self;

                    let nw = ready!(tokio_util::io::poll_write_buf(
                        std::pin::Pin::new(&mut this.stream),
                        cx,
                        &mut this.write_buf
                    ))?;

                    if nw == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write whole data",
                        )));
                    }

                    if written + nw >= total {
                        this.write_state = WriteState::BuildingData;
                        return Poll::Ready(Ok(consumed));
                    }

                    this.write_state = WriteState::FlushingData(consumed, (total, written + nw));
                }
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

// ============================================================================
// WebSocket 流
// ============================================================================

#[allow(clippy::enum_variant_names)]
enum WsReadState {
    ReadingHeader {
        buf: [u8; 2],
        pos: usize,
    },
    ReadingExtLen {
        header: [u8; 2],
        buf: Vec<u8>,
        pos: usize,
        expected: usize,
    },
    ReadingMask {
        payload_len: usize,
        buf: [u8; 4],
        pos: usize,
    },
    ReadingPayload {
        payload_len: usize,
        mask: Option<[u8; 4]>,
        buf: Vec<u8>,
        pos: usize,
    },
}

enum WsWriteState {
    Ready,
    Writing { frame: Vec<u8>, pos: usize },
}

pub struct WebSocketStream<S> {
    inner: S,
    read_state: WsReadState,
    read_buffer: Vec<u8>,
    read_pos: usize,
    write_state: WsWriteState,
}

impl<S> WebSocketStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_state: WsReadState::ReadingHeader {
                buf: [0; 2],
                pos: 0,
            },
            read_buffer: Vec::new(),
            read_pos: 0,
            write_state: WsWriteState::Ready,
        }
    }

    fn build_frame(data: &[u8]) -> Vec<u8> {
        let len = data.len();
        let mut frame = Vec::with_capacity(14 + len);
        frame.push(0x82);

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

        for (i, byte) in data.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }
        frame
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketStream<S> {
    pub async fn handshake(
        stream: S,
        host: &str,
        path: &str,
        extra_headers: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut ws = Self::new(stream);

        let mut key_bytes = [0u8; 16];
        rand_fill(&mut key_bytes);
        let ws_key = BASE64.encode(key_bytes);

        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n",
            path, host, ws_key
        );

        for (k, v) in extra_headers {
            if ![
                "host",
                "upgrade",
                "connection",
                "sec-websocket-key",
                "sec-websocket-version",
            ]
            .contains(&k.to_lowercase().as_str())
            {
                request.push_str(&format!("{}: {}\r\n", k, v));
            }
        }
        request.push_str("\r\n");

        tracing::debug!(
            "[WebSocket] Sending handshake to {}{}:\nRequest Headers:\n{}",
            host,
            path,
            request.replace("\r\n", "\\r\\n\n")
        );

        ws.inner
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::network(format!("WebSocket handshake write failed: {}", e)))?;
        ws.inner.flush().await.ok();

        tracing::debug!("[WebSocket] Handshake sent, waiting for response...");

        // 读取响应
        let mut response = Vec::with_capacity(1024);
        let mut buf = [0u8; 1];
        while response.len() < 4096 {
            ws.inner
                .read_exact(&mut buf)
                .await
                .map_err(|e| Error::network(format!("WebSocket handshake read failed: {}", e)))?;
            response.push(buf[0]);
            if response.len() >= 4 && &response[response.len() - 4..] == b"\r\n\r\n" {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        tracing::debug!("[WebSocket] Received response:\n{}", response_str);

        if !response_str.starts_with("HTTP/1.1 101") {
            return Err(Error::protocol(format!(
                "WebSocket upgrade failed: {}",
                response_str.lines().next().unwrap_or("unknown")
            )));
        }

        // 验证 accept header
        let expected_accept = {
            use sha1::Digest;
            let mut hasher = Sha1::new();
            hasher.update(ws_key.as_bytes());
            hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            BASE64.encode(hasher.finalize())
        };

        let accept_valid = response_str.lines().any(|line| {
            line.to_lowercase().starts_with("sec-websocket-accept:")
                && line.split(':').nth(1).map(|s| s.trim()) == Some(&expected_accept)
        });

        if !accept_valid {
            return Err(Error::protocol("WebSocket accept header mismatch"));
        }

        tracing::debug!("WebSocket handshake completed");
        Ok(ws)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        // 先返回缓冲区中的数据
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();

        loop {
            match &mut this.read_state {
                WsReadState::ReadingHeader {
                    buf: header_buf,
                    pos,
                } => {
                    while *pos < 2 {
                        let mut tmp = [0u8; 2];
                        let mut read_buf = tokio::io::ReadBuf::new(&mut tmp[..(2 - *pos)]);
                        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                header_buf[*pos..*pos + n].copy_from_slice(read_buf.filled());
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let header = *header_buf;
                    let opcode = header[0] & 0x0F;
                    let masked = (header[1] & 0x80) != 0;
                    let payload_len_byte = header[1] & 0x7F;

                    // 处理关闭帧
                    if opcode == 0x08 {
                        this.read_state = WsReadState::ReadingHeader {
                            buf: [0; 2],
                            pos: 0,
                        };
                        return Poll::Ready(Ok(()));
                    }

                    // 处理 ping 帧
                    if opcode == 0x09 {
                        if payload_len_byte > 0 {
                            this.read_state = WsReadState::ReadingPayload {
                                payload_len: payload_len_byte as usize,
                                mask: None,
                                buf: vec![0; payload_len_byte as usize],
                                pos: 0,
                            };
                        } else {
                            this.read_state = WsReadState::ReadingHeader {
                                buf: [0; 2],
                                pos: 0,
                            };
                        }
                        continue;
                    }

                    if payload_len_byte < 126 {
                        let payload_len = payload_len_byte as usize;
                        if masked {
                            this.read_state = WsReadState::ReadingMask {
                                payload_len,
                                buf: [0; 4],
                                pos: 0,
                            };
                        } else {
                            this.read_state = WsReadState::ReadingPayload {
                                payload_len,
                                mask: None,
                                buf: vec![0; payload_len],
                                pos: 0,
                            };
                        }
                    } else if payload_len_byte == 126 {
                        this.read_state = WsReadState::ReadingExtLen {
                            header,
                            buf: vec![0; 2],
                            pos: 0,
                            expected: 2,
                        };
                    } else {
                        this.read_state = WsReadState::ReadingExtLen {
                            header,
                            buf: vec![0; 8],
                            pos: 0,
                            expected: 8,
                        };
                    }
                }

                WsReadState::ReadingExtLen {
                    header,
                    buf: ext_buf,
                    pos,
                    expected,
                } => {
                    while *pos < *expected {
                        let mut tmp = vec![0u8; *expected - *pos];
                        let mut read_buf = tokio::io::ReadBuf::new(&mut tmp);
                        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                ext_buf[*pos..*pos + n].copy_from_slice(read_buf.filled());
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let payload_len = if *expected == 2 {
                        u16::from_be_bytes([ext_buf[0], ext_buf[1]]) as usize
                    } else {
                        u64::from_be_bytes(ext_buf[..8].try_into().unwrap()) as usize
                    };

                    let masked = (header[1] & 0x80) != 0;
                    if masked {
                        this.read_state = WsReadState::ReadingMask {
                            payload_len,
                            buf: [0; 4],
                            pos: 0,
                        };
                    } else {
                        this.read_state = WsReadState::ReadingPayload {
                            payload_len,
                            mask: None,
                            buf: vec![0; payload_len],
                            pos: 0,
                        };
                    }
                }

                WsReadState::ReadingMask {
                    payload_len,
                    buf: mask_buf,
                    pos,
                } => {
                    while *pos < 4 {
                        let mut tmp = [0u8; 4];
                        let mut read_buf = tokio::io::ReadBuf::new(&mut tmp[..(4 - *pos)]);
                        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                mask_buf[*pos..*pos + n].copy_from_slice(read_buf.filled());
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let payload_len = *payload_len;
                    let mask = *mask_buf;
                    this.read_state = WsReadState::ReadingPayload {
                        payload_len,
                        mask: Some(mask),
                        buf: vec![0; payload_len],
                        pos: 0,
                    };
                }

                WsReadState::ReadingPayload {
                    payload_len,
                    mask,
                    buf: payload_buf,
                    pos,
                } => {
                    while *pos < *payload_len {
                        let mut tmp = vec![0u8; *payload_len - *pos];
                        let mut read_buf = tokio::io::ReadBuf::new(&mut tmp);
                        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                payload_buf[*pos..*pos + n].copy_from_slice(read_buf.filled());
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // 解除掩码
                    if let Some(m) = mask {
                        for (i, byte) in payload_buf.iter_mut().enumerate() {
                            *byte ^= m[i % 4];
                        }
                    }

                    // 存储到缓冲区
                    this.read_buffer = std::mem::take(payload_buf);
                    this.read_pos = 0;
                    this.read_state = WsReadState::ReadingHeader {
                        buf: [0; 2],
                        pos: 0,
                    };

                    // 返回数据
                    let to_copy = this.read_buffer.len().min(buf.remaining());
                    buf.put_slice(&this.read_buffer[..to_copy]);
                    this.read_pos = to_copy;
                    if this.read_pos >= this.read_buffer.len() {
                        this.read_buffer.clear();
                        this.read_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();

        loop {
            match &mut this.write_state {
                WsWriteState::Ready => {
                    let frame = Self::build_frame(buf);
                    this.write_state = WsWriteState::Writing { frame, pos: 0 };
                }
                WsWriteState::Writing { frame, pos } => {
                    while *pos < frame.len() {
                        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &frame[*pos..]) {
                            Poll::Ready(Ok(n)) => {
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::WriteZero,
                                        "Failed to write frame",
                                    )));
                                }
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    this.write_state = WsWriteState::Ready;
                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ============================================================================
// QUIC 流
// ============================================================================

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
        use futures::AsyncRead as FuturesAsyncRead;
        use std::task::Poll;

        let this = self.get_mut();
        let unfilled = buf.initialize_unfilled();
        let pinned = std::pin::Pin::new(&mut this.recv);

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
        FuturesAsyncWrite::poll_write(std::pin::Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use futures::AsyncWrite as FuturesAsyncWrite;
        FuturesAsyncWrite::poll_flush(std::pin::Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use futures::AsyncWrite as FuturesAsyncWrite;
        FuturesAsyncWrite::poll_close(std::pin::Pin::new(&mut self.get_mut().send), cx)
    }
}

// ============================================================================
// VMess UDP Datagram
// ============================================================================

use futures::{Sink, Stream};
use std::pin::Pin;
use std::task::{Context, Poll};

/// UDP 数据包
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: TargetAddr,
    pub dst_addr: TargetAddr,
}

/// VMess UDP 出站数据报
#[allow(dead_code)]
pub struct OutboundDatagramVmess {
    inner: Box<dyn AsyncReadWrite>,
    remote_addr: TargetAddr,
    written: Option<usize>,
    flushed: bool,
    pkt: Option<UdpPacket>,
    buf: Vec<u8>,
}

#[allow(dead_code)]
impl OutboundDatagramVmess {
    pub fn new(inner: Box<dyn AsyncReadWrite>, remote_addr: TargetAddr) -> Self {
        Self {
            inner,
            remote_addr,
            written: None,
            flushed: true,
            pkt: None,
            buf: vec![0u8; 65535],
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramVmess {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> std::result::Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        use futures::ready;

        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref remote_addr,
            ref mut flushed,
            ref mut written,
            ..
        } = *self;

        let mut inner = Pin::new(inner.as_mut());
        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            if pkt.dst_addr.to_string() != remote_addr.to_string() {
                tracing::error!(
                    "udp packet dst_addr not match, pkt.dst_addr: {:?}, remote_addr: {:?}",
                    pkt.dst_addr,
                    remote_addr
                );
                return Poll::Ready(Err(std::io::Error::other("udp packet dst_addr not match")));
            }

            if written.is_none() {
                let n = ready!(inner.as_mut().poll_write(cx, pkt.data.as_ref()))?;
                tracing::debug!(
                    "send udp packet to remote vmess server, len: {}, remote_addr: {:?}, dst_addr: {:?}",
                    n, remote_addr, pkt.dst_addr
                );
                *written = Some(n);
            }

            if !*flushed {
                let r = inner.as_mut().poll_flush(cx)?;
                if r.is_pending() {
                    return Poll::Pending;
                }
                *flushed = true;
            }

            let total_len = pkt.data.len();
            *pkt_container = None;

            let res = if written.unwrap() == total_len {
                Ok(())
            } else {
                Err(std::io::Error::other(format!(
                    "failed to write entire datagram, written: {}",
                    written.unwrap()
                )))
            };
            *written = None;
            Poll::Ready(res)
        } else {
            tracing::debug!("no udp packet to send");
            Poll::Ready(Err(std::io::Error::other("no packet to send")))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        use futures::ready;
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl Stream for OutboundDatagramVmess {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use futures::ready;

        let Self {
            ref mut buf,
            ref mut inner,
            ref remote_addr,
            ..
        } = *self;

        let inner = Pin::new(inner.as_mut());
        let mut read_buf = tokio::io::ReadBuf::new(buf);

        let rv = ready!(inner.poll_read(cx, &mut read_buf));

        match rv {
            Ok(()) => Poll::Ready(Some(UdpPacket {
                data: read_buf.filled().to_vec(),
                src_addr: remote_addr.clone(),
                dst_addr: TargetAddr::Domain("0.0.0.0".to_string(), 0),
            })),
            Err(_) => Poll::Ready(None),
        }
    }
}

// ============================================================================
// VMess Builder
// ============================================================================

#[derive(Clone)]
pub struct VmessOption {
    pub uuid: String,
    pub alter_id: u16,
    pub security: String,
    pub udp: bool,
    pub dst: TargetAddr,
}

/// VMess 构建器
#[allow(dead_code)]
pub struct VmessBuilder {
    pub user: Vec<VmessId>,
    pub security: u8,
    pub is_aead: bool,
    pub is_udp: bool,
    pub dst: TargetAddr,
}

#[allow(dead_code)]
impl VmessBuilder {
    pub fn new(opt: &VmessOption) -> std::io::Result<Self> {
        let uuid = Uuid::parse_str(&opt.uuid).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid uuid format, should be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            )
        })?;

        let security = match opt.security.to_lowercase().as_str() {
            "chacha20-poly1305" => SECURITY_CHACHA20_POLY1305,
            "aes-128-gcm" => SECURITY_AES_128_GCM,
            "none" => SECURITY_NONE,
            "auto" => match std::env::consts::ARCH {
                "x86_64" | "s390x" | "aarch64" => SECURITY_AES_128_GCM,
                _ => SECURITY_CHACHA20_POLY1305,
            },
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid security",
                ));
            }
        };

        let primary_id = VmessId::new(&uuid);

        Ok(Self {
            user: new_alter_id_list(&primary_id, opt.alter_id),
            security,
            // VMess AEAD 模式仅在 alterId == 0 时启用
            // alterId > 0 时使用 Legacy 模式
            is_aead: opt.alter_id == 0,
            is_udp: opt.udp,
            dst: opt.dst.clone(),
        })
    }

    pub async fn proxy_stream(
        &self,
        stream: Box<dyn AsyncReadWrite>,
    ) -> std::io::Result<Box<dyn AsyncReadWrite>> {
        let idx = rand_range(0..self.user.len());
        let vmess_stream = VmessStream::new(
            stream,
            &self.user[idx],
            &self.dst,
            &self.security,
            self.is_aead,
            self.is_udp,
        )
        .await?;

        Ok(Box::new(vmess_stream))
    }
}

// ============================================================================
// VmessOutbound 主结构
// ============================================================================

pub struct VmessOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    uuid: Uuid,
    #[allow(dead_code)]
    alter_id: u16,
    use_aead: bool,
    cipher: VmessCipher,
    udp_enabled: bool,
    #[allow(dead_code)]
    cmd_key: [u8; 16],
    transport: VmessTransport,
    tls_enabled: bool,
    skip_cert_verify: bool,
    sni: Option<String>,
    ws_opts: Option<VmessWsOptions>,
    #[allow(dead_code)]
    h2_opts: Option<VmessH2Options>,
    #[allow(dead_code)]
    grpc_opts: Option<VmessGrpcOptions>,
    mkcp_opts: Option<VmessMkcpOptions>,
    mux_opts: VmessMuxOptions,
    quic_endpoint: Mutex<Option<Endpoint>>,
    quic_connection: Mutex<Option<quinn::Connection>>,
    quic_alpn: Vec<String>,
    udp_sessions: DashMap<String, Arc<UdpSession>>,
}

/// UDP 会话
#[allow(dead_code)]
struct UdpSession {
    stream: Mutex<Box<dyn AsyncReadWrite>>,
    last_used: std::sync::RwLock<Instant>,
}

#[allow(dead_code)]
impl UdpSession {
    fn new(stream: Box<dyn AsyncReadWrite>) -> Self {
        Self {
            stream: Mutex::new(stream),
            last_used: std::sync::RwLock::new(Instant::now()),
        }
    }

    fn touch(&self) {
        if let Ok(mut guard) = self.last_used.write() {
            *guard = Instant::now();
        }
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_used
            .read()
            .map(|g| g.elapsed() > timeout)
            .unwrap_or(true)
    }
}

impl VmessOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        time_sync::init_time_sync();

        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server"))?;
        let port = config.port.ok_or_else(|| Error::config("Missing port"))?;

        let uuid_str = config
            .options
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Missing UUID"))?;

        let uuid =
            Uuid::parse_str(uuid_str).map_err(|e| Error::config(format!("Invalid UUID: {}", e)))?;

        let alter_id = config
            .options
            .get("alterId")
            .or_else(|| config.options.get("alter-id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as u16;

        // VMess AEAD 模式仅在 alterId == 0 时启用
        // alterId > 0 时必须使用 Legacy (非AEAD) 模式
        let use_aead = alter_id == 0;

        if !use_aead {
            tracing::info!(
                "VMess '{}': alterId={} > 0, using legacy non-AEAD mode. \
                Consider using alterId=0 for better security and performance.",
                config.tag,
                alter_id
            );
        }

        let cipher_str = config
            .options
            .get("cipher")
            .or_else(|| config.options.get("security"))
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
            let max_early_data = ws_opts_value
                .and_then(|v| v.get("max-early-data"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as usize;
            let early_data_header_name = ws_opts_value
                .and_then(|v| v.get("early-data-header-name"))
                .and_then(|v| v.as_str())
                .unwrap_or("Sec-WebSocket-Protocol")
                .to_string();

            let mut headers = HashMap::new();
            if let Some(hdrs) = ws_opts_value
                .and_then(|v| v.get("headers"))
                .and_then(|v| v.as_mapping())
            {
                for (k, v) in hdrs {
                    if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                        headers.insert(key.to_string(), val.to_string());
                    }
                }
            }
            Some(VmessWsOptions {
                path,
                host,
                headers,
                max_early_data,
                early_data_header_name,
            })
        } else {
            None
        };

        let h2_opts = if transport == VmessTransport::H2 {
            let h2_opts_value = config.options.get("h2-opts");
            let hosts = h2_opts_value
                .and_then(|v| v.get("host"))
                .and_then(|v| v.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_else(|| vec![server.clone()]);
            let path = h2_opts_value
                .and_then(|v| v.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let mut headers = HashMap::new();
            if let Some(hdrs) = h2_opts_value
                .and_then(|v| v.get("headers"))
                .and_then(|v| v.as_mapping())
            {
                for (k, v) in hdrs {
                    if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                        headers.insert(key.to_string(), val.to_string());
                    }
                }
            }
            Some(VmessH2Options {
                hosts,
                path,
                headers,
            })
        } else {
            None
        };

        // 解析 gRPC 选项
        let grpc_opts = if transport == VmessTransport::Grpc {
            let grpc_opts_value = config.options.get("grpc-opts");
            let service_name = grpc_opts_value
                .and_then(|v| v.get("grpc-service-name"))
                .and_then(|v| v.as_str())
                .unwrap_or("GunService")
                .to_string();
            Some(VmessGrpcOptions { service_name })
        } else {
            None
        };

        // 解析 mKCP 选项
        let mkcp_opts = if transport == VmessTransport::Mkcp {
            let opts = config
                .options
                .get("kcp-opts")
                .or_else(|| config.options.get("mkcp-opts"));
            Some(VmessMkcpOptions {
                mtu: opts
                    .and_then(|v| v.get("mtu"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1350) as usize,
                tti: opts
                    .and_then(|v| v.get("tti"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(50) as u32,
                uplink_capacity: opts
                    .and_then(|v| v.get("uplinkCapacity").or_else(|| v.get("uplink-capacity")))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(5) as u32,
                downlink_capacity: opts
                    .and_then(|v| {
                        v.get("downlinkCapacity")
                            .or_else(|| v.get("downlink-capacity"))
                    })
                    .and_then(|v| v.as_i64())
                    .unwrap_or(20) as u32,
                congestion: opts
                    .and_then(|v| v.get("congestion"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                read_buffer_size: opts
                    .and_then(|v| {
                        v.get("readBufferSize")
                            .or_else(|| v.get("read-buffer-size"))
                    })
                    .and_then(|v| v.as_i64())
                    .unwrap_or(4 * 1024 * 1024) as usize,
                write_buffer_size: opts
                    .and_then(|v| {
                        v.get("writeBufferSize")
                            .or_else(|| v.get("write-buffer-size"))
                    })
                    .and_then(|v| v.as_i64())
                    .unwrap_or(4 * 1024 * 1024) as usize,
                header_type: opts
                    .and_then(|v| v.get("header"))
                    .and_then(|v| v.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("none")
                    .to_string(),
                seed: opts
                    .and_then(|v| v.get("seed"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
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

        let cmd_key = generate_cmd_key(uuid.as_bytes());

        tracing::info!(
            "VMess outbound '{}': {}:{}, uuid={}, alter_id={}, transport={:?}, tls={}, udp={}, aead={}",
            config.tag,
            server,
            port,
            uuid,
            alter_id,
            transport,
            tls_enabled,
            udp_enabled,
            use_aead
        );

        Ok(Self {
            config,
            server,
            port,
            uuid,
            alter_id,
            use_aead,
            cipher,
            udp_enabled,
            cmd_key,
            transport,
            tls_enabled,
            skip_cert_verify,
            sni,
            ws_opts,
            h2_opts,
            grpc_opts,
            mkcp_opts,
            mux_opts,
            quic_endpoint: Mutex::new(None),
            quic_connection: Mutex::new(None),
            quic_alpn,
            udp_sessions: DashMap::new(),
        })
    }

    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }
    pub fn is_mux_enabled(&self) -> bool {
        self.mux_opts.enabled
    }
    pub fn mux_concurrency(&self) -> usize {
        self.mux_opts.concurrency
    }
    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    async fn connect_tcp(&self) -> Result<TcpStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("DNS lookup failed: {}", e)))?
            .next()
            .ok_or_else(|| Error::network("No addresses found"))?;

        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(socket_addr))
            .await
            .map_err(|_| Error::network("TCP connect timeout"))?
            .map_err(|e| Error::network(format!("TCP connect failed: {}", e)))
    }

    async fn connect_tls(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = self.connect_tcp().await?;
        let sni = self.sni.as_deref().unwrap_or(&self.server);

        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            root_store.add(cert).ok();
        }

        let tls_config = if self.skip_cert_verify {
            let verifier = Arc::new(SkipServerVerification);
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
            .map_err(|_| Error::config(format!("Invalid SNI: {}", sni)))?;

        tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
            .await
            .map_err(|_| Error::network("TLS handshake timeout"))?
            .map_err(|e| Error::network(format!("TLS handshake failed: {}", e)))
    }

    async fn connect_stream(&self) -> Result<Box<dyn AsyncReadWrite>> {
        match self.transport {
            VmessTransport::Tcp => {
                tracing::debug!(
                    "[VMess] Connecting via TCP to {}:{}",
                    self.server,
                    self.port
                );
                if self.tls_enabled {
                    Ok(Box::new(self.connect_tls().await?) as Box<dyn AsyncReadWrite>)
                } else {
                    Ok(Box::new(self.connect_tcp().await?) as Box<dyn AsyncReadWrite>)
                }
            }
            VmessTransport::Ws => {
                tracing::info!(
                    "[VMess] Connecting via WebSocket to {}:{}, tls={}",
                    self.server,
                    self.port,
                    self.tls_enabled
                );

                let stream: Box<dyn AsyncReadWrite> = if self.tls_enabled {
                    tracing::debug!("[VMess] Establishing TLS connection...");
                    Box::new(self.connect_tls().await?)
                } else {
                    tracing::debug!("[VMess] Establishing TCP connection...");
                    Box::new(self.connect_tcp().await?)
                };
                tracing::debug!("[VMess] Transport connection established");

                let ws_opts = self.ws_opts.as_ref().unwrap();
                let host = ws_opts.host.as_deref().unwrap_or(&self.server);

                tracing::info!(
                    "[VMess] Starting WebSocket handshake: host={}, path={}, headers={:?}",
                    host,
                    ws_opts.path,
                    ws_opts.headers.keys().collect::<Vec<_>>()
                );

                let ws = WebSocketStream::handshake(stream, host, &ws_opts.path, &ws_opts.headers)
                    .await?;

                tracing::info!("[VMess] ✓ WebSocket handshake completed successfully");
                Ok(Box::new(ws) as Box<dyn AsyncReadWrite>)
            }
            VmessTransport::Quic => {
                let stream = self.connect_quic().await?;
                Ok(Box::new(stream) as Box<dyn AsyncReadWrite>)
            }
            VmessTransport::Mkcp => {
                let stream = self.connect_mkcp().await?;
                Ok(Box::new(stream) as Box<dyn AsyncReadWrite>)
            }
            VmessTransport::H2 => {
                let tls_stream = self.connect_tls().await?;
                let h2_opts = self.h2_opts.as_ref().unwrap();

                let h2_config = crate::transport::h2::H2Config {
                    hosts: if h2_opts.hosts.is_empty() {
                        vec![self.server.clone()]
                    } else {
                        h2_opts.hosts.clone()
                    },
                    headers: h2_opts.headers.clone(),
                    method: http::Method::GET,
                    path: h2_opts.path.clone(),
                };

                let h2_client = crate::transport::h2::H2Client::new(h2_config)?;
                let h2_stream = h2_client.proxy_stream(tls_stream).await?;
                Ok(Box::new(h2_stream) as Box<dyn AsyncReadWrite>)
            }
            VmessTransport::Grpc => {
                let tls_stream = self.connect_tls().await?;
                let grpc_opts = self.grpc_opts.as_ref().unwrap();

                let grpc_config = crate::transport::grpc::GrpcConfig {
                    host: self.sni.clone().unwrap_or_else(|| self.server.clone()),
                    service_name: grpc_opts.service_name.clone(),
                };

                let grpc_client = crate::transport::grpc::GrpcClient::new(grpc_config)?;
                let grpc_stream = grpc_client.proxy_stream(tls_stream).await?;
                Ok(Box::new(grpc_stream) as Box<dyn AsyncReadWrite>)
            }
        }
    }

    async fn connect_quic(&self) -> Result<QuicBiStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("DNS lookup failed: {}", e)))?
            .next()
            .ok_or_else(|| Error::network("No addresses found"))?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            root_store.add(cert).ok();
        }

        let mut tls_config = if self.skip_cert_verify {
            let verifier = Arc::new(SkipServerVerification);
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
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

        let client_config = QuinnClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(|e| Error::config(format!("QUIC config error: {}", e)))?,
        ));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| Error::network(format!("QUIC endpoint error: {}", e)))?;
        endpoint.set_default_client_config(client_config);

        let sni = self.sni.as_deref().unwrap_or(&self.server);
        let conn = endpoint
            .connect(socket_addr, sni)
            .map_err(|e| Error::network(format!("QUIC connect error: {}", e)))?
            .await
            .map_err(|e| Error::network(format!("QUIC connection failed: {}", e)))?;

        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::network(format!("QUIC stream error: {}", e)))?;

        *self.quic_endpoint.lock().await = Some(endpoint);
        *self.quic_connection.lock().await = Some(conn);

        Ok(QuicBiStream::new(send, recv))
    }

    async fn connect_mkcp(&self) -> Result<crate::transport::mkcp::MkcpStream> {
        use crate::transport::mkcp::{MkcpConfig, MkcpHeaderType, MkcpStream};

        let addr = format!("{}:{}", self.server, self.port);
        let socket_addr: SocketAddr = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| Error::network(format!("DNS lookup failed: {}", e)))?
            .next()
            .ok_or_else(|| Error::network("No addresses found"))?;

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

        MkcpStream::connect(socket_addr, mkcp_config).await
    }

    pub fn cleanup_udp_sessions(&self) {
        let expired: Vec<_> = self
            .udp_sessions
            .iter()
            .filter(|e| e.value().is_expired(Duration::from_secs(120)))
            .map(|e| e.key().clone())
            .collect();

        for key in expired {
            self.udp_sessions.remove(&key);
            tracing::debug!("Removed expired UDP session: {}", key);
        }
    }

    async fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let stream = self.connect_stream().await?;
        let id = VmessId::new(&self.uuid);
        let security = self.cipher.as_byte();

        let mut vmess_stream =
            VmessStream::new(stream, &id, target, &security, self.use_aead, true)
                .await
                .map_err(|e| Error::protocol(format!("VMess UDP handshake failed: {}", e)))?;

        vmess_stream
            .write_all(data)
            .await
            .map_err(|e| Error::network(format!("Failed to send UDP data: {}", e)))?;
        vmess_stream.flush().await.ok();

        let mut response = vec![0u8; 65535];
        let n = tokio::time::timeout(Duration::from_secs(10), vmess_stream.read(&mut response))
            .await
            .map_err(|_| Error::network("UDP response timeout"))?
            .map_err(|e| Error::network(format!("Failed to read UDP response: {}", e)))?;

        response.truncate(n);
        Ok(response)
    }
}

// ============================================================================
// OutboundProxy Trait 实现
// ============================================================================

fn is_connection_closed_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
    )
}

#[async_trait::async_trait]
impl OutboundProxy for VmessOutbound {
    async fn connect(&self) -> Result<()> {
        let _stream = self.connect_tcp().await?;
        tracing::info!(
            "VMess '{}' can reach {}:{}",
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
            return Err(Error::config("UDP not enabled"));
        }
        self.relay_udp(target, data).await
    }

    async fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();

        let url =
            url::Url::parse(test_url).map_err(|e| Error::config(format!("Invalid URL: {}", e)))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Missing host"))?;
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = url.path();

        let target = TargetAddr::Domain(host.to_string(), port);
        let outbound = self.connect_stream().await?;
        let id = VmessId::new(&self.uuid);
        let security = self.cipher.as_byte();

        let mut vmess_stream = tokio::time::timeout(
            timeout,
            VmessStream::new(outbound, &id, &target, &security, self.use_aead, false),
        )
        .await
        .map_err(|_| Error::network("VMess handshake timeout"))?
        .map_err(|e| Error::protocol(format!("VMess handshake failed: {}", e)))?;

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );

        vmess_stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::network(format!("Failed to send request: {}", e)))?;
        vmess_stream.flush().await.ok();
        let mut response = vec![0u8; 1024];
        tokio::time::timeout(timeout, vmess_stream.read(&mut response))
            .await
            .map_err(|_| Error::network("Response timeout"))?
            .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?;

        Ok(start.elapsed())
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
        tracing::info!(
            "[VMess] Starting relay to {} via {}:{}, transport={:?}, tls={}, is_aead={}",
            target,
            self.server,
            self.port,
            self.transport,
            self.tls_enabled,
            self.use_aead
        );

        let sync_result = time_sync::ensure_time_synced().await;
        if !sync_result.success && time_sync::needs_resync() {
            tracing::warn!(
                "NTP sync failed, VMess connection may fail due to time drift: {:?}",
                sync_result.error
            );
        }

        tracing::debug!("[VMess] Connecting to transport layer...");
        let outbound = self.connect_stream().await.map_err(|e| {
            tracing::error!("[VMess] Transport connection failed: {}", e);
            e
        })?;
        tracing::debug!("[VMess] Transport connected, starting VMess handshake...");

        let id = VmessId::new(&self.uuid);
        let security = self.cipher.as_byte();

        tracing::debug!(
            "[VMess] Creating VMess stream: target={}, security={:02x}, is_aead={}, is_udp=false",
            target,
            security,
            self.use_aead
        );

        let vmess_stream = tokio::time::timeout(
            Duration::from_secs(10),
            VmessStream::new(outbound, &id, &target, &security, self.use_aead, false),
        )
        .await
        .map_err(|_| {
            tracing::error!("[VMess] Handshake timeout after 10s for target {}", target);
            Error::network("VMess handshake timeout")
        })?
        .map_err(|e| {
            tracing::error!("[VMess] Handshake failed for target {}: {}", target, e);
            Error::protocol(format!("VMess handshake failed: {}", e))
        })?;

        tracing::info!(
            "[VMess] ✓ Handshake completed successfully, starting data relay to {}",
            target
        );

        let (mut inbound_read, mut inbound_write) = tokio::io::split(inbound);
        let (mut vmess_read, mut vmess_write) = tokio::io::split(vmess_stream);

        let upload_conn = connection.clone();
        let download_conn = connection;

        // Upload: inbound -> vmess
        let upload = async {
            let mut buf = vec![0u8; 16 * 1024];
            let mut total = 0u64;
            tracing::debug!("[VMess] Upload task started");
            loop {
                match inbound_read.read(&mut buf).await {
                    Ok(0) => {
                        tracing::debug!("[VMess] Upload: inbound EOF");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = vmess_write.write_all(&buf[..n]).await {
                            if !is_connection_closed_error(&e) {
                                tracing::debug!("[VMess] Upload write error: {}", e);
                            }
                            break;
                        }
                        total += n as u64;
                        if let Some(ref conn) = upload_conn {
                            conn.add_upload(n as u64);
                        }
                        if total == n as u64 {
                            tracing::debug!("[VMess] Upload: first {} bytes sent", n);
                        }
                    }
                    Err(e) => {
                        if !is_connection_closed_error(&e) {
                            tracing::debug!("[VMess] Upload read error: {}", e);
                        }
                        break;
                    }
                }
            }
            let _ = vmess_write.shutdown().await;
            tracing::debug!("[VMess] Upload finished: {} bytes total", total);
        };

        let download = async {
            let mut buf = vec![0u8; 16 * 1024];
            let mut total = 0u64;
            tracing::debug!("[VMess] Download task started");
            loop {
                match vmess_read.read(&mut buf).await {
                    Ok(0) => {
                        tracing::debug!("[VMess] Download: vmess EOF");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = inbound_write.write_all(&buf[..n]).await {
                            if !is_connection_closed_error(&e) {
                                tracing::debug!("[VMess] Download write error: {}", e);
                            }
                            break;
                        }
                        total += n as u64;
                        if let Some(ref conn) = download_conn {
                            conn.add_download(n as u64);
                        }
                        if total == n as u64 {
                            tracing::debug!("[VMess] Download: first {} bytes received", n);
                        }
                    }
                    Err(e) => {
                        if !is_connection_closed_error(&e) {
                            tracing::debug!("[VMess] Download read error: {}", e);
                        }
                        break;
                    }
                }
            }
            let _ = inbound_write.shutdown().await;
            tracing::debug!("[VMess] Download finished: {} bytes total", total);
        };

        tokio::join!(upload, download);
        Ok(())
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_cipher_from_str() {
        assert_eq!(VmessCipher::from_str("aes-128-gcm"), VmessCipher::Aes128Gcm);
        assert_eq!(
            VmessCipher::from_str("chacha20-poly1305"),
            VmessCipher::Chacha20Poly1305
        );
        assert_eq!(VmessCipher::from_str("none"), VmessCipher::None);
        assert_eq!(VmessCipher::from_str("auto"), VmessCipher::Auto);
        assert_eq!(VmessCipher::from_str("unknown"), VmessCipher::Auto);
    }

    #[test]
    fn test_vmess_cipher_as_byte() {
        assert_eq!(VmessCipher::Aes128Gcm.as_byte(), SECURITY_AES_128_GCM);
        assert_eq!(
            VmessCipher::Chacha20Poly1305.as_byte(),
            SECURITY_CHACHA20_POLY1305
        );
        assert_eq!(VmessCipher::None.as_byte(), SECURITY_NONE);
    }

    #[test]
    fn test_fnv1a_hash() {
        let data = b"hello world";
        let hash = fnv1a_hash(data);
        assert_ne!(hash, 0);

        let hash2 = fnv1a_hash(data);
        assert_eq!(hash, hash2);

        let hash3 = fnv1a_hash(b"different");
        assert_ne!(hash, hash3);
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
    fn test_vmess_kdf_1_one_shot() {
        let result = vmess_kdf_1_one_shot(b"test", KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
        assert_eq!(
            result.to_vec(),
            vec![
                149, 109, 253, 20, 158, 39, 112, 199, 28, 74, 3, 106, 99, 8, 234, 59, 64, 172, 126,
                5, 155, 28, 59, 21, 220, 196, 241, 54, 138, 5, 71, 107
            ]
        );
    }

    #[test]
    fn test_vmess_kdf_3_one_shot() {
        let result = vmess_kdf_3_one_shot(
            b"test",
            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
            KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
        );
        assert_eq!(
            result.to_vec(),
            vec![
                243, 80, 193, 249, 151, 10, 93, 168, 117, 239, 214, 89, 161, 130, 122, 81, 238,
                177, 51, 113, 21, 74, 73, 212, 199, 41, 75, 155, 49, 55, 217, 226
            ]
        );
    }

    #[test]
    fn test_vmess_id() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let id = VmessId::new(&uuid);
        assert_eq!(id.uuid, uuid);
        assert_eq!(id.cmd_key.len(), 16);
        assert_eq!(
            id.cmd_key,
            [181, 13, 145, 106, 192, 206, 192, 103, 152, 26, 248, 229, 243, 138, 117, 143]
        );
    }

    #[test]
    fn test_next_id() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let next = next_id(&uuid);
        assert_eq!(next.to_string(), "5a071834-12d5-980a-72ac-845d5568d17d");
    }

    #[test]
    fn test_vmess_address_serialization_ipv4() {
        let mut buf = BytesMut::new();
        let addr = TargetAddr::Ip("192.168.1.1:443".parse().unwrap());
        write_vmess_address!(buf, &addr);

        assert_eq!(buf.len(), 7);
        assert_eq!(&buf[0..2], &[0x01, 0xBB]);
        assert_eq!(buf[2], 0x01); // IPv4 类型
        assert_eq!(&buf[3..7], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_vmess_address_serialization_ipv6() {
        let mut buf = BytesMut::new();
        let addr = TargetAddr::Ip("[::1]:8080".parse().unwrap());
        write_vmess_address!(buf, &addr);

        assert_eq!(buf.len(), 19);
        assert_eq!(&buf[0..2], &[0x1F, 0x90]);
        assert_eq!(buf[2], 0x03);
    }

    #[test]
    fn test_vmess_address_serialization_domain() {
        let mut buf = BytesMut::new();
        let addr = TargetAddr::Domain("example.com".to_string(), 443);
        write_vmess_address!(buf, &addr);

        assert_eq!(buf.len(), 15); // 2 + 1 + 1 + 11
        assert_eq!(&buf[0..2], &[0x01, 0xBB]); // 端口 443
        assert_eq!(buf[2], 0x02); // Domain 类型
        assert_eq!(buf[3], 11); // 域名长度
        assert_eq!(&buf[4..15], b"example.com");
    }

    #[test]
    fn test_vmess_address_compatibility() {
        let mut buf = BytesMut::new();
        let addr = TargetAddr::Domain("google.com".to_string(), 80);
        write_vmess_address!(buf, &addr);

        assert_eq!(buf[0], 0x00); // 端口高字节
        assert_eq!(buf[1], 0x50); // 端口低字节 (80)
        assert_eq!(buf[2], 0x02); // 域名类型
        assert_eq!(buf[3], 10); // 域名长度
        assert_eq!(&buf[4..14], b"google.com");
    }

    #[test]
    fn test_create_auth_id() {
        let cmd_key = *b"1234567890123456";
        let timestamp = 0u64;
        let auth_id = create_auth_id(cmd_key, timestamp);
        assert_eq!(auth_id.len(), 16);
    }

    #[test]
    fn test_vmess_builder() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            udp: true,
            dst: TargetAddr::Domain("example.com".to_string(), 443),
        };

        let builder = VmessBuilder::new(&opt).unwrap();
        assert!(builder.is_aead);
        assert!(builder.is_udp);
        assert_eq!(builder.user.len(), 1);
    }

    #[test]
    fn test_vmess_builder_with_alter_id() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 4,
            security: "aes-128-gcm".to_string(),
            udp: false,
            dst: TargetAddr::Domain("example.com".to_string(), 443),
        };

        let builder = VmessBuilder::new(&opt).unwrap();
        assert!(builder.is_aead);
        assert!(!builder.is_udp);
        assert_eq!(builder.user.len(), 5);
        assert_eq!(builder.security, SECURITY_AES_128_GCM);
    }

    #[test]
    fn test_h2_config() {
        let config = crate::transport::h2::H2Config {
            hosts: vec!["example.com".to_string()],
            headers: HashMap::new(),
            method: http::Method::GET,
            path: "/vmess".to_string(),
        };

        let client = crate::transport::h2::H2Client::new(config).unwrap();
        assert_eq!(client.hosts.len(), 1);
        assert_eq!(client.hosts[0], "example.com");
    }

    #[test]
    fn test_grpc_config() {
        let config = crate::transport::grpc::GrpcConfig {
            host: "example.com".to_string(),
            service_name: "GunService".to_string(),
        };

        let client = crate::transport::grpc::GrpcClient::new(config).unwrap();
        assert_eq!(client.host, "example.com");
        assert_eq!(client.path.as_str(), "/GunService/Tun");
    }

    #[test]
    fn test_vmess_transport_from_str() {
        assert_eq!(VmessTransport::from_str("tcp"), VmessTransport::Tcp);
        assert_eq!(VmessTransport::from_str("ws"), VmessTransport::Ws);
        assert_eq!(VmessTransport::from_str("websocket"), VmessTransport::Ws);
        assert_eq!(VmessTransport::from_str("h2"), VmessTransport::H2);
        assert_eq!(VmessTransport::from_str("http2"), VmessTransport::H2);
        assert_eq!(VmessTransport::from_str("grpc"), VmessTransport::Grpc);
        assert_eq!(VmessTransport::from_str("quic"), VmessTransport::Quic);
        assert_eq!(VmessTransport::from_str("kcp"), VmessTransport::Mkcp);
        assert_eq!(VmessTransport::from_str("mkcp"), VmessTransport::Mkcp);
        assert_eq!(VmessTransport::from_str("unknown"), VmessTransport::Tcp);
    }
}
