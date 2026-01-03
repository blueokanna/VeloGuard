//! Configuration types for VeloGuard QUIC

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Supported cipher types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CipherKind {
    #[default]
    Aes256Gcm,
    Aes128Gcm,
    Chacha20Poly1305,
    #[serde(alias = "2022-blake3-aes-256-gcm")]
    Aead2022Aes256Gcm,
    #[serde(alias = "2022-blake3-aes-128-gcm")]
    Aead2022Aes128Gcm,
    #[serde(alias = "2022-blake3-chacha20-poly1305")]
    Aead2022Chacha20Poly1305,
}

impl CipherKind {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            "2022-blake3-aes-256-gcm" => Some(Self::Aead2022Aes256Gcm),
            "2022-blake3-aes-128-gcm" => Some(Self::Aead2022Aes128Gcm),
            "2022-blake3-chacha20-ietf-poly1305" | "2022-blake3-chacha20-poly1305" => {
                Some(Self::Aead2022Chacha20Poly1305)
            }
            _ => None,
        }
    }

    /// Key size in bytes
    #[inline]
    pub const fn key_size(&self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aead2022Aes128Gcm => 16,
            _ => 32,
        }
    }

    /// Nonce size (always 12 bytes for supported ciphers)
    #[inline]
    pub const fn nonce_size(&self) -> usize {
        12
    }

    /// Tag size (always 16 bytes for supported ciphers)
    #[inline]
    pub const fn tag_size(&self) -> usize {
        16
    }

    /// Check if AEAD 2022 cipher
    #[inline]
    pub const fn is_aead_2022(&self) -> bool {
        matches!(
            self,
            Self::Aead2022Aes256Gcm | Self::Aead2022Aes128Gcm | Self::Aead2022Chacha20Poly1305
        )
    }
}

/// Congestion control algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default = "defaults::idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,

    #[serde(default = "defaults::keep_alive", with = "option_duration")]
    pub keep_alive_interval: Option<Duration>,

    #[serde(default = "defaults::max_bi_streams")]
    pub max_concurrent_bi_streams: u32,

    #[serde(default = "defaults::max_uni_streams")]
    pub max_concurrent_uni_streams: u32,

    #[serde(default = "defaults::initial_rtt", with = "humantime_serde")]
    pub initial_rtt: Duration,

    #[serde(default = "defaults::zero_rtt")]
    pub zero_rtt: bool,

    #[serde(default)]
    pub congestion_control: CongestionControl,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            idle_timeout: defaults::idle_timeout(),
            keep_alive_interval: defaults::keep_alive(),
            max_concurrent_bi_streams: defaults::max_bi_streams(),
            max_concurrent_uni_streams: defaults::max_uni_streams(),
            initial_rtt: defaults::initial_rtt(),
            zero_rtt: defaults::zero_rtt(),
            congestion_control: CongestionControl::default(),
        }
    }
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub password: String,

    #[serde(default)]
    pub cipher: CipherKind,

    /// SNI server name for camouflage
    pub server_name: Option<String>,

    #[serde(default = "defaults::alpn")]
    pub alpn: Vec<String>,

    #[serde(default)]
    pub skip_cert_verify: bool,

    #[serde(default)]
    pub transport: TransportConfig,

    pub local_addr: Option<SocketAddr>,

    #[serde(default = "defaults::udp_relay")]
    pub udp_relay: bool,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub password: String,

    #[serde(default)]
    pub cipher: CipherKind,

    /// TLS certificate (PEM)
    pub certificate: String,

    /// TLS private key (PEM)
    pub private_key: String,

    #[serde(default = "defaults::alpn")]
    pub alpn: Vec<String>,

    #[serde(default)]
    pub transport: TransportConfig,

    #[serde(default = "defaults::udp_relay")]
    pub udp_relay: bool,

    /// Fallback server for SNI camouflage
    pub fallback: Option<SocketAddr>,
}

mod defaults {
    use std::time::Duration;

    pub fn idle_timeout() -> Duration {
        Duration::from_secs(30)
    }

    pub fn keep_alive() -> Option<Duration> {
        Some(Duration::from_secs(15))
    }

    pub fn max_bi_streams() -> u32 {
        100
    }

    pub fn max_uni_streams() -> u32 {
        100
    }

    pub fn initial_rtt() -> Duration {
        Duration::from_millis(100)
    }

    pub fn zero_rtt() -> bool {
        true
    }

    pub fn alpn() -> Vec<String> {
        vec!["h3".into(), "h3-29".into()]
    }

    pub fn udp_relay() -> bool {
        true
    }
}

mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

mod option_duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => serializer.serialize_some(&d.as_secs()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<u64>::deserialize(deserializer)?;
        Ok(opt.map(Duration::from_secs))
    }
}
