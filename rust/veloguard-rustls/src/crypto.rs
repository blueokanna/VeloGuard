use crate::error::{Error, Result};
use ring::rand::SecureRandom;
use ring::signature::{RsaKeyPair, EcdsaKeyPair};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::digest::{Context, SHA256, SHA384};
use std::sync::OnceLock;

/// TLS cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha256,
}

impl CipherSuite {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(CipherSuite::TlsAes128GcmSha256),
            0x1302 => Some(CipherSuite::TlsAes256GcmSha384),
            0x1303 => Some(CipherSuite::TlsChacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 0x1301,
            CipherSuite::TlsAes256GcmSha384 => 0x1302,
            CipherSuite::TlsChacha20Poly1305Sha256 => 0x1303,
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 16,
            CipherSuite::TlsAes256GcmSha384 => 32,
            CipherSuite::TlsChacha20Poly1305Sha256 => 32,
        }
    }

    pub fn hash_algorithm(&self) -> &'static ring::digest::Algorithm {
        match self {
            CipherSuite::TlsAes128GcmSha256 => &SHA256,
            CipherSuite::TlsAes256GcmSha384 => &SHA384,
            CipherSuite::TlsChacha20Poly1305Sha256 => &SHA256,
        }
    }
}

/// Key exchange algorithms
#[derive(Debug)]
pub enum KeyExchange {
    Rsa,
    Ecdhe(EcdheKeyPair),
}

impl KeyExchange {
    pub fn generate(alg: KeyExchangeAlgorithm) -> Result<Self> {
        match alg {
            KeyExchangeAlgorithm::Rsa => Ok(KeyExchange::Rsa),
            KeyExchangeAlgorithm::EcdheX25519 => {
                let private_key = EphemeralPrivateKey::generate(&X25519, get_rng())
                    .map_err(|_| Error::KeyExchange("Failed to generate ECDHE key".to_string()))?;
                Ok(KeyExchange::Ecdhe(EcdheKeyPair { private_key }))
            }
        }
    }
}

/// Key exchange algorithms
#[derive(Debug, Clone, Copy)]
pub enum KeyExchangeAlgorithm {
    Rsa,
    EcdheX25519,
}

/// ECDHE key pair
#[derive(Debug)]
pub struct EcdheKeyPair {
    private_key: EphemeralPrivateKey,
}

impl EcdheKeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        self.private_key.compute_public_key()
            .map(|pk| pk.as_ref().to_vec())
            .unwrap_or_default()
    }

    pub fn agree(self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let peer_key = UnparsedPublicKey::new(&X25519, peer_public_key);
        ring::agreement::agree_ephemeral(
            self.private_key,
            &peer_key,
            |shared_secret| Ok(shared_secret.to_vec()),
        )
        .map_err(|_| Error::KeyExchange("Key agreement failed".to_string()))?
    }
}

/// Key material for encryption/decryption
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub cipher_suite: CipherSuite,
    pub key: Vec<u8>,
    pub nonce: [u8; 12],
    pub mac_key: Option<Vec<u8>>, // For TLS 1.2
}

/// TLS signature algorithms
#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp521r1Sha512,
}

/// Digital signature
pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// RSA signer
pub struct RsaSigner {
    key_pair: RsaKeyPair,
}

impl RsaSigner {
    pub fn new(key_pair: RsaKeyPair) -> Self {
        RsaSigner { key_pair }
    }
}

impl Signer for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rng = ring::rand::SystemRandom::new();
        let public_key = self.key_pair.public();
        let mut signature = vec![0; public_key.modulus_len()];
        self.key_pair.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, data, &mut signature)
            .map(|_| signature)
            .map_err(|_| Error::InvalidSignature)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RsaPkcs1Sha256
    }
}

/// ECDSA signer
pub struct EcdsaSigner {
    key_pair: EcdsaKeyPair,
}

impl EcdsaSigner {
    pub fn new(key_pair: EcdsaKeyPair) -> Self {
        EcdsaSigner { key_pair }
    }
}

impl Signer for EcdsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rng = ring::rand::SystemRandom::new();
        self.key_pair.sign(&rng, data)
            .map(|sig| sig.as_ref().to_vec())
            .map_err(|_| Error::InvalidSignature)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaSecp256r1Sha256
    }
}

/// Hash function
pub fn hash(algorithm: &'static ring::digest::Algorithm, data: &[u8]) -> Vec<u8> {
    let mut ctx = Context::new(algorithm);
    ctx.update(data);
    ctx.finish().as_ref().to_vec()
}

/// HMAC
pub fn hmac(key: &[u8], data: &[u8], algorithm: ring::hmac::Algorithm) -> Vec<u8> {
    let key = ring::hmac::Key::new(algorithm, key);
    ring::hmac::sign(&key, data).as_ref().to_vec()
}

/// HKDF expand
pub fn hkdf_expand(secret: &[u8], info: &[u8], len: usize, algorithm: ring::hkdf::Algorithm) -> Vec<u8> {
    let salt = ring::hkdf::Salt::new(algorithm, &[]);
    let prk = salt.extract(secret);
    let info_slice = &[info];
    let okm = prk.expand(info_slice, algorithm).unwrap();
    let mut output = vec![0u8; len];
    okm.fill(&mut output).unwrap();
    output
}

/// Random number generator
pub static RING_RAND: OnceLock<ring::rand::SystemRandom> = OnceLock::new();

/// Get random number generator
pub fn get_rng() -> &'static ring::rand::SystemRandom {
    RING_RAND.get_or_init(|| ring::rand::SystemRandom::new())
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    get_rng().fill(&mut buf)
        .map_err(|_| Error::Unsupported("Random generation failed".to_string()))?;
    Ok(buf)
}

/// Generate random array
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    get_rng().fill(&mut buf)
        .map_err(|_| Error::Unsupported("Random generation failed".to_string()))?;
    Ok(buf)
}
