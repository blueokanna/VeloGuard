//! Cryptographic operations for VeloGuard QUIC

use aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use blake2::{Blake2b512, Digest};
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::config::CipherKind;
use crate::error::{QuicError, Result};

/// AEAD cipher wrapper
pub enum Cipher {
    Aes256Gcm(Aes256Gcm),
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl Cipher {
    /// Create cipher from key
    pub fn new(kind: CipherKind, key: &[u8]) -> Result<Self> {
        let err = || QuicError::Crypto("Invalid key length".into());
        Ok(match kind {
            CipherKind::Aes256Gcm | CipherKind::Aead2022Aes256Gcm => {
                Self::Aes256Gcm(Aes256Gcm::new_from_slice(key).map_err(|_| err())?)
            }
            CipherKind::Aes128Gcm | CipherKind::Aead2022Aes128Gcm => {
                Self::Aes128Gcm(Aes128Gcm::new_from_slice(key).map_err(|_| err())?)
            }
            CipherKind::Chacha20Poly1305 | CipherKind::Aead2022Chacha20Poly1305 => {
                Self::ChaCha20Poly1305(ChaCha20Poly1305::new_from_slice(key).map_err(|_| err())?)
            }
        })
    }

    /// Encrypt with nonce
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        let result = match self {
            Self::Aes256Gcm(c) => c.encrypt(nonce, plaintext),
            Self::Aes128Gcm(c) => c.encrypt(nonce, plaintext),
            Self::ChaCha20Poly1305(c) => c.encrypt(nonce, plaintext),
        };
        result.map_err(|_| QuicError::EncryptionFailed)
    }

    /// Decrypt with nonce
    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        let result = match self {
            Self::Aes256Gcm(c) => c.decrypt(nonce, ciphertext),
            Self::Aes128Gcm(c) => c.decrypt(nonce, ciphertext),
            Self::ChaCha20Poly1305(c) => c.decrypt(nonce, ciphertext),
        };
        result.map_err(|_| QuicError::DecryptionFailed)
    }
}

/// Cryptographic context for a connection
#[derive(Clone)]
pub struct CryptoContext {
    cipher_kind: CipherKind,
    key: Vec<u8>,
    nonce_counter: u64,
}

impl CryptoContext {
    /// Create from password
    pub fn new(cipher_kind: CipherKind, password: &str) -> Self {
        Self {
            key: derive_key(cipher_kind, password),
            cipher_kind,
            nonce_counter: 0,
        }
    }

    /// Create from raw key
    pub fn from_key(cipher_kind: CipherKind, key: Vec<u8>) -> Self {
        Self {
            cipher_kind,
            key,
            nonce_counter: 0,
        }
    }

    #[inline]
    pub fn cipher_kind(&self) -> CipherKind {
        self.cipher_kind
    }

    pub fn cipher(&self) -> Result<Cipher> {
        Cipher::new(self.cipher_kind, &self.key)
    }

    /// Generate sequential nonce
    pub fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        nonce
    }

    /// Generate random nonce
    pub fn random_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt payload (prepends nonce)
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Bytes> {
        let cipher = self.cipher()?;
        let nonce = self.next_nonce();
        let ciphertext = cipher.encrypt(&nonce, plaintext)?;

        let mut output = BytesMut::with_capacity(12 + ciphertext.len());
        output.put_slice(&nonce);
        output.put_slice(&ciphertext);
        Ok(output.freeze())
    }

    /// Decrypt payload (extracts nonce from data)
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 28 {
            // 12 nonce + 16 tag minimum
            return Err(QuicError::BufferTooSmall);
        }
        let cipher = self.cipher()?;
        cipher.decrypt(&data[..12], &data[12..])
    }

    /// Encrypt with explicit nonce
    pub fn encrypt_with_nonce(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()?.encrypt(nonce, plaintext)
    }

    /// Decrypt with explicit nonce
    pub fn decrypt_with_nonce(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()?.decrypt(nonce, ciphertext)
    }
}

/// Derive key from password
pub fn derive_key(cipher_kind: CipherKind, password: &str) -> Vec<u8> {
    let key_size = cipher_kind.key_size();
    if cipher_kind.is_aead_2022() {
        derive_key_blake2b(password, key_size)
    } else {
        derive_key_hkdf(password, key_size)
    }
}

fn derive_key_hkdf(password: &str, key_size: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(b"shadowsocks"), password.as_bytes());
    let mut key = vec![0u8; key_size];
    hk.expand(b"ss-subkey", &mut key).expect("HKDF expand failed");
    key
}

fn derive_key_blake2b(password: &str, key_size: usize) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(password.as_bytes());
    hasher.finalize()[..key_size].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut ctx = CryptoContext::new(CipherKind::Aes256Gcm, "test-password");
        let plaintext = b"Hello, VeloGuard QUIC!";
        let encrypted = ctx.encrypt(plaintext).unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let key1 = derive_key(CipherKind::Aes256Gcm, "password");
        let key2 = derive_key(CipherKind::Aes256Gcm, "password");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_aead_2022_key() {
        let key = derive_key(CipherKind::Aead2022Aes256Gcm, "password");
        assert_eq!(key.len(), 32);
    }
}
