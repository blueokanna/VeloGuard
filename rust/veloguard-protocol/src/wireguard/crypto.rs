use blake2::{Blake2s256, Blake2sMac, Digest};
use blake2::digest::{KeyInit, Mac};
use chacha20poly1305::{ChaCha20Poly1305, aead::Aead};
use chacha20poly1305::aead::KeyInit as AeadKeyInit;
use x25519_dalek::{PublicKey, StaticSecret};

pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
#[allow(dead_code)]
pub const LABEL_COOKIE: &[u8] = b"cookie--";

pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
pub const REKEY_AFTER_TIME: u64 = 120;
pub const REJECT_AFTER_TIME: u64 = 180;
pub const REKEY_TIMEOUT: u64 = 5;
pub const KEEPALIVE_TIMEOUT: u64 = 10;

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacBlake2s = Blake2sMac<blake2::digest::consts::U32>;
    
    let mut mac = <HmacBlake2s as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    type MacBlake2s = Blake2sMac<blake2::digest::consts::U16>;
    
    let mut mac = <MacBlake2s as KeyInit>::new_from_slice(key).expect("MAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn kdf1(key: &[u8], input: &[u8]) -> [u8; 32] {
    let prk = hmac(key, input);
    hmac(&prk, &[0x01])
}

pub fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac(key, input);
    let t0 = hmac(&prk, &[0x01]);
    let mut t1_input = t0.to_vec();
    t1_input.push(0x02);
    let t1 = hmac(&prk, &t1_input);
    (t0, t1)
}

pub fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk = hmac(key, input);
    let t0 = hmac(&prk, &[0x01]);
    let mut t1_input = t0.to_vec();
    t1_input.push(0x02);
    let t1 = hmac(&prk, &t1_input);
    let mut t2_input = t1.to_vec();
    t2_input.push(0x03);
    let t2 = hmac(&prk, &t2_input);
    (t0, t1, t2)
}

pub fn dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(*public_key);
    *secret.diffie_hellman(&public).as_bytes()
}

pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(&secret);
    *public.as_bytes()
}

pub fn aead_encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = <ChaCha20Poly1305 as AeadKeyInit>::new_from_slice(key).expect("Invalid key length");
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce);
    cipher.encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad }).expect("Encryption failed")
}

pub fn aead_decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = <ChaCha20Poly1305 as AeadKeyInit>::new_from_slice(key).expect("Invalid key length");
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce);
    cipher.decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad }).ok()
}

pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes).expect("Failed to generate random bytes");
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

pub fn timestamp() -> [u8; 12] {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();
    
    let mut tai64n = [0u8; 12];
    tai64n[0..8].copy_from_slice(&(secs + 4611686018427387914u64).to_be_bytes());
    tai64n[8..12].copy_from_slice(&nanos.to_be_bytes());
    tai64n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"test data";
        let h1 = hash(data);
        let h2 = hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_hmac() {
        let key = b"test key";
        let data = b"test data";
        let h1 = hmac(key, data);
        let h2 = hmac(key, data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_kdf() {
        let key = [0u8; 32];
        let input = b"test input";
        let k1 = kdf1(&key, input);
        assert_eq!(k1.len(), 32);
        
        let (k2a, k2b) = kdf2(&key, input);
        assert_eq!(k2a.len(), 32);
        assert_eq!(k2b.len(), 32);
        assert_ne!(k2a, k2b);
    }

    #[test]
    fn test_dh() {
        let (priv1, pub1) = generate_keypair();
        let (priv2, pub2) = generate_keypair();
        
        let shared1 = dh(&priv1, &pub2);
        let shared2 = dh(&priv2, &pub1);
        
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"hello world";
        let aad = b"additional data";
        
        let ciphertext = aead_encrypt(&key, 0, plaintext, aad);
        let decrypted = aead_decrypt(&key, 0, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
