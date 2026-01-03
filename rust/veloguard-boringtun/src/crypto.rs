use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use chacha20poly1305::aead::Aead;
use hkdf::Hkdf;
use sha2::Sha256;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::montgomery::MontgomeryPoint;
use std::ops::Mul;
use zeroize::Zeroize;

use crate::BoringTunError;

/// Generate a new private key
pub fn generate_private_key() -> [u8; 32] {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // X25519 keys are automatically clamped by the library
    key
}

/// Derive public key from private key using X25519
pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*private_key);
    let base_point = MontgomeryPoint::default(); // This gives the base point
    let public_point = base_point.mul(&scalar);
    public_point.to_bytes()
}

/// Perform Diffie-Hellman key exchange using X25519
pub fn dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*private_key);
    let public_point = MontgomeryPoint(*public_key);
    let shared_point = public_point.mul(&scalar);
    shared_point.to_bytes()
}

/// Hash function (BLAKE2s)
pub fn hash(data: &[u8]) -> [u8; 32] {
    use blake2::Blake2s256;
    use blake2::Digest;

    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// HMAC-based Key Derivation Function
pub fn hkdf(chaining_key: &[u8; 32], input_key_material: &[u8], num_outputs: usize) -> Vec<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(chaining_key), input_key_material);

    let mut outputs = Vec::with_capacity(num_outputs);
    for i in 0..num_outputs {
        let mut output = [0u8; 32];
        hkdf.expand(&[i as u8 + 1], &mut output)
            .expect("HKDF expansion should not fail");
        outputs.push(output);
    }

    outputs
}

/// AEAD encryption
pub fn aead_encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8], _auth_data: &[u8]) -> Result<Vec<u8>, BoringTunError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = counter.to_le_bytes();
    let nonce = Nonce::from_slice(&nonce[..12]); // Use first 12 bytes for nonce

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| BoringTunError::Crypto(format!("Encryption failed: {:?}", e)))?;

    Ok(ciphertext)
}

/// AEAD decryption
pub fn aead_decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8], _auth_data: &[u8]) -> Result<Vec<u8>, BoringTunError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = counter.to_le_bytes();
    let nonce = Nonce::from_slice(&nonce[..12]); // Use first 12 bytes for nonce

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| BoringTunError::Crypto(format!("Decryption failed: {:?}", e)))?;

    Ok(plaintext)
}

/// Generate a random nonce (for testing)
pub fn generate_nonce() -> [u8; 12] {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    nonce
}

/// Key pair structure
pub struct KeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl KeyPair {
    pub fn new() -> Self {
        let private_key = generate_private_key();
        let public_key = public_key(&private_key);

        Self {
            private_key,
            public_key,
        }
    }

    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let public_key = public_key(&private_key);

        Self {
            private_key,
            public_key,
        }
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::new();

        // Public key should be different from private key
        assert_ne!(keypair.private_key, keypair.public_key);

        // Public key should be deterministic for the same private key
        let public_key2 = public_key(&keypair.private_key);
        assert_eq!(keypair.public_key, public_key2);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = KeyPair::new();
        let bob = KeyPair::new();

        let alice_shared = dh(&alice.private_key, &bob.public_key);
        let bob_shared = dh(&bob.private_key, &alice.public_key);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_hash() {
        let data = b"test data";
        let hash1 = hash(data);
        let hash2 = hash(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [1u8; 32];
        let plaintext = b"Hello, WireGuard!";

        let ciphertext = aead_encrypt(&key, 0, plaintext, &[]).unwrap();
        let decrypted = aead_decrypt(&key, 0, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
