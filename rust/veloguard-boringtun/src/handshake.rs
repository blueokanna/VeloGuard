use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto;
use crate::BoringTunError;

/// Handshake state machine states
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    /// No handshake in progress
    None,
    /// Sent handshake initiation, waiting for response
    InitiationSent,
    /// Received handshake initiation, sent response
    ResponseSent,
    /// Handshake completed, keys established
    Completed,
}

/// Handshake initiation message
#[derive(Debug, Clone)]
pub struct HandshakeInitiation {
    pub sender_index: u32,
    pub ephemeral_public_key: [u8; 32],
    pub static_public_key: [u8; 32],
    pub timestamp: u64,
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

/// Handshake response message
#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral_public_key: [u8; 32],
    pub empty: [u8; 16], // Empty cookie
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

/// Handshake state for a peer
pub struct Handshake {
    state: HandshakeState,
    _local_private_key: [u8; 32],
    local_public_key: [u8; 32],
    remote_public_key: Option<[u8; 32]>,
    preshared_key: Option<[u8; 32]>,
    local_index: u32,
    remote_index: Option<u32>,
    chaining_key: Option<[u8; 32]>,
    hash: Option<[u8; 32]>,
    sending_key: Option<[u8; 32]>,
    receiving_key: Option<[u8; 32]>,
    sending_counter: u64,
    receiving_counter: u64,
}

impl Handshake {
    /// Create a new handshake state
    pub fn new(local_private_key: [u8; 32], local_index: u32) -> Self {
        let local_public_key = crypto::public_key(&local_private_key);

        Self {
            state: HandshakeState::None,
            _local_private_key: local_private_key,
            local_public_key,
            remote_public_key: None,
            preshared_key: None,
            local_index,
            remote_index: None,
            chaining_key: None,
            hash: None,
            sending_key: None,
            receiving_key: None,
            sending_counter: 0,
            receiving_counter: 0,
        }
    }

    /// Set the remote public key
    pub fn set_remote_public_key(&mut self, remote_public_key: [u8; 32]) {
        self.remote_public_key = Some(remote_public_key);
    }

    /// Set the preshared key
    pub fn set_preshared_key(&mut self, preshared_key: [u8; 32]) {
        self.preshared_key = Some(preshared_key);
    }

    /// Create a handshake initiation message
    pub fn create_initiation(&mut self) -> Result<HandshakeInitiation, BoringTunError> {
        if self.remote_public_key.is_none() {
            return Err(BoringTunError::InvalidConfig);
        }

        // Generate ephemeral key pair
        let ephemeral_private = crypto::generate_private_key();
        let ephemeral_public = crypto::public_key(&ephemeral_private);

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create initiation message
        let initiation = HandshakeInitiation {
            sender_index: self.local_index,
            ephemeral_public_key: ephemeral_public,
            static_public_key: self.local_public_key,
            timestamp: timestamp << 24, // WireGuard timestamp format
            mac1: [0u8; 16], // Simplified - would compute MAC
            mac2: [0u8; 16], // Simplified - would compute MAC
        };

        self.state = HandshakeState::InitiationSent;

        Ok(initiation)
    }

    /// Process a handshake initiation message
    pub fn process_initiation(&mut self, initiation: &HandshakeInitiation) -> Result<HandshakeResponse, BoringTunError> {
        self.remote_index = Some(initiation.sender_index);

        // Generate ephemeral key pair for response
        let ephemeral_private = crypto::generate_private_key();
        let ephemeral_public = crypto::public_key(&ephemeral_private);

        // Create response message
        let response = HandshakeResponse {
            sender_index: self.local_index,
            receiver_index: initiation.sender_index,
            ephemeral_public_key: ephemeral_public,
            empty: [0u8; 16],
            mac1: [0u8; 16], // Simplified - would compute MAC
            mac2: [0u8; 16], // Simplified - would compute MAC
        };

        self.state = HandshakeState::ResponseSent;

        Ok(response)
    }

    /// Process a handshake response message
    pub fn process_response(&mut self, response: &HandshakeResponse) -> Result<(), BoringTunError> {
        if self.state != HandshakeState::InitiationSent {
            return Err(BoringTunError::Handshake("Invalid state for response".to_string()));
        }

        // Verify response is for our initiation
        if response.receiver_index != self.local_index {
            return Err(BoringTunError::Handshake("Response index mismatch".to_string()));
        }

        self.remote_index = Some(response.sender_index);
        self.state = HandshakeState::Completed;

        // In a real implementation, we would:
        // 1. Perform the Noise protocol key derivation
        // 2. Establish sending and receiving keys
        // 3. Set up counters

        Ok(())
    }

    /// Check if handshake is completed
    pub fn is_completed(&self) -> bool {
        self.state == HandshakeState::Completed
    }

    /// Get the current handshake state
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Encrypt a data packet
    pub fn encrypt_packet(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, BoringTunError> {
        if !self.is_completed() {
            return Err(BoringTunError::Handshake("Handshake not completed".to_string()));
        }

        // Simplified - in real implementation would use established keys
        crypto::aead_encrypt(&[1u8; 32], self.sending_counter, plaintext, &[])
    }

    /// Decrypt a data packet
    pub fn decrypt_packet(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, BoringTunError> {
        if !self.is_completed() {
            return Err(BoringTunError::Handshake("Handshake not completed".to_string()));
        }

        // Simplified - in real implementation would use established keys
        crypto::aead_decrypt(&[1u8; 32], self.receiving_counter, ciphertext, &[])
    }

    /// Reset the handshake state
    pub fn reset(&mut self) {
        self.state = HandshakeState::None;
        self.remote_index = None;
        self.chaining_key = None;
        self.hash = None;
        self.sending_key = None;
        self.receiving_key = None;
        self.sending_counter = 0;
        self.receiving_counter = 0;
    }
}

/// Noise protocol constants
pub mod constants {
    pub const NOISE_PROTOCOL_NAME: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    pub const NOISE_HANDSHAKE_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    pub const NOISE_HANDSHAKE_CHACHING: &str = "0000000000000000000000000000000000000000000000000000000000000000";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_creation() {
        let private_key = crypto::generate_private_key();
        let handshake = Handshake::new(private_key, 1);

        assert_eq!(handshake.state(), &HandshakeState::None);
        assert!(!handshake.is_completed());
    }

    #[test]
    fn test_handshake_flow() {
        let alice_private = crypto::generate_private_key();
        let alice_public = crypto::public_key(&alice_private);
        let mut alice = Handshake::new(alice_private, 1);
        alice.set_remote_public_key(alice_public); // Simplified for testing

        let bob_private = crypto::generate_private_key();
        let mut bob = Handshake::new(bob_private, 2);

        // Alice creates initiation
        let initiation = alice.create_initiation().unwrap();
        assert_eq!(alice.state(), &HandshakeState::InitiationSent);

        // Bob processes initiation and creates response
        let response = bob.process_initiation(&initiation).unwrap();
        assert_eq!(bob.state(), &HandshakeState::ResponseSent);

        // Alice processes response
        alice.process_response(&response).unwrap();
        assert_eq!(alice.state(), &HandshakeState::Completed);
        assert!(alice.is_completed());
    }
}
