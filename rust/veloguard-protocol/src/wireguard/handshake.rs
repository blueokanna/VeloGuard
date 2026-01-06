use super::crypto::{
    hash, kdf1, kdf2, kdf3, dh, aead_encrypt, aead_decrypt, mac, timestamp,
    CONSTRUCTION, IDENTIFIER, LABEL_MAC1,
};
use super::WireGuardError;

pub const MSG_TYPE_HANDSHAKE_INIT: u8 = 1;
pub const MSG_TYPE_HANDSHAKE_RESP: u8 = 2;
pub const MSG_TYPE_COOKIE_REPLY: u8 = 3;
pub const MSG_TYPE_TRANSPORT: u8 = 4;

#[derive(Debug, Clone)]
pub struct HandshakeInitiation {
    pub sender_index: u32,
    pub ephemeral_public: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral_public: [u8; 32],
    pub encrypted_nothing: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct TransportKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_index: u32,
    pub recv_index: u32,
}

pub struct HandshakeState {
    pub hash: [u8; 32],
    pub chaining_key: [u8; 32],
    pub ephemeral_private: [u8; 32],
    pub ephemeral_public: [u8; 32],
    pub static_private: [u8; 32],
    pub static_public: [u8; 32],
    pub remote_static: [u8; 32],
    pub remote_ephemeral: Option<[u8; 32]>,
    pub preshared_key: Option<[u8; 32]>,
    pub local_index: u32,
    pub remote_index: Option<u32>,
}

impl HandshakeState {
    pub fn new_initiator(
        static_private: [u8; 32],
        static_public: [u8; 32],
        remote_static: [u8; 32],
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        let initial_hash = hash(CONSTRUCTION);
        let chaining_key = initial_hash;
        let hash_val = hash(&[&initial_hash[..], IDENTIFIER].concat());
        let hash_val = hash(&[&hash_val[..], &remote_static[..]].concat());
        
        let (ephemeral_private, ephemeral_public) = super::crypto::generate_keypair();
        
        let mut local_index_bytes = [0u8; 4];
        getrandom::fill(&mut local_index_bytes).expect("Failed to generate random index");
        let local_index = u32::from_le_bytes(local_index_bytes);
        
        Self {
            hash: hash_val,
            chaining_key,
            ephemeral_private,
            ephemeral_public,
            static_private,
            static_public,
            remote_static,
            remote_ephemeral: None,
            preshared_key,
            local_index,
            remote_index: None,
        }
    }

    pub fn new_responder(
        static_private: [u8; 32],
        static_public: [u8; 32],
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        let initial_hash = hash(CONSTRUCTION);
        let chaining_key = initial_hash;
        let hash_val = hash(&[&initial_hash[..], IDENTIFIER].concat());
        let hash_val = hash(&[&hash_val[..], &static_public[..]].concat());
        
        let (ephemeral_private, ephemeral_public) = super::crypto::generate_keypair();
        
        let mut local_index_bytes = [0u8; 4];
        getrandom::fill(&mut local_index_bytes).expect("Failed to generate random index");
        let local_index = u32::from_le_bytes(local_index_bytes);
        
        Self {
            hash: hash_val,
            chaining_key,
            ephemeral_private,
            ephemeral_public,
            static_private,
            static_public,
            remote_static: [0u8; 32],
            remote_ephemeral: None,
            preshared_key,
            local_index,
            remote_index: None,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.hash = hash(&[&self.hash[..], data].concat());
    }

    fn mix_key(&mut self, input: &[u8]) {
        self.chaining_key = kdf1(&self.chaining_key, input);
    }

    fn mix_key_and_hash(&mut self, input: &[u8]) -> [u8; 32] {
        let (ck, temp_h, key) = kdf3(&self.chaining_key, input);
        self.chaining_key = ck;
        self.mix_hash(&temp_h);
        key
    }

    pub fn create_initiation(&mut self) -> Result<HandshakeInitiation, WireGuardError> {
        let ephemeral_public = self.ephemeral_public;
        self.mix_hash(&ephemeral_public);
        
        let dh_result = dh(&self.ephemeral_private, &self.remote_static);
        self.mix_key(&dh_result);
        
        let (ck, key) = kdf2(&self.chaining_key, &dh_result);
        self.chaining_key = ck;
        
        let encrypted_static = aead_encrypt(&key, 0, &self.static_public, &self.hash);
        self.mix_hash(&encrypted_static);
        
        let dh_result2 = dh(&self.static_private, &self.remote_static);
        let (ck2, key2) = kdf2(&self.chaining_key, &dh_result2);
        self.chaining_key = ck2;
        
        let ts = timestamp();
        let encrypted_timestamp = aead_encrypt(&key2, 0, &ts, &self.hash);
        self.mix_hash(&encrypted_timestamp);
        
        let mut msg_for_mac = Vec::with_capacity(116);
        msg_for_mac.push(MSG_TYPE_HANDSHAKE_INIT);
        msg_for_mac.extend_from_slice(&[0u8; 3]);
        msg_for_mac.extend_from_slice(&self.local_index.to_le_bytes());
        msg_for_mac.extend_from_slice(&self.ephemeral_public);
        msg_for_mac.extend_from_slice(&encrypted_static);
        msg_for_mac.extend_from_slice(&encrypted_timestamp);
        
        let mac1_key = hash(&[LABEL_MAC1, &self.remote_static[..]].concat());
        let mac1 = mac(&mac1_key, &msg_for_mac);
        
        let mac2 = [0u8; 16];
        
        let mut encrypted_static_arr = [0u8; 48];
        encrypted_static_arr.copy_from_slice(&encrypted_static);
        
        let mut encrypted_timestamp_arr = [0u8; 28];
        encrypted_timestamp_arr.copy_from_slice(&encrypted_timestamp);
        
        Ok(HandshakeInitiation {
            sender_index: self.local_index,
            ephemeral_public: self.ephemeral_public,
            encrypted_static: encrypted_static_arr,
            encrypted_timestamp: encrypted_timestamp_arr,
            mac1,
            mac2,
        })
    }

    pub fn consume_response(&mut self, response: &HandshakeResponse) -> Result<TransportKeys, WireGuardError> {
        if response.receiver_index != self.local_index {
            return Err(WireGuardError::Handshake("Invalid receiver index".to_string()));
        }
        
        self.remote_index = Some(response.sender_index);
        self.remote_ephemeral = Some(response.ephemeral_public);
        
        self.mix_hash(&response.ephemeral_public);
        
        let dh1 = dh(&self.ephemeral_private, &response.ephemeral_public);
        self.mix_key(&dh1);
        
        let dh2 = dh(&self.static_private, &response.ephemeral_public);
        self.mix_key(&dh2);
        
        let psk = self.preshared_key.unwrap_or([0u8; 32]);
        let key = self.mix_key_and_hash(&psk);
        
        let decrypted = aead_decrypt(&key, 0, &response.encrypted_nothing, &self.hash)
            .ok_or_else(|| WireGuardError::Handshake("Failed to decrypt response".to_string()))?;
        
        if !decrypted.is_empty() {
            return Err(WireGuardError::Handshake("Invalid response payload".to_string()));
        }
        
        self.mix_hash(&response.encrypted_nothing);
        
        let (send_key, recv_key) = kdf2(&self.chaining_key, &[]);
        
        Ok(TransportKeys {
            send_key,
            recv_key,
            send_index: self.local_index,
            recv_index: response.sender_index,
        })
    }

    pub fn process_initiation(&mut self, init: &HandshakeInitiation) -> Result<[u8; 32], WireGuardError> {
        let mac1_key = hash(&[LABEL_MAC1, &self.static_public[..]].concat());
        
        let mut msg_for_mac = Vec::with_capacity(116);
        msg_for_mac.push(MSG_TYPE_HANDSHAKE_INIT);
        msg_for_mac.extend_from_slice(&[0u8; 3]);
        msg_for_mac.extend_from_slice(&init.sender_index.to_le_bytes());
        msg_for_mac.extend_from_slice(&init.ephemeral_public);
        msg_for_mac.extend_from_slice(&init.encrypted_static);
        msg_for_mac.extend_from_slice(&init.encrypted_timestamp);
        
        let expected_mac1 = mac(&mac1_key, &msg_for_mac);
        if expected_mac1 != init.mac1 {
            return Err(WireGuardError::Handshake("Invalid MAC1".to_string()));
        }
        
        self.remote_index = Some(init.sender_index);
        self.remote_ephemeral = Some(init.ephemeral_public);
        
        self.mix_hash(&init.ephemeral_public);
        
        let dh_result = dh(&self.static_private, &init.ephemeral_public);
        self.mix_key(&dh_result);
        
        let (ck, key) = kdf2(&self.chaining_key, &dh_result);
        self.chaining_key = ck;
        
        let decrypted_static = aead_decrypt(&key, 0, &init.encrypted_static, &self.hash)
            .ok_or_else(|| WireGuardError::Handshake("Failed to decrypt static key".to_string()))?;
        
        if decrypted_static.len() != 32 {
            return Err(WireGuardError::Handshake("Invalid static key length".to_string()));
        }
        
        let mut remote_static = [0u8; 32];
        remote_static.copy_from_slice(&decrypted_static);
        self.remote_static = remote_static;
        
        self.mix_hash(&init.encrypted_static);
        
        let dh_result2 = dh(&self.static_private, &remote_static);
        let (ck2, key2) = kdf2(&self.chaining_key, &dh_result2);
        self.chaining_key = ck2;
        
        let _decrypted_timestamp = aead_decrypt(&key2, 0, &init.encrypted_timestamp, &self.hash)
            .ok_or_else(|| WireGuardError::Handshake("Failed to decrypt timestamp".to_string()))?;
        
        self.mix_hash(&init.encrypted_timestamp);
        
        Ok(remote_static)
    }

    pub fn create_response(&mut self) -> Result<(HandshakeResponse, TransportKeys), WireGuardError> {
        let remote_ephemeral = self.remote_ephemeral
            .ok_or_else(|| WireGuardError::Handshake("No remote ephemeral key".to_string()))?;
        let remote_index = self.remote_index
            .ok_or_else(|| WireGuardError::Handshake("No remote index".to_string()))?;
        
        let ephemeral_public = self.ephemeral_public;
        self.mix_hash(&ephemeral_public);
        
        let dh1 = dh(&self.ephemeral_private, &remote_ephemeral);
        self.mix_key(&dh1);
        
        let dh2 = dh(&self.ephemeral_private, &self.remote_static);
        self.mix_key(&dh2);
        
        let psk = self.preshared_key.unwrap_or([0u8; 32]);
        let key = self.mix_key_and_hash(&psk);
        
        let encrypted_nothing = aead_encrypt(&key, 0, &[], &self.hash);
        self.mix_hash(&encrypted_nothing);
        
        let mut msg_for_mac = Vec::with_capacity(92);
        msg_for_mac.push(MSG_TYPE_HANDSHAKE_RESP);
        msg_for_mac.extend_from_slice(&[0u8; 3]);
        msg_for_mac.extend_from_slice(&self.local_index.to_le_bytes());
        msg_for_mac.extend_from_slice(&remote_index.to_le_bytes());
        msg_for_mac.extend_from_slice(&self.ephemeral_public);
        msg_for_mac.extend_from_slice(&encrypted_nothing);
        
        let mac1_key = hash(&[LABEL_MAC1, &self.remote_static[..]].concat());
        let mac1 = mac(&mac1_key, &msg_for_mac);
        
        let mac2 = [0u8; 16];
        
        let mut encrypted_nothing_arr = [0u8; 16];
        encrypted_nothing_arr.copy_from_slice(&encrypted_nothing);
        
        let (recv_key, send_key) = kdf2(&self.chaining_key, &[]);
        
        let response = HandshakeResponse {
            sender_index: self.local_index,
            receiver_index: remote_index,
            ephemeral_public: self.ephemeral_public,
            encrypted_nothing: encrypted_nothing_arr,
            mac1,
            mac2,
        };
        
        let keys = TransportKeys {
            send_key,
            recv_key,
            send_index: self.local_index,
            recv_index: remote_index,
        };
        
        Ok((response, keys))
    }
}

impl HandshakeInitiation {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(148);
        buf.push(MSG_TYPE_HANDSHAKE_INIT);
        buf.extend_from_slice(&[0u8; 3]);
        buf.extend_from_slice(&self.sender_index.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral_public);
        buf.extend_from_slice(&self.encrypted_static);
        buf.extend_from_slice(&self.encrypted_timestamp);
        buf.extend_from_slice(&self.mac1);
        buf.extend_from_slice(&self.mac2);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, WireGuardError> {
        if data.len() < 148 {
            return Err(WireGuardError::Handshake("Initiation message too short".to_string()));
        }
        
        if data[0] != MSG_TYPE_HANDSHAKE_INIT {
            return Err(WireGuardError::Handshake("Invalid message type".to_string()));
        }
        
        let sender_index = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        
        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[8..40]);
        
        let mut encrypted_static = [0u8; 48];
        encrypted_static.copy_from_slice(&data[40..88]);
        
        let mut encrypted_timestamp = [0u8; 28];
        encrypted_timestamp.copy_from_slice(&data[88..116]);
        
        let mut mac1 = [0u8; 16];
        mac1.copy_from_slice(&data[116..132]);
        
        let mut mac2 = [0u8; 16];
        mac2.copy_from_slice(&data[132..148]);
        
        Ok(Self {
            sender_index,
            ephemeral_public,
            encrypted_static,
            encrypted_timestamp,
            mac1,
            mac2,
        })
    }
}

impl HandshakeResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(92);
        buf.push(MSG_TYPE_HANDSHAKE_RESP);
        buf.extend_from_slice(&[0u8; 3]);
        buf.extend_from_slice(&self.sender_index.to_le_bytes());
        buf.extend_from_slice(&self.receiver_index.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral_public);
        buf.extend_from_slice(&self.encrypted_nothing);
        buf.extend_from_slice(&self.mac1);
        buf.extend_from_slice(&self.mac2);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, WireGuardError> {
        if data.len() < 92 {
            return Err(WireGuardError::Handshake("Response message too short".to_string()));
        }
        
        if data[0] != MSG_TYPE_HANDSHAKE_RESP {
            return Err(WireGuardError::Handshake("Invalid message type".to_string()));
        }
        
        let sender_index = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let receiver_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        
        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[12..44]);
        
        let mut encrypted_nothing = [0u8; 16];
        encrypted_nothing.copy_from_slice(&data[44..60]);
        
        let mut mac1 = [0u8; 16];
        mac1.copy_from_slice(&data[60..76]);
        
        let mut mac2 = [0u8; 16];
        mac2.copy_from_slice(&data[76..92]);
        
        Ok(Self {
            sender_index,
            receiver_index,
            ephemeral_public,
            encrypted_nothing,
            mac1,
            mac2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::crypto::generate_keypair;

    #[test]
    fn test_handshake_roundtrip() {
        let (initiator_priv, initiator_pub) = generate_keypair();
        let (responder_priv, responder_pub) = generate_keypair();
        
        let mut initiator = HandshakeState::new_initiator(
            initiator_priv,
            initiator_pub,
            responder_pub,
            None,
        );
        
        let init_msg = initiator.create_initiation().unwrap();
        let init_bytes = init_msg.to_bytes();
        let init_parsed = HandshakeInitiation::from_bytes(&init_bytes).unwrap();
        
        let mut responder = HandshakeState::new_responder(
            responder_priv,
            responder_pub,
            None,
        );
        
        let remote_static = responder.process_initiation(&init_parsed).unwrap();
        assert_eq!(remote_static, initiator_pub);
        
        let (resp_msg, responder_keys) = responder.create_response().unwrap();
        let resp_bytes = resp_msg.to_bytes();
        let resp_parsed = HandshakeResponse::from_bytes(&resp_bytes).unwrap();
        
        let initiator_keys = initiator.consume_response(&resp_parsed).unwrap();
        
        assert_eq!(initiator_keys.send_key, responder_keys.recv_key);
        assert_eq!(initiator_keys.recv_key, responder_keys.send_key);
    }

    #[test]
    fn test_handshake_with_psk() {
        let (initiator_priv, initiator_pub) = generate_keypair();
        let (responder_priv, responder_pub) = generate_keypair();
        let psk = [42u8; 32];
        
        let mut initiator = HandshakeState::new_initiator(
            initiator_priv,
            initiator_pub,
            responder_pub,
            Some(psk),
        );
        
        let init_msg = initiator.create_initiation().unwrap();
        
        let mut responder = HandshakeState::new_responder(
            responder_priv,
            responder_pub,
            Some(psk),
        );
        
        responder.process_initiation(&init_msg).unwrap();
        let (resp_msg, responder_keys) = responder.create_response().unwrap();
        
        let initiator_keys = initiator.consume_response(&resp_msg).unwrap();
        
        assert_eq!(initiator_keys.send_key, responder_keys.recv_key);
        assert_eq!(initiator_keys.recv_key, responder_keys.send_key);
    }
}
