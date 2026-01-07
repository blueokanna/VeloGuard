mod crypto;
mod device;
mod handshake;
mod peer;

pub use crypto::{
    aead_encrypt, aead_decrypt, generate_keypair, public_key_from_private,
    REKEY_AFTER_MESSAGES, REJECT_AFTER_MESSAGES, REKEY_AFTER_TIME, REJECT_AFTER_TIME,
    REKEY_TIMEOUT, KEEPALIVE_TIMEOUT,
};
pub use device::Device;
pub use handshake::{
    HandshakeState, HandshakeInitiation, HandshakeResponse, TransportKeys,
    MSG_TYPE_HANDSHAKE_INIT, MSG_TYPE_HANDSHAKE_RESP, MSG_TYPE_COOKIE_REPLY, MSG_TYPE_TRANSPORT,
};
pub use peer::Peer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireGuardError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Handshake error: {0}")]
    Handshake(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Invalid configuration")]
    InvalidConfig,
    #[error("Peer not found")]
    PeerNotFound,
    #[error("Session not established")]
    NoSession,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid packet")]
    InvalidPacket,
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub fwmark: Option<u32>,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<cidr::IpCidr>,
    pub persistent_keepalive: Option<u16>,
}

pub struct WireguardSession {
    pub transport_keys: TransportKeys,
    pub send_nonce: AtomicU64,
    pub recv_nonce: AtomicU64,
    pub created_at: std::time::Instant,
    pub last_sent: std::sync::atomic::AtomicU64,
    pub last_received: std::sync::atomic::AtomicU64,
}

impl WireguardSession {
    pub fn new(keys: TransportKeys) -> Self {
        Self {
            transport_keys: keys,
            send_nonce: AtomicU64::new(0),
            recv_nonce: AtomicU64::new(0),
            created_at: std::time::Instant::now(),
            last_sent: std::sync::atomic::AtomicU64::new(0),
            last_received: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn encrypt_packet(&self, plaintext: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        
        if nonce >= REJECT_AFTER_MESSAGES {
            return Err(WireGuardError::Crypto("Nonce exhausted".to_string()));
        }
        
        let ciphertext = aead_encrypt(&self.transport_keys.send_key, nonce, plaintext, &[]);
        
        let mut packet = Vec::with_capacity(16 + ciphertext.len());
        packet.push(MSG_TYPE_TRANSPORT);
        packet.extend_from_slice(&[0u8; 3]);
        packet.extend_from_slice(&self.transport_keys.recv_index.to_le_bytes());
        packet.extend_from_slice(&nonce.to_le_bytes());
        packet.extend_from_slice(&ciphertext);
        
        self.last_sent.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::SeqCst,
        );
        
        Ok(packet)
    }

    pub fn decrypt_packet(&self, packet: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        if packet.len() < 32 {
            return Err(WireGuardError::InvalidPacket);
        }
        
        if packet[0] != MSG_TYPE_TRANSPORT {
            return Err(WireGuardError::InvalidPacket);
        }
        
        let receiver_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
        if receiver_index != self.transport_keys.send_index {
            return Err(WireGuardError::InvalidPacket);
        }
        
        let nonce = u64::from_le_bytes([
            packet[8], packet[9], packet[10], packet[11],
            packet[12], packet[13], packet[14], packet[15],
        ]);
        
        let ciphertext = &packet[16..];
        
        let plaintext = aead_decrypt(&self.transport_keys.recv_key, nonce, ciphertext, &[])
            .ok_or(WireGuardError::DecryptionFailed)?;
        
        self.last_received.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::SeqCst,
        );
        
        Ok(plaintext)
    }

    pub fn needs_rekey(&self) -> bool {
        let nonce = self.send_nonce.load(Ordering::SeqCst);
        if nonce >= REKEY_AFTER_MESSAGES {
            return true;
        }
        
        let elapsed = self.created_at.elapsed().as_secs();
        elapsed >= REKEY_AFTER_TIME
    }

    pub fn is_expired(&self) -> bool {
        let nonce = self.send_nonce.load(Ordering::SeqCst);
        if nonce >= REJECT_AFTER_MESSAGES {
            return true;
        }
        
        let elapsed = self.created_at.elapsed().as_secs();
        elapsed >= REJECT_AFTER_TIME
    }

    pub fn create_keepalive(&self) -> Result<Vec<u8>, WireGuardError> {
        self.encrypt_packet(&[])
    }
}

pub struct WireGuardTunnel {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: SocketAddr,
    pub session: Option<Arc<WireguardSession>>,
    pub handshake_state: Option<HandshakeState>,
}

impl WireGuardTunnel {
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        endpoint: SocketAddr,
    ) -> Self {
        let public_key = public_key_from_private(&private_key);
        
        Self {
            private_key,
            public_key,
            peer_public_key,
            preshared_key,
            endpoint,
            session: None,
            handshake_state: None,
        }
    }

    pub fn initiate_handshake(&mut self) -> Result<Vec<u8>, WireGuardError> {
        let mut state = HandshakeState::new_initiator(
            self.private_key,
            self.public_key,
            self.peer_public_key,
            self.preshared_key,
        );
        
        let init = state.create_initiation()?;
        let bytes = init.to_bytes();
        
        self.handshake_state = Some(state);
        
        Ok(bytes)
    }

    pub fn process_handshake_response(&mut self, data: &[u8]) -> Result<(), WireGuardError> {
        let response = HandshakeResponse::from_bytes(data)?;
        
        let state = self.handshake_state.as_mut()
            .ok_or(WireGuardError::Handshake("No handshake in progress".to_string()))?;
        
        let keys = state.consume_response(&response)?;
        
        self.session = Some(Arc::new(WireguardSession::new(keys)));
        self.handshake_state = None;
        
        Ok(())
    }

    pub fn encrypt_packet(&self, plaintext: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let session = self.session.as_ref().ok_or(WireGuardError::NoSession)?;
        session.encrypt_packet(plaintext)
    }

    pub fn decrypt_packet(&self, packet: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let session = self.session.as_ref().ok_or(WireGuardError::NoSession)?;
        session.decrypt_packet(packet)
    }

    pub fn create_keepalive(&self) -> Result<Vec<u8>, WireGuardError> {
        let session = self.session.as_ref().ok_or(WireGuardError::NoSession)?;
        session.create_keepalive()
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    pub fn needs_rekey(&self) -> bool {
        self.session.as_ref().map(|s| s.needs_rekey()).unwrap_or(true)
    }

    pub fn is_session_expired(&self) -> bool {
        self.session.as_ref().map(|s| s.is_expired()).unwrap_or(true)
    }
}

pub struct WireGuard {
    _device: Arc<Mutex<Device>>,
    peers: HashMap<[u8; 32], Arc<Mutex<Peer>>>,
}

impl WireGuard {
    pub fn new(config: DeviceConfig) -> Result<Self, WireGuardError> {
        let device = Device::new(config.listen_port)?;
        let mut peers = HashMap::new();

        for peer_config in &config.peers {
            let peer = Peer::new(peer_config.clone())?;
            peers.insert(peer_config.public_key, Arc::new(Mutex::new(peer)));
        }

        Ok(Self {
            _device: Arc::new(Mutex::new(device)),
            peers,
        })
    }

    pub fn add_peer(&mut self, config: PeerConfig) -> Result<(), WireGuardError> {
        let peer = Peer::new(config.clone())?;
        self.peers.insert(config.public_key, Arc::new(Mutex::new(peer)));
        Ok(())
    }

    pub fn remove_peer(&mut self, public_key: &[u8; 32]) -> Result<(), WireGuardError> {
        if self.peers.remove(public_key).is_none() {
            return Err(WireGuardError::PeerNotFound);
        }
        Ok(())
    }

    pub fn get_peer(&self, public_key: &[u8; 32]) -> Option<Arc<Mutex<Peer>>> {
        self.peers.get(public_key).cloned()
    }

    pub fn process_packet(&self, _packet: &[u8], _src_addr: SocketAddr) -> Result<Option<Vec<u8>>, WireGuardError> {
        Ok(None)
    }

    pub fn send_packet(&self, packet: &[u8], peer_key: &[u8; 32]) -> Result<(), WireGuardError> {
        let peer = self.peers.get(peer_key).ok_or(WireGuardError::PeerNotFound)?;
        let mut peer = peer.lock().unwrap();
        peer.send_packet(packet)?;
        Ok(())
    }

    pub fn stats(&self) -> DeviceStats {
        DeviceStats {
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_handshake() {
        let (client_priv, client_pub) = generate_keypair();
        let (server_priv, server_pub) = generate_keypair();
        
        let endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        
        let mut client_tunnel = WireGuardTunnel::new(
            client_priv,
            server_pub,
            None,
            endpoint,
        );
        
        let init_packet = client_tunnel.initiate_handshake().unwrap();
        
        let init = HandshakeInitiation::from_bytes(&init_packet).unwrap();
        let mut server_state = HandshakeState::new_responder(server_priv, server_pub, None);
        let remote_pub = server_state.process_initiation(&init).unwrap();
        assert_eq!(remote_pub, client_pub);
        
        let (response, _server_keys) = server_state.create_response().unwrap();
        let response_bytes = response.to_bytes();
        
        client_tunnel.process_handshake_response(&response_bytes).unwrap();
        
        assert!(client_tunnel.has_session());
    }

    #[test]
    fn test_tunnel_encrypt_decrypt() {
        let (client_priv, _client_pub) = generate_keypair();
        let (server_priv, server_pub) = generate_keypair();
        
        let endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        
        let mut client_tunnel = WireGuardTunnel::new(
            client_priv,
            server_pub,
            None,
            endpoint,
        );
        
        let init_packet = client_tunnel.initiate_handshake().unwrap();
        let init = HandshakeInitiation::from_bytes(&init_packet).unwrap();
        
        let mut server_state = HandshakeState::new_responder(server_priv, server_pub, None);
        server_state.process_initiation(&init).unwrap();
        let (response, server_keys) = server_state.create_response().unwrap();
        
        client_tunnel.process_handshake_response(&response.to_bytes()).unwrap();
        
        let server_session = WireguardSession::new(TransportKeys {
            send_key: server_keys.send_key,
            recv_key: server_keys.recv_key,
            send_index: server_keys.send_index,
            recv_index: server_keys.recv_index,
        });
        
        let plaintext = b"Hello, WireGuard!";
        let encrypted = client_tunnel.encrypt_packet(plaintext).unwrap();
        let decrypted = server_session.decrypt_packet(&encrypted).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        
        let server_plaintext = b"Hello from server!";
        let server_encrypted = server_session.encrypt_packet(server_plaintext).unwrap();
        let server_decrypted = client_tunnel.decrypt_packet(&server_encrypted).unwrap();
        
        assert_eq!(server_plaintext.as_slice(), server_decrypted.as_slice());
    }

    #[test]
    fn test_keepalive() {
        let (client_priv, _) = generate_keypair();
        let (server_priv, server_pub) = generate_keypair();
        
        let endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        
        let mut client_tunnel = WireGuardTunnel::new(client_priv, server_pub, None, endpoint);
        
        let init_packet = client_tunnel.initiate_handshake().unwrap();
        let init = HandshakeInitiation::from_bytes(&init_packet).unwrap();
        
        let mut server_state = HandshakeState::new_responder(server_priv, server_pub, None);
        server_state.process_initiation(&init).unwrap();
        let (response, server_keys) = server_state.create_response().unwrap();
        
        client_tunnel.process_handshake_response(&response.to_bytes()).unwrap();
        
        let keepalive = client_tunnel.create_keepalive().unwrap();
        
        let server_session = WireguardSession::new(TransportKeys {
            send_key: server_keys.send_key,
            recv_key: server_keys.recv_key,
            send_index: server_keys.send_index,
            recv_index: server_keys.recv_index,
        });
        
        let decrypted = server_session.decrypt_packet(&keepalive).unwrap();
        assert!(decrypted.is_empty());
    }
}
