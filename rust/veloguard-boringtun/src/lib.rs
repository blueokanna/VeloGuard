use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub mod crypto;
pub mod handshake;
pub mod device;
pub mod peer;

pub use device::Device;
pub use peer::Peer;

#[derive(Debug, Error)]
pub enum BoringTunError {
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
}

/// WireGuard device configuration
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub fwmark: Option<u32>,
    pub peers: Vec<PeerConfig>,
}

/// Peer configuration
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<cidr::IpCidr>,
    pub persistent_keepalive: Option<u16>,
}

/// Main WireGuard device
pub struct WireGuard {
    _device: Arc<Mutex<Device>>,
    peers: HashMap<[u8; 32], Arc<Mutex<Peer>>>,
}

impl WireGuard {
    /// Create a new WireGuard device
    pub fn new(config: DeviceConfig) -> Result<Self, BoringTunError> {
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

    /// Add a new peer
    pub fn add_peer(&mut self, config: PeerConfig) -> Result<(), BoringTunError> {
        let peer = Peer::new(config.clone())?;
        self.peers.insert(config.public_key, Arc::new(Mutex::new(peer)));
        Ok(())
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, public_key: &[u8; 32]) -> Result<(), BoringTunError> {
        if self.peers.remove(public_key).is_none() {
            return Err(BoringTunError::PeerNotFound);
        }
        Ok(())
    }

    /// Get peer by public key
    pub fn get_peer(&self, public_key: &[u8; 32]) -> Option<Arc<Mutex<Peer>>> {
        self.peers.get(public_key).cloned()
    }

    /// Process incoming packet
    pub fn process_packet(&self, _packet: &[u8], _src_addr: SocketAddr) -> Result<Option<Vec<u8>>, BoringTunError> {
        // This is a simplified implementation
        // In a real implementation, this would:
        // 1. Parse the packet type (handshake initiation, response, cookie, data)
        // 2. Handle handshake protocol
        // 3. Decrypt data packets
        // 4. Route packets to appropriate peers

        Ok(None)
    }

    /// Send packet to peer
    pub fn send_packet(&self, packet: &[u8], peer_key: &[u8; 32]) -> Result<(), BoringTunError> {
        let peer = self.peers.get(peer_key)
            .ok_or(BoringTunError::PeerNotFound)?;

        let mut peer = peer.lock().unwrap();
        peer.send_packet(packet)?;
        Ok(())
    }

    /// Get device statistics
    pub fn stats(&self) -> DeviceStats {
        // Implementation would gather stats from device and peers
        DeviceStats {
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
        }
    }
}

/// Device statistics
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
    fn test_device_creation() {
        let config = DeviceConfig {
            private_key: [0u8; 32], // This would be a real private key in practice
            listen_port: 51820,
            fwmark: None,
            peers: vec![],
        };

        let wg = WireGuard::new(config);
        assert!(wg.is_ok());
    }
}
