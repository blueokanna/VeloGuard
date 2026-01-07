use super::{PeerConfig, WireGuardError};
use std::net::SocketAddr;

pub struct Peer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<cidr::IpCidr>,
    pub persistent_keepalive: Option<u16>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

impl Peer {
    pub fn new(config: PeerConfig) -> Result<Self, WireGuardError> {
        Ok(Self {
            public_key: config.public_key,
            preshared_key: config.preshared_key,
            endpoint: config.endpoint,
            allowed_ips: config.allowed_ips,
            persistent_keepalive: config.persistent_keepalive,
            tx_bytes: 0,
            rx_bytes: 0,
        })
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), WireGuardError> {
        self.tx_bytes += packet.len() as u64;
        Ok(())
    }

    pub fn receive_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        self.rx_bytes += packet.len() as u64;
        Ok(packet.to_vec())
    }
}
