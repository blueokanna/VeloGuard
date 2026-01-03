use std::net::UdpSocket;
use std::io;

use crate::BoringTunError;

/// WireGuard device abstraction
pub struct Device {
    socket: UdpSocket,
    listen_port: u16,
}

impl Device {
    /// Create a new device
    pub fn new(listen_port: u16) -> Result<Self, BoringTunError> {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", listen_port))
            .map_err(|e| BoringTunError::Network(e.to_string()))?;

        Ok(Self {
            socket,
            listen_port,
        })
    }

    /// Send a packet
    pub fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr)
    }

    /// Receive a packet
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        self.socket.recv_from(buf)
    }

    /// Get the listen port
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }
}
