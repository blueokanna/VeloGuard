use crate::config::OutboundConfig;
use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use veloguard_protocol::wireguard::{
    WireGuardTunnel, public_key_from_private,
};

const WG_HEADER_SIZE: usize = 32;
const IP_HEADER_SIZE: usize = 20;
const TCP_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;

pub struct WireguardOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    private_key: [u8; 32],
    #[allow(dead_code)]
    public_key: [u8; 32],
    peer_public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    local_address: IpAddr,
    mtu: u16,
    #[allow(dead_code)]
    reserved: Option<[u8; 3]>,
    tunnel: Arc<Mutex<Option<WireGuardTunnel>>>,
    socket: Arc<Mutex<Option<UdpSocket>>>,
}

impl WireguardOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for WireGuard"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for WireGuard"))?;

        let private_key_str = config
            .options
            .get("private-key")
            .or_else(|| config.options.get("privateKey"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Missing private-key for WireGuard"))?;

        let private_key = decode_base64_key(private_key_str)
            .map_err(|e| Error::config(format!("Invalid private-key: {}", e)))?;

        let public_key = public_key_from_private(&private_key);

        let peer_public_key_str = config
            .options
            .get("public-key")
            .or_else(|| config.options.get("publicKey"))
            .or_else(|| config.options.get("peer-public-key"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Missing public-key for WireGuard"))?;

        let peer_public_key = decode_base64_key(peer_public_key_str)
            .map_err(|e| Error::config(format!("Invalid public-key: {}", e)))?;

        let preshared_key = config
            .options
            .get("preshared-key")
            .or_else(|| config.options.get("presharedKey"))
            .and_then(|v| v.as_str())
            .map(decode_base64_key)
            .transpose()
            .map_err(|e| Error::config(format!("Invalid preshared-key: {}", e)))?;

        let local_address = config
            .options
            .get("local-address")
            .or_else(|| config.options.get("localAddress"))
            .and_then(|v| v.as_str())
            .and_then(|s| {
                s.split('/').next()
                    .and_then(|ip| ip.parse::<IpAddr>().ok())
            })
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));

        let mtu = config
            .options
            .get("mtu")
            .and_then(|v| v.as_i64())
            .map(|n| n as u16)
            .unwrap_or(1420);

        let reserved = config
            .options
            .get("reserved")
            .and_then(|v| v.as_sequence())
            .and_then(|seq| {
                if seq.len() >= 3 {
                    Some([
                        seq[0].as_i64()? as u8,
                        seq[1].as_i64()? as u8,
                        seq[2].as_i64()? as u8,
                    ])
                } else {
                    None
                }
            });

        Ok(Self {
            config,
            server,
            port,
            private_key,
            public_key,
            peer_public_key,
            preshared_key,
            local_address,
            mtu,
            reserved,
            tunnel: Arc::new(Mutex::new(None)),
            socket: Arc::new(Mutex::new(None)),
        })
    }

    async fn ensure_tunnel(&self) -> Result<()> {
        let mut tunnel_guard = self.tunnel.lock().await;
        
        if tunnel_guard.as_ref().map(|t| t.has_session()).unwrap_or(false)
            && !tunnel_guard.as_ref().unwrap().is_session_expired() {
                return Ok(());
            }

        let endpoint: SocketAddr = format!("{}:{}", self.server, self.port)
            .parse()
            .map_err(|e| Error::config(format!("Invalid endpoint: {}", e)))?;

        let mut tunnel = WireGuardTunnel::new(
            self.private_key,
            self.peer_public_key,
            self.preshared_key,
            endpoint,
        );

        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;

        socket.connect(endpoint).await
            .map_err(|e| Error::network(format!("Failed to connect to WireGuard endpoint: {}", e)))?;

        let init_packet = tunnel.initiate_handshake()
            .map_err(|e| Error::protocol(format!("Failed to create handshake: {}", e)))?;

        socket.send(&init_packet).await
            .map_err(|e| Error::network(format!("Failed to send handshake: {}", e)))?;

        let mut response_buf = vec![0u8; 256];
        let timeout = tokio::time::Duration::from_secs(10);
        
        let n = tokio::time::timeout(timeout, socket.recv(&mut response_buf))
            .await
            .map_err(|_| Error::network("Handshake timeout"))?
            .map_err(|e| Error::network(format!("Failed to receive handshake response: {}", e)))?;

        tunnel.process_handshake_response(&response_buf[..n])
            .map_err(|e| Error::protocol(format!("Failed to process handshake response: {}", e)))?;

        tracing::info!(
            "WireGuard tunnel established to {}:{} (local: {})",
            self.server, self.port, self.local_address
        );

        *tunnel_guard = Some(tunnel);
        *self.socket.lock().await = Some(socket);

        Ok(())
    }

    async fn send_ip_packet(&self, packet: &[u8]) -> Result<()> {
        let tunnel_guard = self.tunnel.lock().await;
        let tunnel = tunnel_guard.as_ref()
            .ok_or_else(|| Error::protocol("WireGuard tunnel not established"))?;

        let encrypted = tunnel.encrypt_packet(packet)
            .map_err(|e| Error::protocol(format!("Failed to encrypt packet: {}", e)))?;

        let socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_ref()
            .ok_or_else(|| Error::protocol("WireGuard socket not available"))?;

        socket.send(&encrypted).await
            .map_err(|e| Error::network(format!("Failed to send packet: {}", e)))?;

        Ok(())
    }

    async fn recv_ip_packet(&self) -> Result<Vec<u8>> {
        let socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_ref()
            .ok_or_else(|| Error::protocol("WireGuard socket not available"))?;

        let mut buf = vec![0u8; self.mtu as usize + WG_HEADER_SIZE];
        let n = socket.recv(&mut buf).await
            .map_err(|e| Error::network(format!("Failed to receive packet: {}", e)))?;

        drop(socket_guard);

        let tunnel_guard = self.tunnel.lock().await;
        let tunnel = tunnel_guard.as_ref()
            .ok_or_else(|| Error::protocol("WireGuard tunnel not established"))?;

        let decrypted = tunnel.decrypt_packet(&buf[..n])
            .map_err(|e| Error::protocol(format!("Failed to decrypt packet: {}", e)))?;

        Ok(decrypted)
    }

    #[allow(dead_code)]
    fn build_tcp_syn_packet(&self, target: &TargetAddr, seq: u32) -> Vec<u8> {
        let dst_ip = match target {
            TargetAddr::Ip(addr) => addr.ip(),
            TargetAddr::Domain(_, _) => return vec![],
        };
        let dst_port = target.port();

        let src_ip = match self.local_address {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return vec![],
        };
        let src_port = 40000 + (seq % 20000) as u16;

        let mut packet = vec![0u8; IP_HEADER_SIZE + TCP_HEADER_SIZE];

        packet[0] = 0x45;
        packet[1] = 0x00;
        let total_len = (IP_HEADER_SIZE + TCP_HEADER_SIZE) as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[4..6].copy_from_slice(&(seq as u16).to_be_bytes());
        packet[6] = 0x40;
        packet[7] = 0x00;
        packet[8] = 64;
        packet[9] = 6;
        packet[10..12].copy_from_slice(&[0, 0]);
        packet[12..16].copy_from_slice(&src_ip.octets());
        
        if let IpAddr::V4(dst) = dst_ip {
            packet[16..20].copy_from_slice(&dst.octets());
        }

        let ip_checksum = calculate_ip_checksum(&packet[..IP_HEADER_SIZE]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_offset = IP_HEADER_SIZE;
        packet[tcp_offset..tcp_offset+2].copy_from_slice(&src_port.to_be_bytes());
        packet[tcp_offset+2..tcp_offset+4].copy_from_slice(&dst_port.to_be_bytes());
        packet[tcp_offset+4..tcp_offset+8].copy_from_slice(&seq.to_be_bytes());
        packet[tcp_offset+8..tcp_offset+12].copy_from_slice(&0u32.to_be_bytes());
        packet[tcp_offset+12] = 0x50;
        packet[tcp_offset+13] = 0x02;
        packet[tcp_offset+14..tcp_offset+16].copy_from_slice(&65535u16.to_be_bytes());
        packet[tcp_offset+16..tcp_offset+18].copy_from_slice(&[0, 0]);
        packet[tcp_offset+18..tcp_offset+20].copy_from_slice(&[0, 0]);

        packet
    }

    pub async fn relay_udp(
        &self,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.ensure_tunnel().await?;

        let dst_ip = match target {
            TargetAddr::Ip(addr) => match addr.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => return Err(Error::protocol("IPv6 not supported for WireGuard UDP")),
            },
            TargetAddr::Domain(_, _) => {
                return Err(Error::protocol("Domain targets require DNS resolution for WireGuard"));
            }
        };
        let dst_port = target.port();

        let src_ip = match self.local_address {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err(Error::protocol("IPv6 local address not supported")),
        };
        let src_port = 40000 + (rand::random::<u16>() % 20000);

        let udp_len = UDP_HEADER_SIZE + data.len();
        let total_len = IP_HEADER_SIZE + udp_len;
        let mut packet = vec![0u8; total_len];

        packet[0] = 0x45;
        packet[1] = 0x00;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
        packet[6] = 0x40;
        packet[7] = 0x00;
        packet[8] = 64;
        packet[9] = 17;
        packet[10..12].copy_from_slice(&[0, 0]);
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        let ip_checksum = calculate_ip_checksum(&packet[..IP_HEADER_SIZE]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        let udp_offset = IP_HEADER_SIZE;
        packet[udp_offset..udp_offset+2].copy_from_slice(&src_port.to_be_bytes());
        packet[udp_offset+2..udp_offset+4].copy_from_slice(&dst_port.to_be_bytes());
        packet[udp_offset+4..udp_offset+6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[udp_offset+6..udp_offset+8].copy_from_slice(&[0, 0]);
        packet[udp_offset+8..].copy_from_slice(data);

        self.send_ip_packet(&packet).await?;

        let timeout = tokio::time::Duration::from_secs(30);
        let response = tokio::time::timeout(timeout, self.recv_ip_packet())
            .await
            .map_err(|_| Error::network("UDP response timeout"))?
            .map_err(|e| Error::network(format!("Failed to receive UDP response: {}", e)))?;

        if response.len() < IP_HEADER_SIZE + UDP_HEADER_SIZE {
            return Err(Error::protocol("Response packet too short"));
        }

        let payload_start = IP_HEADER_SIZE + UDP_HEADER_SIZE;
        Ok(response[payload_start..].to_vec())
    }
}

#[async_trait::async_trait]
impl OutboundProxy for WireguardOutbound {
    async fn connect(&self) -> Result<()> {
        self.ensure_tunnel().await?;
        tracing::info!(
            "WireGuard outbound '{}' connected to {}:{}",
            self.config.tag,
            self.server,
            self.port
        );
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        *self.tunnel.lock().await = None;
        *self.socket.lock().await = None;
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
    
    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
    
    async fn test_http_latency(
        &self,
        _test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;
        
        let start = Instant::now();
        
        tokio::time::timeout(timeout, self.ensure_tunnel())
            .await
            .map_err(|_| Error::network("Connection timeout"))?
            .map_err(|e| Error::network(format!("Failed to establish tunnel: {}", e)))?;
        
        let tunnel_guard = self.tunnel.lock().await;
        if let Some(tunnel) = tunnel_guard.as_ref() {
            let keepalive = tunnel.create_keepalive()
                .map_err(|e| Error::protocol(format!("Failed to create keepalive: {}", e)))?;
            
            let socket_guard = self.socket.lock().await;
            if let Some(socket) = socket_guard.as_ref() {
                socket.send(&keepalive).await
                    .map_err(|e| Error::network(format!("Failed to send keepalive: {}", e)))?;
            }
        }
        
        Ok(start.elapsed())
    }
    
    async fn relay_tcp(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
    ) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None).await
    }

    async fn relay_tcp_with_connection(
        &self,
        mut inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<Arc<TrackedConnection>>,
    ) -> Result<()> {
        self.ensure_tunnel().await?;

        tracing::debug!(
            "WireGuard: relaying TCP to {} via {}:{}",
            target,
            self.server,
            self.port
        );

        let tracker = global_tracker();
        let mut buf = vec![0u8; self.mtu as usize - IP_HEADER_SIZE - TCP_HEADER_SIZE - 50];
        let mut seq: u32 = rand::random();

        loop {
            tokio::select! {
                result = inbound.read(&mut buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = &buf[..n];
                            
                            let dst_ip = match &target {
                                TargetAddr::Ip(addr) => match addr.ip() {
                                    IpAddr::V4(ip) => ip,
                                    IpAddr::V6(_) => {
                                        return Err(Error::protocol("IPv6 not supported"));
                                    }
                                },
                                TargetAddr::Domain(_, _) => {
                                    return Err(Error::protocol("Domain targets require DNS resolution"));
                                }
                            };
                            let dst_port = target.port();

                            let src_ip = match self.local_address {
                                IpAddr::V4(ip) => ip,
                                IpAddr::V6(_) => {
                                    return Err(Error::protocol("IPv6 local address not supported"));
                                }
                            };
                            let src_port = 40000 + (seq % 20000) as u16;

                            let tcp_len = TCP_HEADER_SIZE + data.len();
                            let total_len = IP_HEADER_SIZE + tcp_len;
                            let mut packet = vec![0u8; total_len];

                            packet[0] = 0x45;
                            packet[1] = 0x00;
                            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
                            packet[4..6].copy_from_slice(&(seq as u16).to_be_bytes());
                            packet[6] = 0x40;
                            packet[7] = 0x00;
                            packet[8] = 64;
                            packet[9] = 6;
                            packet[10..12].copy_from_slice(&[0, 0]);
                            packet[12..16].copy_from_slice(&src_ip.octets());
                            packet[16..20].copy_from_slice(&dst_ip.octets());

                            let ip_checksum = calculate_ip_checksum(&packet[..IP_HEADER_SIZE]);
                            packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

                            let tcp_offset = IP_HEADER_SIZE;
                            packet[tcp_offset..tcp_offset+2].copy_from_slice(&src_port.to_be_bytes());
                            packet[tcp_offset+2..tcp_offset+4].copy_from_slice(&dst_port.to_be_bytes());
                            packet[tcp_offset+4..tcp_offset+8].copy_from_slice(&seq.to_be_bytes());
                            packet[tcp_offset+8..tcp_offset+12].copy_from_slice(&0u32.to_be_bytes());
                            packet[tcp_offset+12] = ((TCP_HEADER_SIZE / 4) as u8) << 4;
                            packet[tcp_offset+13] = 0x18;
                            packet[tcp_offset+14..tcp_offset+16].copy_from_slice(&65535u16.to_be_bytes());
                            packet[tcp_offset+16..tcp_offset+18].copy_from_slice(&[0, 0]);
                            packet[tcp_offset+18..tcp_offset+20].copy_from_slice(&[0, 0]);
                            packet[tcp_offset+20..].copy_from_slice(data);

                            self.send_ip_packet(&packet).await?;
                            
                            seq = seq.wrapping_add(data.len() as u32);
                            tracker.add_global_upload(n as u64);
                            if let Some(ref conn) = connection {
                                conn.add_upload(n as u64);
                            }
                        }
                        Err(e) => {
                            tracing::debug!("WireGuard inbound read error: {}", e);
                            break;
                        }
                    }
                }
                result = self.recv_ip_packet() => {
                    match result {
                        Ok(ip_packet) => {
                            if ip_packet.len() < IP_HEADER_SIZE + TCP_HEADER_SIZE {
                                continue;
                            }
                            
                            let protocol = ip_packet[9];
                            if protocol != 6 {
                                continue;
                            }
                            
                            let tcp_offset = IP_HEADER_SIZE;
                            let data_offset = tcp_offset + TCP_HEADER_SIZE;
                            
                            if ip_packet.len() > data_offset {
                                let payload = &ip_packet[data_offset..];
                                inbound.write_all(payload).await.map_err(|e| {
                                    Error::network(format!("Failed to write to inbound: {}", e))
                                })?;
                                
                                tracker.add_global_download(payload.len() as u64);
                                if let Some(ref conn) = connection {
                                    conn.add_download(payload.len() as u64);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("WireGuard recv error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn decode_base64_key(s: &str) -> std::result::Result<[u8; 32], String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    
    let bytes = STANDARD.decode(s)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    if bytes.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", bytes.len()));
    }
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue;
        }
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use veloguard_protocol::wireguard::generate_keypair;

    #[test]
    fn test_decode_base64_key() {
        let valid_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let result = decode_base64_key(valid_key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_decode_base64_key_invalid() {
        let invalid_key = "not-valid-base64!!!";
        let result = decode_base64_key(invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_base64_key_wrong_length() {
        let short_key = "AAAA";
        let result = decode_base64_key(short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_checksum() {
        let header = [
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x0a, 0x00, 0x00, 0x02,
            0x0a, 0x00, 0x00, 0x01,
        ];
        
        let checksum = calculate_ip_checksum(&header);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_wireguard_outbound_new() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        
        let (priv_key, _) = generate_keypair();
        let (_, peer_pub) = generate_keypair();
        
        let priv_key_b64 = STANDARD.encode(priv_key);
        let peer_pub_b64 = STANDARD.encode(peer_pub);
        
        let mut options = std::collections::HashMap::new();
        options.insert(
            "private-key".to_string(),
            serde_yaml::Value::String(priv_key_b64),
        );
        options.insert(
            "public-key".to_string(),
            serde_yaml::Value::String(peer_pub_b64),
        );
        options.insert(
            "local-address".to_string(),
            serde_yaml::Value::String("10.0.0.2/32".to_string()),
        );

        let config = OutboundConfig {
            tag: "wg-test".to_string(),
            outbound_type: crate::config::OutboundType::Wireguard,
            server: Some("wg.example.com".to_string()),
            port: Some(51820),
            options,
        };

        let outbound = WireguardOutbound::new(config).unwrap();
        assert_eq!(outbound.tag(), "wg-test");
        assert_eq!(outbound.server, "wg.example.com");
        assert_eq!(outbound.port, 51820);
    }

    #[test]
    fn test_wireguard_outbound_missing_private_key() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "public-key".to_string(),
            serde_yaml::Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
        );

        let config = OutboundConfig {
            tag: "wg-test".to_string(),
            outbound_type: crate::config::OutboundType::Wireguard,
            server: Some("wg.example.com".to_string()),
            port: Some(51820),
            options,
        };

        let result = WireguardOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_wireguard_outbound_server_addr() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        
        let (priv_key, _) = generate_keypair();
        let (_, peer_pub) = generate_keypair();
        
        let mut options = std::collections::HashMap::new();
        options.insert(
            "private-key".to_string(),
            serde_yaml::Value::String(STANDARD.encode(priv_key)),
        );
        options.insert(
            "public-key".to_string(),
            serde_yaml::Value::String(STANDARD.encode(peer_pub)),
        );

        let config = OutboundConfig {
            tag: "wg-test".to_string(),
            outbound_type: crate::config::OutboundType::Wireguard,
            server: Some("wg.example.com".to_string()),
            port: Some(51820),
            options,
        };

        let outbound = WireguardOutbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "wg.example.com");
        assert_eq!(port, 51820);
    }
}
