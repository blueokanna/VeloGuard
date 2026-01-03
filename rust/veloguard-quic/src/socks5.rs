//! SOCKS5 proxy server for VeloGuard QUIC client

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use crate::address::Address;
use crate::client::QuicClient;
use crate::error::{Result, QuicError};

/// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
#[allow(dead_code)]
const SOCKS5_REP_CONN_NOT_ALLOWED: u8 = 0x02;
#[allow(dead_code)]
const SOCKS5_REP_NETWORK_UNREACHABLE: u8 = 0x03;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REP_CONN_REFUSED: u8 = 0x05;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
#[allow(dead_code)]
const SOCKS5_REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 proxy server
pub struct Socks5Server {
    listener: TcpListener,
    client: Arc<QuicClient>,
}

impl Socks5Server {
    /// Create a new SOCKS5 server
    pub async fn bind(addr: SocketAddr, client: Arc<QuicClient>) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("SOCKS5 server listening on {}", addr);
        Ok(Self { listener, client })
    }

    /// Run the SOCKS5 server
    pub async fn run(&self) -> Result<()> {
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            debug!("New SOCKS5 connection from {}", peer_addr);

            let client = self.client.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_socks5_connection(stream, client).await {
                    debug!("SOCKS5 connection error: {}", e);
                }
            });
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

/// Handle a single SOCKS5 connection
async fn handle_socks5_connection(
    mut stream: TcpStream,
    client: Arc<QuicClient>,
) -> Result<()> {
    // Read version and auth methods
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    if buf[0] != SOCKS5_VERSION {
        return Err(QuicError::Protocol("Invalid SOCKS version".to_string()));
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // We only support no authentication
    if !methods.contains(&SOCKS5_AUTH_NONE) {
        stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
        return Err(QuicError::Protocol("No supported auth method".to_string()));
    }

    // Send auth response
    stream.write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE]).await?;

    // Read request
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS5_VERSION {
        return Err(QuicError::Protocol("Invalid SOCKS version".to_string()));
    }

    let cmd = header[1];
    let atyp = header[3];

    // Parse target address
    let target = parse_address(&mut stream, atyp).await?;

    match cmd {
        SOCKS5_CMD_CONNECT => {
            handle_tcp_connect(&mut stream, client, target).await
        }
        SOCKS5_CMD_UDP_ASSOCIATE => {
            handle_udp_associate(&mut stream, client, target).await
        }
        _ => {
            send_reply(&mut stream, SOCKS5_REP_CMD_NOT_SUPPORTED, None).await?;
            Err(QuicError::UnsupportedCommand(cmd))
        }
    }
}

/// Parse SOCKS5 address
async fn parse_address(stream: &mut TcpStream, atyp: u8) -> Result<Address> {
    match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            let ip = std::net::Ipv4Addr::from(addr);
            Ok(Address::from(SocketAddr::from((ip, port))))
        }
        SOCKS5_ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            let ip = std::net::Ipv6Addr::from(addr);
            Ok(Address::from(SocketAddr::from((ip, port))))
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let len = len[0] as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            let domain = String::from_utf8(domain)
                .map_err(|_| QuicError::AddressParse("Invalid domain".to_string()))?;
            Ok(Address::from_domain(domain, port))
        }
        _ => Err(QuicError::UnsupportedAddressType(atyp)),
    }
}

/// Send SOCKS5 reply
async fn send_reply(
    stream: &mut TcpStream,
    rep: u8,
    bind_addr: Option<SocketAddr>,
) -> Result<()> {
    let bind = bind_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

    let mut reply = Vec::with_capacity(22);
    reply.push(SOCKS5_VERSION);
    reply.push(rep);
    reply.push(0x00); // Reserved

    match bind {
        SocketAddr::V4(addr) => {
            reply.push(SOCKS5_ATYP_IPV4);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            reply.push(SOCKS5_ATYP_IPV6);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    stream.write_all(&reply).await?;
    Ok(())
}

/// Handle TCP CONNECT command
async fn handle_tcp_connect(
    stream: &mut TcpStream,
    client: Arc<QuicClient>,
    target: Address,
) -> Result<()> {
    debug!("TCP CONNECT to {}", target);

    // Connect to server
    let conn = match client.connect().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to server: {}", e);
            send_reply(stream, SOCKS5_REP_GENERAL_FAILURE, None).await?;
            return Err(e);
        }
    };

    // Open stream to target
    let quic_stream = match conn.open_tcp_stream(target.clone()).await {
        Ok(s) => s,
        Err(e) => {
            let rep = match &e {
                QuicError::Protocol(msg) if msg.contains("refused") => SOCKS5_REP_CONN_REFUSED,
                QuicError::Protocol(msg) if msg.contains("unreachable") => SOCKS5_REP_HOST_UNREACHABLE,
                _ => SOCKS5_REP_GENERAL_FAILURE,
            };
            send_reply(stream, rep, None).await?;
            return Err(e);
        }
    };

    // Send success reply
    send_reply(stream, SOCKS5_REP_SUCCESS, None).await?;

    // Relay data
    let (mut client_read, mut client_write) = stream.split();
    let (quic_send, quic_recv) = quic_stream.split();

    let client_to_server = async {
        let mut buf = vec![0u8; 8192];
        let mut send = quic_send;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_raw(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = send.finish().await;
    };

    let server_to_client = async {
        let mut buf = vec![0u8; 8192];
        let mut recv = quic_recv;
        loop {
            match recv.read_raw(&mut buf).await {
                Ok(Some(n)) if n > 0 => {
                    if client_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    };

    tokio::select! {
        _ = client_to_server => {}
        _ = server_to_client => {}
    }

    Ok(())
}

/// Handle UDP ASSOCIATE command
async fn handle_udp_associate(
    stream: &mut TcpStream,
    client: Arc<QuicClient>,
    _target: Address,
) -> Result<()> {
    debug!("UDP ASSOCIATE requested");

    // Connect to server
    let conn = match client.connect().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to server: {}", e);
            send_reply(stream, SOCKS5_REP_GENERAL_FAILURE, None).await?;
            return Err(e);
        }
    };

    // Bind local UDP socket
    let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = udp_socket.local_addr()?;

    // Open UDP session
    let bind_addr = Address::from(local_addr);
    let udp_session = match conn.open_udp_session(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            send_reply(stream, SOCKS5_REP_GENERAL_FAILURE, None).await?;
            return Err(e);
        }
    };

    // Send success reply with bound address
    send_reply(stream, SOCKS5_REP_SUCCESS, Some(local_addr)).await?;

    let udp_socket = Arc::new(udp_socket);
    let socket_clone = udp_socket.clone();

    // Use channels to communicate between tasks
    let (tx_to_server, mut rx_to_server) = tokio::sync::mpsc::channel::<(Vec<u8>, Address)>(32);
    let (tx_to_client, mut rx_to_client) = tokio::sync::mpsc::channel::<(Vec<u8>, Address)>(32);

    // Task: Read from local UDP socket and send to channel
    let udp_read_task = {
        let tx = tx_to_server;
        async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket_clone.recv_from(&mut buf).await {
                    Ok((n, _from)) => {
                        if n < 10 {
                            continue;
                        }
                        let atyp = buf[3];
                        let (target, header_len) = match parse_udp_header(&buf[..n], atyp) {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                        let payload = buf[header_len..n].to_vec();
                        if tx.send((payload, target)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    };

    // Task: Handle QUIC UDP session
    let quic_task = async move {
        let mut session = udp_session;
        loop {
            tokio::select! {
                Some((payload, target)) = rx_to_server.recv() => {
                    let _ = session.send_to(&payload, &target).await;
                }
                result = session.recv_from() => {
                    match result {
                        Ok(Some((data, from))) => {
                            if tx_to_client.send((data, from)).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
    };

    // Task: Write to local UDP socket
    let udp_write_task = async move {
        while let Some((data, from)) = rx_to_client.recv().await {
            let mut packet = build_udp_header(&from);
            packet.extend_from_slice(&data);
            // We would need to track the client address to send back
            // For now, this is a simplified implementation
        }
    };

    // Keep connection alive while TCP stream is open
    let keep_alive = async {
        let mut buf = [0u8; 1];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Err(_) => break,
                _ => {}
            }
        }
    };

    tokio::select! {
        _ = udp_read_task => {}
        _ = quic_task => {}
        _ = udp_write_task => {}
        _ = keep_alive => {}
    }

    Ok(())
}

/// Parse SOCKS5 UDP header
fn parse_udp_header(data: &[u8], atyp: u8) -> Result<(Address, usize)> {
    let mut offset = 4; // Skip RSV + FRAG + ATYP

    match atyp {
        SOCKS5_ATYP_IPV4 => {
            if data.len() < offset + 6 {
                return Err(QuicError::BufferTooSmall);
            }
            let ip = std::net::Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            offset += 4;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            Ok((Address::from(SocketAddr::from((ip, port))), offset))
        }
        SOCKS5_ATYP_IPV6 => {
            if data.len() < offset + 18 {
                return Err(QuicError::BufferTooSmall);
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[offset..offset + 16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            offset += 16;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            Ok((Address::from(SocketAddr::from((ip, port))), offset))
        }
        SOCKS5_ATYP_DOMAIN => {
            if data.len() < offset + 1 {
                return Err(QuicError::BufferTooSmall);
            }
            let domain_len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + domain_len + 2 {
                return Err(QuicError::BufferTooSmall);
            }
            let domain = String::from_utf8(data[offset..offset + domain_len].to_vec())
                .map_err(|_| QuicError::AddressParse("Invalid domain".to_string()))?;
            offset += domain_len;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            Ok((Address::from_domain(domain, port), offset))
        }
        _ => Err(QuicError::UnsupportedAddressType(atyp)),
    }
}

/// Build SOCKS5 UDP header
fn build_udp_header(addr: &Address) -> Vec<u8> {
    let mut header = Vec::with_capacity(22);
    header.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG

    match addr {
        Address::SocketAddr(SocketAddr::V4(a)) => {
            header.push(SOCKS5_ATYP_IPV4);
            header.extend_from_slice(&a.ip().octets());
            header.extend_from_slice(&a.port().to_be_bytes());
        }
        Address::SocketAddr(SocketAddr::V6(a)) => {
            header.push(SOCKS5_ATYP_IPV6);
            header.extend_from_slice(&a.ip().octets());
            header.extend_from_slice(&a.port().to_be_bytes());
        }
        Address::DomainName(domain, port) => {
            header.push(SOCKS5_ATYP_DOMAIN);
            header.push(domain.len() as u8);
            header.extend_from_slice(domain.as_bytes());
            header.extend_from_slice(&port.to_be_bytes());
        }
    }

    header
}
