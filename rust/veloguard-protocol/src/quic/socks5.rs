use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use super::address::Address;
use super::client::QuicClient;
use super::error::{Result, QuicError};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REP_CONN_REFUSED: u8 = 0x05;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;

pub struct Socks5Server {
    listener: TcpListener,
    client: Arc<QuicClient>,
}

impl Socks5Server {
    pub async fn bind(addr: SocketAddr, client: Arc<QuicClient>) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("SOCKS5 server listening on {}", addr);
        Ok(Self { listener, client })
    }

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

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

async fn handle_socks5_connection(mut stream: TcpStream, client: Arc<QuicClient>) -> Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    if buf[0] != SOCKS5_VERSION {
        return Err(QuicError::Protocol("Invalid SOCKS version".to_string()));
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&SOCKS5_AUTH_NONE) {
        stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
        return Err(QuicError::Protocol("No supported auth method".to_string()));
    }

    stream.write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE]).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS5_VERSION {
        return Err(QuicError::Protocol("Invalid SOCKS version".to_string()));
    }

    let cmd = header[1];
    let atyp = header[3];

    let target = parse_address(&mut stream, atyp).await?;

    match cmd {
        SOCKS5_CMD_CONNECT => handle_tcp_connect(&mut stream, client, target).await,
        _ => {
            send_reply(&mut stream, SOCKS5_REP_CMD_NOT_SUPPORTED, None).await?;
            Err(QuicError::UnsupportedCommand(cmd))
        }
    }
}

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

async fn send_reply(stream: &mut TcpStream, rep: u8, bind_addr: Option<SocketAddr>) -> Result<()> {
    let bind = bind_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

    let mut reply = Vec::with_capacity(22);
    reply.push(SOCKS5_VERSION);
    reply.push(rep);
    reply.push(0x00);

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

async fn handle_tcp_connect(stream: &mut TcpStream, client: Arc<QuicClient>, target: Address) -> Result<()> {
    debug!("TCP CONNECT to {}", target);

    let conn = match client.connect().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to server: {}", e);
            send_reply(stream, SOCKS5_REP_GENERAL_FAILURE, None).await?;
            return Err(e);
        }
    };

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

    send_reply(stream, SOCKS5_REP_SUCCESS, None).await?;

    let (mut client_read, mut client_write) = stream.split();
    let (quic_send, quic_recv) = quic_stream.split();

    let client_to_server = async {
        let mut buf = vec![0u8; 8192];
        let mut send = quic_send;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_raw(&buf[..n]).await.is_err() { break; }
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
                    if client_write.write_all(&buf[..n]).await.is_err() { break; }
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
