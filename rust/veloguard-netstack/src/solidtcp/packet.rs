//! Packet parsing and building using smoltcp wire types

use crate::solidtcp::error::{Result, SolidTcpError};
use smoltcp::wire::{
    IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet,
    TcpPacket, UdpPacket,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const DEFAULT_MTU: usize = 1500;
pub const DEFAULT_MSS_V4: u16 = 1360;
pub const DEFAULT_MSS_V6: u16 = 1340;

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

impl TcpFlags {
    pub fn syn_only() -> Self {
        Self { syn: true, ..Default::default() }
    }
    pub fn syn_ack() -> Self {
        Self { syn: true, ack: true, ..Default::default() }
    }
    pub fn ack_only() -> Self {
        Self { ack: true, ..Default::default() }
    }
    pub fn fin_ack() -> Self {
        Self { fin: true, ack: true, ..Default::default() }
    }
    pub fn rst_ack() -> Self {
        Self { rst: true, ack: true, ..Default::default() }
    }
    pub fn rst_only() -> Self {
        Self { rst: true, ..Default::default() }
    }
    pub fn psh_ack() -> Self {
        Self { psh: true, ack: true, ..Default::default() }
    }

    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.syn { flags |= 0x02; }
        if self.rst { flags |= 0x04; }
        if self.psh { flags |= 0x08; }
        if self.ack { flags |= 0x10; }
        flags
    }
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub version: IpVersion,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub protocol: IpProtocol,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub transport: TransportInfo,
}

#[derive(Debug, Clone)]
pub enum TransportInfo {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload_len: usize,
}

#[derive(Debug, Clone)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: usize,
}

impl ParsedPacket {
    pub fn src_socket(&self) -> Option<SocketAddr> {
        match &self.transport {
            TransportInfo::Tcp(t) => Some(SocketAddr::new(self.src_addr, t.src_port)),
            TransportInfo::Udp(u) => Some(SocketAddr::new(self.src_addr, u.src_port)),
            _ => None,
        }
    }

    pub fn dst_socket(&self) -> Option<SocketAddr> {
        match &self.transport {
            TransportInfo::Tcp(t) => Some(SocketAddr::new(self.dst_addr, t.dst_port)),
            TransportInfo::Udp(u) => Some(SocketAddr::new(self.dst_addr, u.dst_port)),
            _ => None,
        }
    }

    pub fn is_tcp_syn(&self) -> bool {
        matches!(&self.transport, TransportInfo::Tcp(t) if t.flags.syn && !t.flags.ack)
    }

    pub fn is_dns(&self) -> bool {
        matches!(&self.transport, TransportInfo::Udp(u) if u.dst_port == 53)
    }
}

/// Parse an IP packet
pub fn parse_packet(data: &[u8]) -> Result<ParsedPacket> {
    if data.is_empty() {
        return Err(SolidTcpError::PacketTooShort { expected: 1, actual: 0 });
    }

    let version = (data[0] >> 4) & 0x0F;
    match version {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => Err(SolidTcpError::InvalidIpVersion(version)),
    }
}

fn parse_ipv4(data: &[u8]) -> Result<ParsedPacket> {
    let pkt = Ipv4Packet::new_checked(data)
        .map_err(|e| SolidTcpError::InvalidPacket(format!("IPv4: {}", e)))?;

    let ihl = ((data[0] & 0x0F) as usize) * 4;
    let payload = pkt.payload();
    let protocol = pkt.next_header();

    let src = pkt.src_addr();
    let dst = pkt.dst_addr();

    let transport = parse_transport(protocol, payload)?;

    Ok(ParsedPacket {
        version: IpVersion::Ipv4,
        src_addr: IpAddr::V4(src),
        dst_addr: IpAddr::V4(dst),
        protocol,
        payload_offset: ihl,
        payload_len: payload.len(),
        transport,
    })
}

fn parse_ipv6(data: &[u8]) -> Result<ParsedPacket> {
    let pkt = Ipv6Packet::new_checked(data)
        .map_err(|e| SolidTcpError::InvalidPacket(format!("IPv6: {}", e)))?;

    let payload = pkt.payload();
    let protocol = pkt.next_header();

    let src = pkt.src_addr();
    let dst = pkt.dst_addr();

    let transport = parse_transport(protocol, payload)?;

    Ok(ParsedPacket {
        version: IpVersion::Ipv6,
        src_addr: IpAddr::V6(src),
        dst_addr: IpAddr::V6(dst),
        protocol,
        payload_offset: 40,
        payload_len: payload.len(),
        transport,
    })
}

fn parse_transport(protocol: IpProtocol, payload: &[u8]) -> Result<TransportInfo> {
    match protocol {
        IpProtocol::Tcp => parse_tcp(payload),
        IpProtocol::Udp => parse_udp(payload),
        IpProtocol::Icmp | IpProtocol::Icmpv6 => Ok(TransportInfo::Icmp),
        _ => Ok(TransportInfo::Other(protocol.into())),
    }
}

fn parse_tcp(data: &[u8]) -> Result<TransportInfo> {
    let pkt = TcpPacket::new_checked(data)
        .map_err(|e| SolidTcpError::InvalidPacket(format!("TCP: {}", e)))?;

    let header_len = pkt.header_len() as usize;
    let mut mss = None;

    // Parse options for MSS
    if header_len > 20 && data.len() >= header_len {
        let opts = &data[20..header_len];
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                0 => break,
                1 => i += 1,
                2 if i + 4 <= opts.len() => {
                    mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                    i += 4;
                }
                _ => {
                    if i + 1 < opts.len() && opts[i + 1] > 0 {
                        i += opts[i + 1] as usize;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    Ok(TransportInfo::Tcp(TcpInfo {
        src_port: pkt.src_port(),
        dst_port: pkt.dst_port(),
        seq: pkt.seq_number().0 as u32,
        ack: pkt.ack_number().0 as u32,
        flags: TcpFlags {
            fin: pkt.fin(),
            syn: pkt.syn(),
            rst: pkt.rst(),
            psh: pkt.psh(),
            ack: pkt.ack(),
        },
        window: pkt.window_len(),
        mss,
        payload_len: data.len().saturating_sub(header_len),
    }))
}

fn parse_udp(data: &[u8]) -> Result<TransportInfo> {
    let pkt = UdpPacket::new_checked(data)
        .map_err(|e| SolidTcpError::InvalidPacket(format!("UDP: {}", e)))?;

    Ok(TransportInfo::Udp(UdpInfo {
        src_port: pkt.src_port(),
        dst_port: pkt.dst_port(),
        payload_len: pkt.payload().len(),
    }))
}

/// Build IPv4 TCP packet
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
    mss: Option<u16>,
) -> Vec<u8> {
    use std::sync::atomic::{AtomicU16, Ordering};
    static IP_ID: AtomicU16 = AtomicU16::new(1);
    
    let tcp_opts_len = if flags.syn && mss.is_some() { 4 } else { 0 };
    let tcp_hdr_len = 20 + tcp_opts_len;
    let total_len = 20 + tcp_hdr_len + payload.len();

    let mut pkt = vec![0u8; total_len];

    // IPv4 header
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    
    let ip_id = IP_ID.fetch_add(1, Ordering::Relaxed);
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
    
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    let ip_cksum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // TCP header
    let tcp_start = 20;
    pkt[tcp_start..tcp_start+2].copy_from_slice(&src_port.to_be_bytes());
    pkt[tcp_start+2..tcp_start+4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[tcp_start+4..tcp_start+8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_start+8..tcp_start+12].copy_from_slice(&ack.to_be_bytes());
    pkt[tcp_start+12] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[tcp_start+13] = flags.to_byte();
    pkt[tcp_start+14..tcp_start+16].copy_from_slice(&window.to_be_bytes());

    if flags.syn {
        if let Some(mss_val) = mss {
            pkt[tcp_start+20] = 2;
            pkt[tcp_start+21] = 4;
            pkt[tcp_start+22..tcp_start+24].copy_from_slice(&mss_val.to_be_bytes());
        }
    }

    let payload_start = tcp_start + tcp_hdr_len;
    if !payload.is_empty() {
        pkt[payload_start..payload_start+payload.len()].copy_from_slice(payload);
    }

    let tcp_cksum = tcp_checksum(&src_ip.octets(), &dst_ip.octets(), &pkt[tcp_start..]);
    pkt[tcp_start+16..tcp_start+18].copy_from_slice(&tcp_cksum.to_be_bytes());

    pkt
}

/// Build IPv4 UDP packet
pub fn build_ipv4_udp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    let ip_cksum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    let udp_len = (8 + payload.len()) as u16;
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());

    if !payload.is_empty() {
        pkt[28..].copy_from_slice(payload);
    }

    let udp_cksum = udp_checksum(&src_ip.octets(), &dst_ip.octets(), &pkt[20..]);
    pkt[26..28].copy_from_slice(&udp_cksum.to_be_bytes());

    pkt
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn tcp_checksum(src: &[u8; 4], dst: &[u8; 4], tcp: &[u8]) -> u16 {
    transport_checksum(src, dst, 6, tcp)
}

fn udp_checksum(src: &[u8; 4], dst: &[u8; 4], udp: &[u8]) -> u16 {
    let cksum = transport_checksum(src, dst, 17, udp);
    if cksum == 0 { 0xFFFF } else { cksum }
}

fn transport_checksum(src: &[u8; 4], dst: &[u8; 4], proto: u8, data: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = sum.wrapping_add(((src[0] as u32) << 8) | src[1] as u32);
    sum = sum.wrapping_add(((src[2] as u32) << 8) | src[3] as u32);
    sum = sum.wrapping_add(((dst[0] as u32) << 8) | dst[1] as u32);
    sum = sum.wrapping_add(((dst[2] as u32) << 8) | dst[3] as u32);
    sum = sum.wrapping_add(proto as u32);
    sum = sum.wrapping_add(data.len() as u32);
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Packet parser utility struct
pub struct PacketParser;

impl PacketParser {
    pub fn parse(data: &[u8]) -> Result<ParsedPacket> {
        parse_packet(data)
    }
}

/// Packet builder utility struct
pub struct PacketBuilder;

impl PacketBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn build_ipv4_tcp(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
        payload: &[u8],
        mss: Option<u16>,
    ) -> Vec<u8> {
        build_ipv4_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window, payload, mss)
    }

    pub fn build_ipv4_udp(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        build_ipv4_udp(src_ip, dst_ip, src_port, dst_port, payload)
    }
}
