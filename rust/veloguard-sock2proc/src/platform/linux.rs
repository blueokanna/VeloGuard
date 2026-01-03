use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;

use crate::{ProcessInfo, Sock2ProcError};

/// Convert hex string to IPv4 address
fn hex_to_ipv4(hex: &str) -> Result<Ipv4Addr, Sock2ProcError> {
    if hex.len() != 8 {
        return Err(Sock2ProcError::InvalidSocketAddr);
    }

    let bytes = (0..4)
        .map(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Sock2ProcError::InvalidSocketAddr)?;

    Ok(Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]))
}

/// Convert hex string to IPv6 address
fn hex_to_ipv6(hex: &str) -> Result<Ipv6Addr, Sock2ProcError> {
    if hex.len() != 32 {
        return Err(Sock2ProcError::InvalidSocketAddr);
    }

    let bytes: [u8; 16] = (0..16)
        .map(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Sock2ProcError::InvalidSocketAddr)?
        .try_into()
        .map_err(|_| Sock2ProcError::InvalidSocketAddr)?;

    Ok(Ipv6Addr::from(bytes))
}

/// Convert hex string to port number
fn hex_to_port(hex: &str) -> Result<u16, Sock2ProcError> {
    u16::from_str_radix(hex, 16).map_err(|_| Sock2ProcError::InvalidSocketAddr)
}

/// Parse socket address from /proc/net/tcp or /proc/net/udp format
fn parse_socket_addr(line: &str, is_ipv6: bool) -> Result<SocketAddr, Sock2ProcError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return Err(Sock2ProcError::InvalidSocketAddr);
    }

    let local_addr_hex = parts[1];
    let addr_port: Vec<&str> = local_addr_hex.split(':').collect();
    if addr_port.len() != 2 {
        return Err(Sock2ProcError::InvalidSocketAddr);
    }

    let port = hex_to_port(addr_port[1])?;

    if is_ipv6 {
        let addr = hex_to_ipv6(addr_port[0])?;
        Ok(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0)))
    } else {
        let addr = hex_to_ipv4(addr_port[0])?;
        Ok(SocketAddr::V4(SocketAddrV4::new(addr, port)))
    }
}

/// Build inode to process mapping
fn build_inode_process_map() -> Result<HashMap<String, ProcessInfo>, Sock2ProcError> {
    let mut map = HashMap::new();

    let proc_dir = Path::new("/proc");
    let entries = fs::read_dir(proc_dir)
        .map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;

    for entry in entries {
        let entry = entry.map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;
        let path = entry.path();

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if let Ok(pid) = name.parse::<u32>() {
                let fd_dir = path.join("fd");
                if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                    for fd_entry in fd_entries {
                        if let Ok(fd_entry) = fd_entry {
                            if let Ok(link) = fs::read_link(fd_entry.path()) {
                                if let Some(link_str) = link.to_str() {
                                    if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                                        let inode = &link_str[8..link_str.len()-1];
                                        let process_info = get_process_info(pid)?;
                                        map.insert(inode.to_string(), process_info);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(map)
}

/// Get process information from /proc/<pid>
fn get_process_info(pid: u32) -> Result<ProcessInfo, Sock2ProcError> {
    let proc_path = format!("/proc/{}", pid);

    let cmdline = fs::read_to_string(format!("{}/cmdline", proc_path))
        .ok()
        .map(|s| s.replace('\0', " ").trim().to_string());

    let exe_path = fs::read_link(format!("{}/exe", proc_path))
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()));

    let status = fs::read_to_string(format!("{}/status", proc_path))
        .map_err(|_| Sock2ProcError::ProcessNotFound)?;

    let name = status
        .lines()
        .find(|line| line.starts_with("Name:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("unknown")
        .to_string();

    Ok(ProcessInfo {
        pid,
        name,
        exe_path,
        cmdline,
    })
}

/// Find process by socket address for TCP connections
pub fn find_process_by_socket(socket_addr: SocketAddr) -> Result<ProcessInfo, Sock2ProcError> {
    let inode_map = build_inode_process_map()?;

    let tcp_content = fs::read_to_string("/proc/net/tcp")
        .map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;

    for line in tcp_content.lines().skip(1) {
        if let Ok(addr) = parse_socket_addr(line, false) {
            if addr == socket_addr {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let inode = parts[9];
                    if let Some(process_info) = inode_map.get(inode) {
                        return Ok(process_info.clone());
                    }
                }
            }
        }
    }

    if let Ok(tcp6_content) = fs::read_to_string("/proc/net/tcp6") {
        for line in tcp6_content.lines().skip(1) {
            if let Ok(addr) = parse_socket_addr(line, true) {
                if addr == socket_addr {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        let inode = parts[9];
                        if let Some(process_info) = inode_map.get(inode) {
                            return Ok(process_info.clone());
                        }
                    }
                }
            }
        }
    }

    let udp_content = fs::read_to_string("/proc/net/udp")
        .map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;

    for line in udp_content.lines().skip(1) {
        if let Ok(addr) = parse_socket_addr(line, false) {
            if addr == socket_addr {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let inode = parts[9];
                    if let Some(process_info) = inode_map.get(inode) {
                        return Ok(process_info.clone());
                    }
                }
            }
        }
    }

    if let Ok(udp6_content) = fs::read_to_string("/proc/net/udp6") {
        for line in udp6_content.lines().skip(1) {
            if let Ok(addr) = parse_socket_addr(line, true) {
                if addr == socket_addr {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        let inode = parts[9];
                        if let Some(process_info) = inode_map.get(inode) {
                            return Ok(process_info.clone());
                        }
                    }
                }
            }
        }
    }

    Err(Sock2ProcError::ProcessNotFound)
}

/// Find all processes with TCP sockets
pub fn find_processes_by_tcp_sockets() -> Result<Vec<(SocketAddr, ProcessInfo)>, Sock2ProcError> {
    let inode_map = build_inode_process_map()?;
    let mut result = Vec::new();

    let tcp_content = fs::read_to_string("/proc/net/tcp")
        .map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;

    for line in tcp_content.lines().skip(1) {
        if let Ok(addr) = parse_socket_addr(line, false) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let inode = parts[9];
                if let Some(process_info) = inode_map.get(inode) {
                    result.push((addr, process_info.clone()));
                }
            }
        }
    }

    if let Ok(tcp6_content) = fs::read_to_string("/proc/net/tcp6") {
        for line in tcp6_content.lines().skip(1) {
            if let Ok(addr) = parse_socket_addr(line, true) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let inode = parts[9];
                    if let Some(process_info) = inode_map.get(inode) {
                        result.push((addr, process_info.clone()));
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Find all processes with UDP sockets
pub fn find_processes_by_udp_sockets() -> Result<Vec<(SocketAddr, ProcessInfo)>, Sock2ProcError> {
    let inode_map = build_inode_process_map()?;
    let mut result = Vec::new();

    let udp_content = fs::read_to_string("/proc/net/udp")
        .map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;

    for line in udp_content.lines().skip(1) {
        if let Ok(addr) = parse_socket_addr(line, false) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let inode = parts[9];
                if let Some(process_info) = inode_map.get(inode) {
                    result.push((addr, process_info.clone()));
                }
            }
        }
    }

    if let Ok(udp6_content) = fs::read_to_string("/proc/net/udp6") {
        for line in udp6_content.lines().skip(1) {
            if let Ok(addr) = parse_socket_addr(line, true) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let inode = parts[9];
                    if let Some(process_info) = inode_map.get(inode) {
                        result.push((addr, process_info.clone()));
                    }
                }
            }
        }
    }

    Ok(result)
}
