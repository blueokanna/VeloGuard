use std::net::SocketAddr;
use std::process::Command;

use crate::{ProcessInfo, Sock2ProcError};

/// Parse lsof output to extract process information
fn parse_lsof_output(line: &str) -> Option<(SocketAddr, ProcessInfo)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let command = parts[0];
    let pid = parts[1].parse::<u32>().ok()?;

    let socket_info = parts[8];
    if !socket_info.contains("->") {
        return None;
    }

    let addr_part = socket_info.split("->").next()?;
    let addr_str = if addr_part.contains(':') {
        addr_part
    } else {
        return None;
    };

    let addr_parts: Vec<&str> = addr_str.split(':').collect();
    if addr_parts.len() != 2 {
        return None;
    }

    let ip_str = addr_parts[0];
    let port_str = addr_parts[1];

    let ip = if ip_str == "*" {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
    } else {
        ip_str.parse().ok()?
    };

    let port = port_str.parse().ok()?;

    let socket_addr = SocketAddr::new(ip, port);

    let process_info = ProcessInfo {
        pid,
        name: command.to_string(),
        exe_path: None,
        cmdline: None,
    };

    Some((socket_addr, process_info))
}

/// Find process by socket address using lsof
pub fn find_process_by_socket(socket_addr: SocketAddr) -> Result<ProcessInfo, Sock2ProcError> {
    let output = Command::new("lsof")
        .args(["-i", &format!("{}", socket_addr)])
        .output()
        .map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;

    if !output.status.success() {
        return Err(Sock2ProcError::SystemError("lsof command failed".to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        if let Some((addr, info)) = parse_lsof_output(line) {
            if addr == socket_addr {
                return Ok(info);
            }
        }
    }

    Err(Sock2ProcError::ProcessNotFound)
}

/// Find all processes with TCP sockets using lsof
pub fn find_processes_by_tcp_sockets() -> Result<Vec<(SocketAddr, ProcessInfo)>, Sock2ProcError> {
    let output = Command::new("lsof")
        .args(["-i", "tcp"])
        .output()
        .map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;

    if !output.status.success() {
        return Err(Sock2ProcError::SystemError("lsof command failed".to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();

    for line in stdout.lines().skip(1) {
        if let Some((addr, info)) = parse_lsof_output(line) {
            result.push((addr, info));
        }
    }

    Ok(result)
}

/// Find all processes with UDP sockets using lsof
pub fn find_processes_by_udp_sockets() -> Result<Vec<(SocketAddr, ProcessInfo)>, Sock2ProcError> {
    let output = Command::new("lsof")
        .args(["-i", "udp"])
        .output()
        .map_err(|e| Sock2ProcError::SystemError(e.to_string()))?;

    if !output.status.success() {
        return Err(Sock2ProcError::SystemError("lsof command failed".to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();

    for line in stdout.lines().skip(1) {
        if let Some((addr, info)) = parse_lsof_output(line) {
            result.push((addr, info));
        }
    }

    Ok(result)
}
