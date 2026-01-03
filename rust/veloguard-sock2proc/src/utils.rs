use crate::{ProcessInfo, Sock2ProcError};
use std::net::SocketAddr;

/// Utility function to format process information for display
pub fn format_process_info(process_info: &ProcessInfo) -> String {
    let exe_path = process_info.exe_path.as_deref().unwrap_or("<unknown>");
    let cmdline = process_info.cmdline.as_deref().unwrap_or("<unknown>");

    format!(
        "PID: {}, Name: {}, Exe: {}, Cmdline: {}",
        process_info.pid, process_info.name, exe_path, cmdline
    )
}

/// Utility function to format socket address for display
pub fn format_socket_addr(socket_addr: &SocketAddr) -> String {
    format!("{}", socket_addr)
}

/// Utility function to validate socket address
pub fn validate_socket_addr(socket_addr: &SocketAddr) -> Result<(), Sock2ProcError> {
    match socket_addr {
        SocketAddr::V4(addr) => {
            if addr.ip().is_unspecified() && addr.port() == 0 {
                return Err(Sock2ProcError::InvalidSocketAddr);
            }
        }
        SocketAddr::V6(addr) => {
            if addr.ip().is_unspecified() && addr.port() == 0 {
                return Err(Sock2ProcError::InvalidSocketAddr);
            }
        }
    }
    Ok(())
}
