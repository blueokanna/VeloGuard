use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
}

#[derive(Debug, Error)]
pub enum Sock2ProcError {
    #[error("Process not found")]
    ProcessNotFound,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Invalid socket address")]
    InvalidSocketAddr,
    #[error("System error: {0}")]
    SystemError(String),
    #[error("Not implemented for this platform")]
    NotImplemented,
}

/// Find the process that owns the given socket address
pub fn find_process_by_socket(socket_addr: SocketAddr) -> Result<ProcessInfo, Sock2ProcError> {
    #[cfg(target_os = "linux")]
    {
        platform::linux::find_process_by_socket(socket_addr)
    }
    #[cfg(target_os = "macos")]
    {
        platform::macos::find_process_by_socket(socket_addr)
    }
    #[cfg(target_os = "windows")]
    {
        platform::windows::find_process_by_socket(socket_addr)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(Sock2ProcError::NotImplemented)
    }
}

/// Find processes that own TCP sockets
pub fn find_processes_by_tcp_sockets() -> Result<Vec<(SocketAddr, ProcessInfo)>, Sock2ProcError> {
    #[cfg(target_os = "linux")]
    {
        platform::linux::find_processes_by_tcp_sockets()
    }
    #[cfg(target_os = "macos")]
    {
        platform::macos::find_processes_by_tcp_sockets()
    }
    #[cfg(target_os = "windows")]
    {
        platform::windows::find_processes_by_tcp_sockets()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(Sock2ProcError::NotImplemented)
    }
}

/// Find processes that own UDP sockets
pub fn find_processes_by_udp_sockets() -> Result<Vec<(SocketAddr, ProcessInfo)>, Sock2ProcError> {
    #[cfg(target_os = "linux")]
    {
        platform::linux::find_processes_by_udp_sockets()
    }
    #[cfg(target_os = "macos")]
    {
        platform::macos::find_processes_by_udp_sockets()
    }
    #[cfg(target_os = "windows")]
    {
        platform::windows::find_processes_by_udp_sockets()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(Sock2ProcError::NotImplemented)
    }
}

pub mod utils;

#[cfg(target_os = "linux")]
mod platform {
    pub mod linux;
}

#[cfg(target_os = "macos")]
mod platform {
    pub mod macos;
}

#[cfg(target_os = "windows")]
mod platform {
    pub mod windows;
}
