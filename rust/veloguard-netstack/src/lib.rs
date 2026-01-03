//! VeloGuard Network Stack
//!
//! A userspace TCP/IP stack for TUN-based transparent proxying.
//!
//! This crate provides:
//! - TUN device management (cross-platform, using wintun on Windows)
//! - TCP connection handling with NAT
//! - UDP session handling with NAT
//! - IP packet parsing and generation using smoltcp
//! - DNS resolution with DoH/DoT support (via veloguard-dns)
//! - Fake-IP mode for transparent proxying
//!
//! # Platform Requirements
//!
//! ## Windows
//! Requires `wintun.dll` in the executable directory.
//! The library will attempt to download it automatically if not present.
//! Manual download: https://www.wintun.net/
//!
//! ## Linux
//! Requires CAP_NET_ADMIN capability or root privileges.
//!
//! ## macOS
//! Requires root privileges.
//!
//! ## Android
//! Requires VpnService permission.
//!
//! # Example
//!
//! ```rust,no_run
//! use veloguard_netstack::{NetStack, NetStackBuilder};
//!
//! async fn run() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create network stack
//!     let mut stack = NetStackBuilder::new()
//!         .tun_name("VeloGuard")
//!         .tun_address("198.18.0.1".parse()?)
//!         .tun_netmask("255.255.0.0".parse()?)
//!         .enable_tcp(true)
//!         .enable_udp(true)
//!         .build()
//!         .await?;
//!
//!     // Create TUN device
//!     stack.create_tun("VeloGuard", "198.18.0.1", "255.255.0.0").await?;
//!
//!     // Start the stack
//!     stack.start().await?;
//!
//!     // Get TCP listener
//!     if let Some(mut tcp_listener) = stack.tcp_listener() {
//!         while let Some(conn) = tcp_listener.accept().await {
//!             // Handle TCP connection
//!             println!("New TCP connection: {} -> {}", conn.src_addr(), conn.dst_addr());
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod route;
pub mod stack;
pub mod tcp;
pub mod tun;
pub mod udp;
#[cfg(windows)]
pub mod wintun_embed;
#[cfg(windows)]
pub mod windows_vpn;
#[cfg(windows)]
pub mod windows_route;
#[cfg(target_os = "android")]
pub mod android_vpn;
#[cfg(target_os = "android")]
pub mod android_tun;

// Re-exports
pub use error::{NetStackError, Result};
pub use route::RouteManager;
pub use stack::{NetStack, NetStackBuilder, StackConfig, StackStats};
pub use tcp::{TcpConnection, TcpConnectionId, TcpListener, TcpStack, TcpState, TcpStream};
pub use tun::{TunConfig, TunDevice};
pub use udp::{UdpListener, UdpNatTable, UdpPacket, UdpSession, UdpSocket, UdpStack};

// Re-export DNS types from veloguard-dns crate
pub use veloguard_dns::{
    // Core types
    DnsManager, DnsConfig, DnsCache, DnsError, DnsResolver, DnsServer,
    // DoH/DoT
    DohClient, DohResolver, DohClientConfig, DohMethod,
    DotClient, DotResolver, DotClientConfig,
    // Fake-IP
    FakeIpPool, FakeIpEntry,
    // Config
    UpstreamConfig, UpstreamProtocol, FallbackFilter,
    // Client
    DnsClient, DnsProtocol,
    // Other
    HostsFile, RecordType, CacheStatistics, DnsManagerState,
    Result as DnsResult,
};

// Android-specific exports
#[cfg(target_os = "android")]
pub use tun::{
    set_android_vpn_fd, get_android_vpn_fd, clear_android_vpn_fd,
    set_android_proxy_mode, get_android_proxy_mode,
    ANDROID_VPN_FD, ANDROID_PROXY_MODE,
};

#[cfg(target_os = "android")]
pub use android_vpn::{AndroidVpnProcessor, VpnTrafficStats};

#[cfg(target_os = "android")]
pub use android_tun::{
    set_protect_callback, protect_socket, has_protect_callback, clear_protect_callback,
    AndroidTunProcessor, FakeIpPool as AndroidFakeIpPool,
};

// Windows-specific exports
#[cfg(windows)]
pub use windows_vpn::{
    WindowsVpnProcessor, WindowsVpnTrafficStats,
    set_windows_proxy_mode, get_windows_proxy_mode, WINDOWS_PROXY_MODE,
};

#[cfg(windows)]
pub use windows_route::{WindowsRouteManager, set_tun_dns, flush_dns_cache};

/// Check if wintun.dll is available (Windows only)
#[cfg(windows)]
pub fn check_wintun_available() -> bool {
    wintun_embed::is_wintun_available()
}

/// Check if wintun.dll is available (non-Windows)
#[cfg(not(windows))]
pub fn check_wintun_available() -> bool {
    true // Not needed on non-Windows platforms
}

/// Get the path where wintun.dll should be placed
#[cfg(windows)]
pub fn get_wintun_path() -> Option<std::path::PathBuf> {
    wintun_embed::get_wintun_dll_path().ok()
}

/// Get the path where wintun.dll should be placed (non-Windows)
#[cfg(not(windows))]
pub fn get_wintun_path() -> Option<std::path::PathBuf> {
    None
}

/// Ensure wintun.dll is available, downloading if necessary (Windows only)
#[cfg(windows)]
pub async fn ensure_wintun() -> Result<std::path::PathBuf> {
    // First try to use existing or embedded
    if let Ok(path) = wintun_embed::ensure_wintun_available() {
        return Ok(path);
    }
    
    // Try to download
    wintun_embed::download_wintun_dll().await
}

/// Ensure wintun.dll is available (non-Windows - always succeeds)
#[cfg(not(windows))]
pub async fn ensure_wintun() -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.name, "VeloGuard");
        assert_eq!(config.address, std::net::Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(config.mtu, 1500);
    }

    #[test]
    fn test_stack_config_default() {
        let config = StackConfig::default();
        assert!(config.enable_tcp);
        assert!(config.enable_udp);
        assert_eq!(config.tcp_buffer_size, 64 * 1024);
    }

    #[test]
    fn test_tcp_connection_id() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let id = TcpConnectionId {
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443),
        };

        assert_eq!(id.src_addr.port(), 12345);
        assert_eq!(id.dst_addr.port(), 443);
    }

    #[test]
    fn test_udp_nat_table() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let nat = UdpNatTable::new(30000);
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);

        let port1 = nat.get_or_create(src, dst).unwrap();
        let port2 = nat.get_or_create(src, dst).unwrap();

        assert_eq!(port1, port2); // Same mapping should return same port
        assert!(port1 >= 30000);
    }
}
