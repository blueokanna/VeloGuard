use parking_lot::RwLock;
use std::sync::Arc;
use tracing::info;

#[cfg(target_os = "android")]
use tracing::{debug, warn};

#[cfg(target_os = "android")]
use std::os::unix::io::AsRawFd;

/// Socket 保护回调类型
type ProtectCallback = Arc<dyn Fn(i32) -> bool + Send + Sync>;

#[allow(clippy::type_complexity)]
static PROTECT_CALLBACK: RwLock<Option<ProtectCallback>> = RwLock::new(None);
pub fn set_protect_callback<F>(callback: F)
where
    F: Fn(i32) -> bool + Send + Sync + 'static,
{
    let mut guard = PROTECT_CALLBACK.write();
    *guard = Some(Arc::new(callback));
    info!("veloguard-core: Socket protect callback registered");
}

pub fn clear_protect_callback() {
    let mut guard = PROTECT_CALLBACK.write();
    *guard = None;
    info!("veloguard-core: Socket protect callback cleared");
}

pub fn has_protect_callback() -> bool {
    PROTECT_CALLBACK.read().is_some()
}

#[cfg(target_os = "android")]
pub fn protect_socket(fd: i32) -> bool {
    let guard = PROTECT_CALLBACK.read();
    if let Some(ref callback) = *guard {
        let result = callback(fd);
        if result {
            debug!("Socket fd={} protected successfully", fd);
        } else {
            warn!("Socket fd={} protection FAILED", fd);
        }
        result
    } else {
        // Fallback: allow the connection and only emit a low-level debug to avoid noisy warnings.
        debug!(
            "No protect callback set for socket fd={}, using fallback allow",
            fd
        );
        true
    }
}

#[cfg(not(target_os = "android"))]
pub fn protect_socket(_fd: i32) -> bool {
    true
}

#[cfg(target_os = "android")]
pub fn protect_tcp_stream(stream: &tokio::net::TcpStream) -> bool {
    let fd = stream.as_raw_fd();
    protect_socket(fd)
}

#[cfg(not(target_os = "android"))]
pub fn protect_tcp_stream(_stream: &tokio::net::TcpStream) -> bool {
    true
}

#[cfg(target_os = "android")]
pub fn protect_socket2(socket: &socket2::Socket) -> bool {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    protect_socket(fd)
}

#[cfg(not(target_os = "android"))]
pub fn protect_socket2(_socket: &socket2::Socket) -> bool {
    true
}

#[cfg(target_os = "android")]
pub async fn connect_protected(addr: &str) -> std::io::Result<tokio::net::TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let socket_addr: SocketAddr = tokio::net::lookup_host(addr).await?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Could not resolve address: {}", addr),
        )
    })?;

    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    let fd = socket.as_raw_fd();
    if !protect_socket(fd) {
        warn!(
            "Failed to protect socket fd={}, connection may cause routing loop",
            fd
        );
    }

    socket.set_nonblocking(true)?;
    match socket.connect(&socket_addr.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = tokio::net::TcpStream::from_std(std_stream)?;

    stream.writable().await?;

    if let Some(e) = stream.take_error()? {
        return Err(e);
    }

    Ok(stream)
}

#[cfg(not(target_os = "android"))]
pub async fn connect_protected(addr: &str) -> std::io::Result<tokio::net::TcpStream> {
    tokio::net::TcpStream::connect(addr).await
}

pub async fn connect_protected_timeout(
    addr: &str,
    timeout: std::time::Duration,
) -> std::io::Result<tokio::net::TcpStream> {
    tokio::time::timeout(timeout, connect_protected(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timeout"))?
}
