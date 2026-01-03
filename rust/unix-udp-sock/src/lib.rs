#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::task::{Context, Poll};

#[cfg(unix)]
use futures::future::poll_fn;
#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UnixUdpError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Socket not connected")]
    NotConnected,
    #[error("Socket already connected")]
    AlreadyConnected,
    #[error("Not supported on this platform")]
    NotSupported,
}

#[cfg(unix)]
/// Unix domain UDP socket implementation
pub struct UnixUdpSocket {
    socket: UnixDatagram,
    connected: bool,
}

#[cfg(not(unix))]
/// Stub implementation for non-Unix platforms
pub struct UnixUdpSocket;

#[cfg(not(unix))]
impl UnixUdpSocket {
    /// Create a new Unix UDP socket (not supported on this platform)
    pub fn new() -> Result<Self, UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Bind the socket to a path (not supported on this platform)
    pub fn bind<P: AsRef<std::path::Path>>(_path: P) -> Result<Self, UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Connect to a peer address (not supported on this platform)
    pub fn connect<P: AsRef<std::path::Path>>(&mut self, _path: P) -> Result<(), UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Send data to the connected peer (not supported on this platform)
    pub async fn send(&self, _buf: &[u8]) -> Result<usize, UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Send data to a specific address (not supported on this platform)
    pub async fn send_to<P: AsRef<std::path::Path>>(&self, _buf: &[u8], _path: P) -> Result<usize, UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Receive data from the socket (not supported on this platform)
    pub async fn recv(&self, _buf: &mut [u8]) -> Result<usize, UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Receive data and get sender address (not supported on this platform)
    pub async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Get the local address of the socket (not supported on this platform)
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Get the peer address of the socket (not supported on this platform)
    pub fn peer_addr(&self) -> Result<std::net::SocketAddr, UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }

    /// Set the socket to non-blocking mode (not supported on this platform)
    pub fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), UnixUdpError> {
        Err(UnixUdpError::NotSupported)
    }
}

#[cfg(unix)]
impl UnixUdpSocket {
    /// Create a new Unix UDP socket
    pub fn new() -> Result<Self, UnixUdpError> {
        let socket = UnixDatagram::unbound()?;
        Ok(Self {
            socket,
            connected: false,
        })
    }

    /// Bind the socket to a path
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<Self, UnixUdpError> {
        let socket = UnixDatagram::bind(path)?;
        Ok(Self {
            socket,
            connected: false,
        })
    }

    /// Connect to a peer address
    pub fn connect<P: AsRef<Path>>(&mut self, path: P) -> Result<(), UnixUdpError> {
        if self.connected {
            return Err(UnixUdpError::AlreadyConnected);
        }
        self.socket.connect(path)?;
        self.connected = true;
        Ok(())
    }

    /// Send data to the connected peer
    pub async fn send(&self, buf: &[u8]) -> Result<usize, UnixUdpError> {
        if !self.connected {
            return Err(UnixUdpError::NotConnected);
        }

        poll_fn(|cx| self.poll_send(buf, cx)).await
    }

    /// Send data to a specific address
    pub async fn send_to<P: AsRef<Path>>(&self, buf: &[u8], path: P) -> Result<usize, UnixUdpError> {
        poll_fn(|cx| self.poll_send_to(buf, path.as_ref(), cx)).await
    }

    /// Receive data from the socket
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, UnixUdpError> {
        poll_fn(|cx| self.poll_recv(buf, cx)).await
    }

    /// Receive data and get sender address
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), UnixUdpError> {
        poll_fn(|cx| self.poll_recv_from(buf, cx)).await
    }

    /// Get the local address of the socket
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, UnixUdpError> {
        Ok(self.socket.local_addr()?)
    }

    /// Get the peer address of the socket (if connected)
    pub fn peer_addr(&self) -> Result<std::net::SocketAddr, UnixUdpError> {
        if !self.connected {
            return Err(UnixUdpError::NotConnected);
        }
        Ok(self.socket.peer_addr()?)
    }

    /// Set the socket to non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), UnixUdpError> {
        self.socket.set_nonblocking(nonblocking)?;
        Ok(())
    }

    /// Poll-based send operation
    fn poll_send(&self, buf: &[u8], _cx: &mut Context<'_>) -> Poll<Result<usize, UnixUdpError>> {
        match self.socket.send(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // In a real implementation, we'd register with the reactor here
                // For now, just return pending
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    /// Poll-based send_to operation
    fn poll_send_to(&self, buf: &[u8], path: &Path, _cx: &mut Context<'_>) -> Poll<Result<usize, UnixUdpError>> {
        match self.socket.send_to(buf, path) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    /// Poll-based receive operation
    fn poll_recv(&self, buf: &mut [u8], _cx: &mut Context<'_>) -> Poll<Result<usize, UnixUdpError>> {
        match self.socket.recv(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    /// Poll-based receive_from operation
    fn poll_recv_from(&self, buf: &mut [u8], _cx: &mut Context<'_>) -> Poll<Result<(usize, std::net::SocketAddr), UnixUdpError>> {
        match self.socket.recv_from(buf) {
            Ok(result) => Poll::Ready(Ok(result)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }
}

#[cfg(unix)]
impl AsyncRead for UnixUdpSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.socket.recv(buf.initialize_unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(unix)]
impl AsyncWrite for UnixUdpSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        match this.socket.send(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_unix_udp_socket_creation() {
        let socket = UnixUdpSocket::new();
        assert!(socket.is_ok());
    }

    #[tokio::test]
    async fn test_unix_udp_socket_bind() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test_socket");

        let socket = UnixUdpSocket::bind(&socket_path);
        assert!(socket.is_ok());
    }

    #[tokio::test]
    async fn test_unix_udp_socket_connect() {
        let temp_dir = tempdir().unwrap();
        let server_path = temp_dir.path().join("server_socket");
        let client_path = temp_dir.path().join("client_socket");

        // Create server socket
        let _server = UnixUdpSocket::bind(&server_path).unwrap();

        // Create and bind client socket
        let mut client = UnixUdpSocket::bind(&client_path).unwrap();

        // Connect to server
        let result = client.connect(&server_path);
        assert!(result.is_ok());
        assert!(client.connected);
    }
}

#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;

    #[test]
    fn test_unix_udp_socket_not_supported() {
        let socket = UnixUdpSocket::new();
        assert!(socket.is_err());
    }
}
