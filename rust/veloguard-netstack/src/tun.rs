use crate::error::{NetStackError, Result};
use bytes::BytesMut;
use std::net::Ipv4Addr;
#[cfg(target_os = "android")]
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Global Android VPN file descriptor
/// Set by the Android layer when VPN service starts
#[cfg(target_os = "android")]
pub static ANDROID_VPN_FD: AtomicI32 = AtomicI32::new(-1);

/// Global Android VPN proxy mode
/// 0 = rule, 1 = global, 2 = direct
#[cfg(target_os = "android")]
pub static ANDROID_PROXY_MODE: AtomicI32 = AtomicI32::new(0);

/// Set the Android VPN file descriptor from the Java/Kotlin layer
#[cfg(target_os = "android")]
pub fn set_android_vpn_fd(fd: i32) {
    info!("Setting Android VPN fd to {}", fd);
    ANDROID_VPN_FD.store(fd, Ordering::SeqCst);
}

/// Get the current Android VPN file descriptor
#[cfg(target_os = "android")]
pub fn get_android_vpn_fd() -> i32 {
    ANDROID_VPN_FD.load(Ordering::SeqCst)
}

/// Clear the Android VPN file descriptor (called when VPN stops)
#[cfg(target_os = "android")]
pub fn clear_android_vpn_fd() {
    info!("Clearing Android VPN fd");
    ANDROID_VPN_FD.store(-1, Ordering::SeqCst);
}

/// Set the Android proxy mode
/// mode: 0 = rule, 1 = global, 2 = direct
#[cfg(target_os = "android")]
pub fn set_android_proxy_mode(mode: i32) {
    info!("Setting Android proxy mode to {}", mode);
    ANDROID_PROXY_MODE.store(mode, Ordering::SeqCst);
}

/// Get the current Android proxy mode
#[cfg(target_os = "android")]
pub fn get_android_proxy_mode() -> i32 {
    ANDROID_PROXY_MODE.load(Ordering::SeqCst)
}

/// TUN device configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "VeloGuard".to_string(),
            address: Ipv4Addr::new(198, 18, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 0, 0),
            mtu: 1500,
            gateway: None,
            dns: vec![Ipv4Addr::new(198, 18, 0, 2)],
        }
    }
}

/// TUN device wrapper
pub struct TunDevice {
    config: TunConfig,
    tx: Option<mpsc::Sender<BytesMut>>,
    rx: Option<mpsc::Receiver<BytesMut>>,
    running: Arc<AtomicBool>,
    shutdown: Option<CancellationToken>,
    #[cfg(windows)]
    windows_session: Option<Arc<wintun_bindings::Session>>,
}

impl TunDevice {
    pub async fn new(name: &str, addr: &str, netmask: &str) -> Result<Self> {
        let address: Ipv4Addr = addr
            .parse()
            .map_err(|e| NetStackError::Parse(format!("Invalid address: {}", e)))?;
        let netmask: Ipv4Addr = netmask
            .parse()
            .map_err(|e| NetStackError::Parse(format!("Invalid netmask: {}", e)))?;

        Ok(Self {
            config: TunConfig {
                name: name.to_string(),
                address,
                netmask,
                ..Default::default()
            },
            tx: None,
            rx: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown: None,
            #[cfg(windows)]
            windows_session: None,
        })
    }

    pub async fn with_config(config: TunConfig) -> Result<Self> {
        Ok(Self {
            config,
            tx: None,
            rx: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown: None,
            #[cfg(windows)]
            windows_session: None,
        })
    }

    pub fn config(&self) -> &TunConfig {
        &self.config
    }
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        info!("Starting TUN device: {}", self.config.name);
        self.running.store(true, Ordering::Release);

        #[cfg(windows)]
        if let Err(error) = self.start_windows().await {
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        #[cfg(all(unix, not(target_os = "android")))]
        if let Err(error) = self.start_unix().await {
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        #[cfg(target_os = "android")]
        if let Err(error) = self.start_android().await {
            self.running.store(false, Ordering::Release);
            return Err(error);
        }

        info!("TUN device {} started successfully", self.config.name);
        Ok(())
    }

    #[cfg(windows)]
    async fn start_windows(&mut self) -> Result<()> {
        use crate::wintun_embed;
        use wintun_bindings::{Adapter, MAX_RING_CAPACITY};

        // Ensure wintun.dll is available and load it
        let dll_path = match wintun_embed::ensure_wintun_available() {
            Ok(path) => path,
            Err(_) => wintun_embed::download_wintun_dll().await?,
        };

        info!("Loading wintun.dll from {:?}", dll_path);

        let wintun = unsafe {
            wintun_bindings::load_from_path(&dll_path)
                .map_err(|e| NetStackError::TunError(format!("Failed to load wintun.dll: {}", e)))?
        };

        // Try to open existing adapter or create new one
        let adapter = match Adapter::open(&wintun, &self.config.name) {
            Ok(adapter) => {
                info!("Opened existing adapter: {}", self.config.name);
                adapter
            }
            Err(_) => {
                info!("Creating new adapter: {}", self.config.name);
                Adapter::create(&wintun, &self.config.name, "VeloGuard", None).map_err(|e| {
                    NetStackError::TunError(format!("Failed to create adapter: {}", e))
                })?
            }
        };

        // Configure IP address
        let prefix_len = netmask_to_prefix(self.config.netmask);
        self.configure_windows_adapter(prefix_len)?;

        // Start session - returns Arc<Session>
        let session = adapter
            .start_session(MAX_RING_CAPACITY)
            .map_err(|e| NetStackError::TunError(format!("Failed to start session: {}", e)))?;

        info!(
            "Wintun session started with ring capacity: {} bytes",
            MAX_RING_CAPACITY
        );

        // Create channels
        let (tx_to_tun, mut rx_from_stack) = mpsc::channel::<BytesMut>(4096);
        let (tx_to_stack, rx_from_tun) = mpsc::channel::<BytesMut>(4096);
        let shutdown = CancellationToken::new();

        self.tx = Some(tx_to_tun);
        self.rx = Some(rx_from_tun);
        self.shutdown = Some(shutdown.clone());
        self.windows_session = Some(session.clone());

        let running = self.running.clone();
        let session_read = session.clone();
        let session_write = session.clone();

        // Read task using blocking operations in spawn_blocking
        let running_read = running.clone();
        tokio::spawn(async move {
            info!("TUN read task started");

            loop {
                if !running_read.load(Ordering::Relaxed) {
                    break;
                }

                let session_clone = session_read.clone();
                let result =
                    tokio::task::spawn_blocking(move || session_clone.receive_blocking()).await;

                match result {
                    Ok(Ok(packet)) => {
                        let data = BytesMut::from(packet.bytes());
                        if tx_to_stack.send(data).await.is_err() {
                            debug!("Stack receiver dropped");
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        let err_str = e.to_string();
                        if err_str.contains("shutdown") || err_str.contains("EOF") {
                            info!("TUN adapter terminating");
                            break;
                        } else {
                            warn!("TUN read error: {}", e);
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    }
                    Err(e) => {
                        error!("spawn_blocking error: {}", e);
                        break;
                    }
                }
            }
            info!("TUN read task stopped");
        });

        // Write task
        let running_write = running.clone();
        tokio::spawn(async move {
            info!("TUN write task started");

            loop {
                tokio::select! {
                    Some(packet) = rx_from_stack.recv() => {
                        let session_clone = session_write.clone();
                        let packet_data = packet.to_vec();
                        let _ = tokio::task::spawn_blocking(move || {
                            match session_clone.allocate_send_packet(packet_data.len() as u16) {
                                Ok(mut send_packet) => {
                                    send_packet.bytes_mut().copy_from_slice(&packet_data);
                                    session_clone.send_packet(send_packet);
                                }
                                Err(e) => {
                                    if !e.to_string().contains("ERROR_BUFFER_OVERFLOW") {
                                        tracing::error!("Failed to allocate send packet: {}", e);
                                    }
                                }
                            }
                        }).await;
                    }
                    _ = shutdown.cancelled() => {
                        debug!("TUN shutdown requested");
                        break;
                    }
                }
            }
            running_write.store(false, Ordering::Relaxed);
            info!("TUN write task stopped");
        });

        Ok(())
    }

    #[cfg(windows)]
    fn configure_windows_adapter(&self, prefix_len: u8) -> Result<()> {
        use std::process::Command;

        let ip_str = self.config.address.to_string();
        info!("Configuring adapter with IP: {}/{}", ip_str, prefix_len);

        // Set IP address using netsh
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &format!("name=\"{}\"", self.config.name),
                "source=static",
                &format!("addr={}", ip_str),
                &format!("mask={}", self.config.netmask),
            ])
            .output();

        // Set MTU
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &format!("\"{}\"", self.config.name),
                &format!("mtu={}", self.config.mtu),
                "store=active",
            ])
            .output();

        // Configure DNS
        for (i, dns) in self.config.dns.iter().enumerate() {
            let _ = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    if i == 0 { "set" } else { "add" },
                    "dns",
                    &format!("name=\"{}\"", self.config.name),
                    &format!("addr={}", dns),
                ])
                .output();
        }

        // Set interface metric to 1 (highest priority) to ensure DNS queries use this interface
        let _ = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Set-NetIPInterface -InterfaceAlias '{}' -InterfaceMetric 1 -ErrorAction SilentlyContinue",
                    self.config.name
                ),
            ])
            .output();

        // Also set IPv4 interface metric via netsh for compatibility
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "interface",
                &format!("\"{}\"", self.config.name),
                "metric=1",
            ])
            .output();

        info!("Adapter configured successfully with high priority DNS");
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "android")))]
    async fn start_unix(&mut self) -> Result<()> {
        use tun_rs::DeviceBuilder;

        let prefix_len = netmask_to_prefix(self.config.netmask);

        let device = DeviceBuilder::new()
            .name(&self.config.name)
            .ipv4(self.config.address, prefix_len, None::<Ipv4Addr>)
            .mtu(self.config.mtu)
            .build_async()
            .map_err(|e| NetStackError::TunError(format!("Failed to create TUN: {}", e)))?;

        info!(
            "TUN device created: {} with address {}/{}",
            self.config.name, self.config.address, prefix_len
        );

        let (tx_to_tun, mut rx_from_stack) = mpsc::channel::<BytesMut>(4096);
        let (tx_to_stack, rx_from_tun) = mpsc::channel::<BytesMut>(4096);
        let shutdown = CancellationToken::new();

        self.tx = Some(tx_to_tun);
        self.rx = Some(rx_from_tun);
        self.shutdown = Some(shutdown.clone());

        let running = self.running.clone();

        tokio::spawn(async move {
            let mut read_buf = vec![0u8; 65535];

            loop {
                tokio::select! {
                    result = device.recv(&mut read_buf) => {
                        match result {
                            Ok(n) => {
                                let packet = BytesMut::from(&read_buf[..n]);
                                if tx_to_stack.send(packet).await.is_err() {
                                    debug!("Stack receiver dropped");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("TUN read error: {}", e);
                                break;
                            }
                        }
                    }
                    Some(packet) = rx_from_stack.recv() => {
                        if let Err(e) = device.send(&packet).await {
                            error!("TUN write error: {}", e);
                            break;
                        }
                    }
                    _ = shutdown.cancelled() => {
                        debug!("TUN shutdown requested");
                        break;
                    }
                }
            }

            running.store(false, Ordering::Relaxed);
            info!("TUN I/O task stopped");
        });

        Ok(())
    }

    /// Android TUN implementation
    /// On Android, TUN device is created by VpnService and we receive the file descriptor
    #[cfg(target_os = "android")]
    async fn start_android(&mut self) -> Result<()> {
        use std::os::unix::io::FromRawFd;

        // Check if we have a VPN file descriptor from the Android layer
        let fd = ANDROID_VPN_FD.load(std::sync::atomic::Ordering::Relaxed);

        if fd < 0 {
            return Err(NetStackError::TunError(
                "Android VPN file descriptor is not set".to_string(),
            ));
        }

        info!("Starting Android TUN with VPN fd={}", fd);

        // Duplicate the file descriptor so we don't take ownership of the original
        // The original fd is owned by VpnService and must remain valid
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(NetStackError::TunError(format!(
                "Failed to duplicate VPN fd: {}",
                std::io::Error::last_os_error()
            )));
        }

        info!("Duplicated VPN fd: {} -> {}", fd, dup_fd);

        // Create async file from the duplicated VPN file descriptor
        // SAFETY: dup_fd is a valid duplicated fd that we own
        let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let async_fd = tokio::io::unix::AsyncFd::new(file)
            .map_err(|e| NetStackError::TunError(format!("Failed to create AsyncFd: {}", e)))?;

        // Create channels for packet communication
        let (tx_to_tun, mut rx_from_stack) = mpsc::channel::<BytesMut>(4096);
        let (tx_to_stack, rx_from_tun) = mpsc::channel::<BytesMut>(4096);
        let shutdown = CancellationToken::new();

        self.tx = Some(tx_to_tun);
        self.rx = Some(rx_from_tun);
        self.shutdown = Some(shutdown.clone());

        let running = self.running.clone();
        let async_fd = Arc::new(async_fd);
        let async_fd_read = async_fd.clone();
        let async_fd_write = async_fd.clone();
        let read_shutdown = shutdown.clone();
        let write_shutdown = shutdown;

        // Read task - read packets from TUN and send to stack
        let running_read = running.clone();
        tokio::spawn(async move {
            info!("Android TUN read task started");
            let mut read_buf = vec![0u8; 65535];

            loop {
                if !running_read.load(Ordering::Relaxed) {
                    break;
                }

                let readiness = tokio::select! {
                    _ = read_shutdown.cancelled() => break,
                    readiness = async_fd_read.readable() => readiness,
                };
                let mut guard = match readiness {
                    Ok(g) => g,
                    Err(e) => {
                        error!("AsyncFd readable error: {}", e);
                        break;
                    }
                };

                // Try to read from the TUN device
                match guard.try_io(|inner| {
                    use std::io::Read;
                    inner.get_ref().read(&mut read_buf)
                }) {
                    Ok(Ok(n)) if n > 0 => {
                        let packet = BytesMut::from(&read_buf[..n]);
                        if tx_to_stack.send(packet).await.is_err() {
                            debug!("Stack receiver dropped");
                            break;
                        }
                    }
                    Ok(Ok(_)) => {
                        // EOF
                        info!("TUN read EOF");
                        break;
                    }
                    Ok(Err(e)) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            error!("TUN read error: {}", e);
                            break;
                        }
                    }
                    Err(_would_block) => {
                        // WouldBlock, continue waiting
                        continue;
                    }
                }
            }

            running_read.store(false, Ordering::Relaxed);
            info!("Android TUN read task stopped");
        });

        // Write task - write packets from stack to TUN
        let running_write = running.clone();
        tokio::spawn(async move {
            info!("Android TUN write task started");

            loop {
                tokio::select! {
                    Some(packet) = rx_from_stack.recv() => {
                        let mut written = 0;
                        while written < packet.len() {
                            let readiness = tokio::select! {
                                _ = write_shutdown.cancelled() => break,
                                readiness = async_fd_write.writable() => readiness,
                            };
                            let mut guard = match readiness {
                                Ok(guard) => guard,
                                Err(error) => {
                                    error!("AsyncFd writable error: {}", error);
                                    break;
                                }
                            };
                            match guard.try_io(|inner| {
                                use std::io::Write;
                                inner.get_ref().write(&packet[written..])
                            }) {
                                Ok(Ok(0)) => break,
                                Ok(Ok(count)) => written += count,
                                Ok(Err(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                                Ok(Err(error)) => {
                                    error!("TUN write error: {}", error);
                                    break;
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    _ = write_shutdown.cancelled() => {
                        debug!("TUN shutdown requested");
                        break;
                    }
                }
            }

            running_write.store(false, Ordering::Relaxed);
            info!("Android TUN write task stopped");
        });

        info!("Android TUN initialized with fd={}", fd);
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running() {
            return Ok(());
        }
        info!("Stopping TUN device: {}", self.config.name);

        if let Some(shutdown) = self.shutdown.take() {
            shutdown.cancel();
        }

        #[cfg(windows)]
        if let Some(session) = self.windows_session.take() {
            let _ = session.shutdown();
        }

        self.tx = None;
        self.rx = None;
        self.running.store(false, Ordering::Release);
        info!("TUN device {} stopped", self.config.name);
        Ok(())
    }

    pub async fn send(&self, packet: BytesMut) -> Result<()> {
        if let Some(tx) = &self.tx {
            tx.send(packet)
                .await
                .map_err(|_| NetStackError::ChannelClosed)?;
            Ok(())
        } else {
            Err(NetStackError::NotRunning)
        }
    }

    pub async fn recv(&mut self) -> Result<BytesMut> {
        if let Some(rx) = &mut self.rx {
            rx.recv().await.ok_or(NetStackError::ChannelClosed)
        } else {
            Err(NetStackError::NotRunning)
        }
    }

    pub fn get_sender(&self) -> Option<mpsc::Sender<BytesMut>> {
        self.tx.clone()
    }
    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<BytesMut>> {
        self.rx.take()
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if self.is_running() {
            warn!("TUN device dropped while still running");
        }

        if let Some(shutdown) = self.shutdown.take() {
            shutdown.cancel();
        }

        #[cfg(windows)]
        if let Some(session) = self.windows_session.take() {
            let _ = session.shutdown();
        }

        self.tx = None;
        self.rx = None;
        self.running.store(false, Ordering::Release);
    }
}

#[allow(dead_code)]
fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    netmask.octets().iter().map(|o| o.count_ones() as u8).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_to_prefix() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.name, "VeloGuard");
        assert_eq!(config.address, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(config.mtu, 1500);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux CAP_NET_ADMIN and /dev/net/tun"]
    async fn linux_tun_lifecycle() {
        use std::path::Path;
        use tokio::time::{sleep, Duration, Instant};

        let name = format!("vgtest{}", std::process::id() % 100_000);
        let mut device = TunDevice::with_config(TunConfig {
            name: name.clone(),
            address: Ipv4Addr::new(198, 18, 255, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 252),
            mtu: 1_400,
            ..TunConfig::default()
        })
        .await
        .expect("TUN configuration should be valid");

        device.start().await.expect("Linux TUN should start");
        assert!(device.is_running());
        assert!(Path::new(&format!("/sys/class/net/{name}")).exists());

        device.stop().await.expect("Linux TUN should stop");
        assert!(!device.is_running());

        let interface_path = format!("/sys/class/net/{name}");
        let deadline = Instant::now() + Duration::from_secs(2);
        while Path::new(&interface_path).exists() && Instant::now() < deadline {
            sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !Path::new(&interface_path).exists(),
            "Linux TUN interface was not released after stop"
        );
    }
}
