//! Virtual device abstraction for TUN interface
//!
//! Provides a unified interface for reading/writing packets to TUN devices.

use crate::solidtcp::error::{Result, SolidTcpError};
use bytes::BytesMut;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Device configuration
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    /// MTU (Maximum Transmission Unit)
    pub mtu: usize,
    /// Read buffer size
    pub read_buffer_size: usize,
    /// Write queue size
    pub write_queue_size: usize,
    /// Device name (for logging)
    pub name: String,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            read_buffer_size: 65535,
            write_queue_size: 4096,
            name: "tun0".to_string(),
        }
    }
}

/// Virtual device statistics
#[derive(Debug, Default)]
pub struct DeviceStats {
    pub packets_read: AtomicU64,
    pub packets_written: AtomicU64,
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub read_errors: AtomicU64,
    pub write_errors: AtomicU64,
}

impl DeviceStats {
    pub fn record_read(&self, bytes: usize) {
        self.packets_read.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_write(&self, bytes: usize) {
        self.packets_written.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_read_error(&self) {
        self.read_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_write_error(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DeviceStatsSnapshot {
        DeviceStatsSnapshot {
            packets_read: self.packets_read.load(Ordering::Relaxed),
            packets_written: self.packets_written.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            read_errors: self.read_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of device statistics
#[derive(Debug, Clone)]
pub struct DeviceStatsSnapshot {
    pub packets_read: u64,
    pub packets_written: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_errors: u64,
    pub write_errors: u64,
}

/// Trait for virtual network devices
pub trait VirtualDeviceTrait: Send + Sync {
    /// Read a packet from the device
    fn read_packet(&self, buf: &mut [u8]) -> Result<usize>;
    
    /// Write a packet to the device
    fn write_packet(&self, data: &[u8]) -> Result<usize>;
    
    /// Get device MTU
    fn mtu(&self) -> usize;
    
    /// Get device name
    fn name(&self) -> &str;
    
    /// Check if device is ready
    fn is_ready(&self) -> bool;
}

/// Virtual device wrapper for file descriptor based TUN
pub struct VirtualDevice {
    /// Configuration
    config: DeviceConfig,
    /// Statistics
    stats: Arc<DeviceStats>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Write channel sender
    write_tx: mpsc::Sender<BytesMut>,
    /// Write channel receiver (for internal use)
    write_rx: Option<mpsc::Receiver<BytesMut>>,
}

impl VirtualDevice {
    /// Create a new virtual device
    pub fn new(config: DeviceConfig) -> Self {
        let (write_tx, write_rx) = mpsc::channel(config.write_queue_size);
        
        Self {
            config,
            stats: Arc::new(DeviceStats::default()),
            running: Arc::new(AtomicBool::new(true)),
            write_tx,
            write_rx: Some(write_rx),
        }
    }

    /// Get write channel sender (for sending packets to TUN)
    pub fn write_sender(&self) -> mpsc::Sender<BytesMut> {
        self.write_tx.clone()
    }

    /// Take write channel receiver (for the write loop)
    pub fn take_write_receiver(&mut self) -> Option<mpsc::Receiver<BytesMut>> {
        self.write_rx.take()
    }

    /// Get statistics
    pub fn stats(&self) -> &Arc<DeviceStats> {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// Check if device is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the device
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Queue a packet for writing
    pub async fn queue_write(&self, packet: BytesMut) -> Result<()> {
        self.write_tx
            .send(packet)
            .await
            .map_err(|_| SolidTcpError::ChannelClosed)
    }

    /// Try to queue a packet for writing (non-blocking)
    pub fn try_queue_write(&self, packet: BytesMut) -> Result<()> {
        self.write_tx
            .try_send(packet)
            .map_err(|_| SolidTcpError::ChannelClosed)
    }
}

/// Android-specific TUN device using file descriptor
#[cfg(target_os = "android")]
pub mod android {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::io::{FromRawFd, RawFd};

    /// Android TUN device
    pub struct AndroidTunDevice {
        fd: RawFd,
        config: DeviceConfig,
        stats: Arc<DeviceStats>,
        running: Arc<AtomicBool>,
    }

    impl AndroidTunDevice {
        /// Create from raw file descriptor
        pub unsafe fn from_raw_fd(fd: RawFd, config: DeviceConfig) -> Self {
            Self {
                fd,
                config,
                stats: Arc::new(DeviceStats::default()),
                running: Arc::new(AtomicBool::new(true)),
            }
        }

        /// Get raw file descriptor
        pub fn fd(&self) -> RawFd {
            self.fd
        }

        /// Get statistics
        pub fn stats(&self) -> &Arc<DeviceStats> {
            &self.stats
        }

        /// Stop the device
        pub fn stop(&self) {
            self.running.store(false, Ordering::Relaxed);
        }

        /// Check if running
        pub fn is_running(&self) -> bool {
            self.running.load(Ordering::Relaxed)
        }
    }

    impl VirtualDeviceTrait for AndroidTunDevice {
        fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
            // Note: This is a simplified implementation
            // In practice, you'd use AsyncFd for non-blocking I/O
            let mut file = unsafe { std::fs::File::from_raw_fd(self.fd) };
            let result = file.read(buf);
            std::mem::forget(file); // Don't close the fd
            
            match result {
                Ok(n) => {
                    self.stats.record_read(n);
                    Ok(n)
                }
                Err(e) => {
                    self.stats.record_read_error();
                    Err(SolidTcpError::Io(e))
                }
            }
        }

        fn write_packet(&self, data: &[u8]) -> Result<usize> {
            let mut file = unsafe { std::fs::File::from_raw_fd(self.fd) };
            let result = file.write(data);
            std::mem::forget(file);
            
            match result {
                Ok(n) => {
                    self.stats.record_write(n);
                    Ok(n)
                }
                Err(e) => {
                    self.stats.record_write_error();
                    Err(SolidTcpError::Io(e))
                }
            }
        }

        fn mtu(&self) -> usize {
            self.config.mtu
        }

        fn name(&self) -> &str {
            &self.config.name
        }

        fn is_ready(&self) -> bool {
            self.running.load(Ordering::Relaxed)
        }
    }
}

/// Mock device for testing
#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::VecDeque;
    use parking_lot::Mutex;

    pub struct MockDevice {
        config: DeviceConfig,
        stats: Arc<DeviceStats>,
        read_queue: Mutex<VecDeque<Vec<u8>>>,
        write_queue: Mutex<VecDeque<Vec<u8>>>,
    }

    impl MockDevice {
        pub fn new(config: DeviceConfig) -> Self {
            Self {
                config,
                stats: Arc::new(DeviceStats::default()),
                read_queue: Mutex::new(VecDeque::new()),
                write_queue: Mutex::new(VecDeque::new()),
            }
        }

        pub fn inject_packet(&self, data: Vec<u8>) {
            self.read_queue.lock().push_back(data);
        }

        pub fn get_written_packets(&self) -> Vec<Vec<u8>> {
            self.write_queue.lock().drain(..).collect()
        }
    }

    impl VirtualDeviceTrait for MockDevice {
        fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
            if let Some(packet) = self.read_queue.lock().pop_front() {
                let len = packet.len().min(buf.len());
                buf[..len].copy_from_slice(&packet[..len]);
                self.stats.record_read(len);
                Ok(len)
            } else {
                Err(SolidTcpError::DeviceNotReady)
            }
        }

        fn write_packet(&self, data: &[u8]) -> Result<usize> {
            self.write_queue.lock().push_back(data.to_vec());
            self.stats.record_write(data.len());
            Ok(data.len())
        }

        fn mtu(&self) -> usize {
            self.config.mtu
        }

        fn name(&self) -> &str {
            &self.config.name
        }

        fn is_ready(&self) -> bool {
            true
        }
    }
}
