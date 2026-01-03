//! TLS stream wrapper

use crate::error::Result;
use crate::connection::Connection;
use std::io::{Read, Write};

/// TLS stream wrapper
#[derive(Debug)]
pub struct TlsStream<R, W> {
    connection: Connection<R, W>,
}

impl<R: Read, W: Write> TlsStream<R, W> {
    /// Create a new TLS stream
    pub fn new(connection: Connection<R, W>) -> Self {
        Self { connection }
    }

    /// Get the inner connection
    pub fn connection(&self) -> &Connection<R, W> {
        &self.connection
    }

    /// Get the inner connection mutably
    pub fn connection_mut(&mut self) -> &mut Connection<R, W> {
        &mut self.connection
    }

    /// Check if connection is established
    pub fn is_established(&self) -> bool {
        self.connection.is_established()
    }

    /// Close the stream
    pub fn close(&mut self) -> Result<()> {
        self.connection.close()
    }
}

impl<R: Read, W: Write> Read for TlsStream<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.connection.read(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl<R: Read, W: Write> Write for TlsStream<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.connection.write(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // TLS records are flushed immediately
        Ok(())
    }
}
