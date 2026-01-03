use crate::error::{Error, Result};
use std::io;

// Re-export TLS types from VeloGuard-rustls
pub use veloguard_rustls::{Certificate, PrivateKey};

/// TLS connector using custom implementation
pub struct TlsConnector {
    inner: tokio_veloguard_tls::TlsConnector,
}

impl TlsConnector {
    pub fn new() -> Result<Self> {
        let inner = tokio_veloguard_tls::TlsConnector::new()
            .map_err(|e| Error::Tls { 
                message: format!("Failed to create TLS connector: {}", e),
                source: None,
            })?;
        Ok(Self { inner })
    }

    /// Add a root certificate for trust verification
    pub fn add_root_certificate(&mut self, cert: Certificate) -> Result<()> {
        // Convert Certificate type
        let tls_cert = tokio_veloguard_tls::Certificate(cert.0);
        self.inner.add_root_certificate(tls_cert)
            .map_err(|e| Error::Tls {
                message: format!("Failed to add root certificate: {}", e),
                source: None,
            })?;
        Ok(())
    }

    pub async fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<TlsStream<S>>
    where
        S: io::Read + io::Write + Send + Unpin + 'static,
    {
        let tls_stream = self.inner.connect(domain, stream)
            .map_err(|e| Error::Tls {
                message: format!("TLS connection failed: {}", e),
                source: None,
            })?;
        Ok(TlsStream { inner: tls_stream })
    }
}

impl Default for TlsConnector {
    fn default() -> Self {
        Self::new().expect("Failed to create default TLS connector")
    }
}

pub struct TlsAcceptor {
    inner: tokio_veloguard_tls::TlsAcceptor,
}

impl TlsAcceptor {
    pub fn new() -> Result<Self> {
        let inner = tokio_veloguard_tls::TlsAcceptor::new()
            .map_err(|e| Error::Tls {
                message: format!("Failed to create TLS acceptor: {}", e),
                source: None,
            })?;
        Ok(Self { inner })
    }

    /// Set the server certificate
    pub fn set_certificate(&mut self, cert: Certificate) -> Result<()> {
        let tls_cert = tokio_veloguard_tls::Certificate(cert.0);
        self.inner.set_certificate(tls_cert)
            .map_err(|e| Error::Tls {
                message: format!("Failed to set certificate: {}", e),
                source: None,
            })?;
        Ok(())
    }

    /// Set the private key
    pub fn set_private_key(&mut self, key: PrivateKey) -> Result<()> {
        let tls_key = tokio_veloguard_tls::PrivateKey(key.0);
        self.inner.set_private_key(tls_key)
            .map_err(|e| Error::Tls {
                message: format!("Failed to set private key: {}", e),
                source: None,
            })?;
        Ok(())
    }

    pub async fn accept<S>(
        &self,
        stream: S,
    ) -> Result<ServerTlsStream<S>>
    where
        S: io::Read + io::Write + Send + Unpin + 'static,
    {
        let tls_stream = self.inner.accept(stream)
            .map_err(|e| Error::Tls {
                message: format!("TLS accept failed: {}", e),
                source: None,
            })?;
        Ok(ServerTlsStream { inner: tls_stream })
    }
}

impl Default for TlsAcceptor {
    fn default() -> Self {
        Self::new().expect("Failed to create default TLS acceptor")
    }
}

/// TLS stream wrapper for client connections
pub struct TlsStream<S> {
    inner: tokio_veloguard_tls::TlsStream<S>,
}

impl<S> TlsStream<S>
where
    S: io::Read + io::Write + Send + Unpin,
{
    pub fn new(inner: tokio_veloguard_tls::TlsStream<S>) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }

    /// Check if TLS connection is established
    pub fn is_established(&self) -> bool {
        self.inner.is_established()
    }
}

impl<S> io::Read for TlsStream<S>
where
    S: io::Read + io::Write + Send + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S> io::Write for TlsStream<S>
where
    S: io::Read + io::Write + Send + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// TLS stream wrapper for server connections
pub struct ServerTlsStream<S> {
    inner: tokio_veloguard_tls::ServerTlsStream<S>,
}

impl<S> ServerTlsStream<S>
where
    S: io::Read + io::Write + Send + Unpin,
{
    pub fn new(inner: tokio_veloguard_tls::ServerTlsStream<S>) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }

    /// Check if TLS connection is established
    pub fn is_established(&self) -> bool {
        self.inner.is_established()
    }
}

impl<S> io::Read for ServerTlsStream<S>
where
    S: io::Read + io::Write + Send + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S> io::Write for ServerTlsStream<S>
where
    S: io::Read + io::Write + Send + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Shadow TLS implementation
/// Enhanced TLS with additional obfuscation features
pub mod shadow_tls {
    use super::*;

    pub struct ShadowTlsConnector {
        inner: tokio_veloguard_tls::TlsConnector,
        obfuscation_enabled: bool,
    }

    impl ShadowTlsConnector {
        pub fn new() -> Result<Self> {
            let inner = tokio_veloguard_tls::TlsConnector::new()
                .map_err(|e| Error::Tls {
                    message: format!("Failed to create Shadow TLS connector: {}", e),
                    source: None,
                })?;
            Ok(Self {
                inner,
                obfuscation_enabled: true,
            })
        }

        /// Enable/disable TLS fingerprint obfuscation
        pub fn set_obfuscation(&mut self, enabled: bool) {
            self.obfuscation_enabled = enabled;
        }

        pub fn connect<S>(
            &self,
            domain: &str,
            stream: S,
        ) -> Result<ShadowTlsStream<S>>
        where
            S: io::Read + io::Write + Send + Unpin + 'static,
        {
            let tls_stream = self.inner.connect(domain, stream)
                .map_err(|e| Error::Tls {
                    message: format!("Shadow TLS connection failed: {}", e),
                    source: None,
                })?;
            Ok(ShadowTlsStream {
                inner: tls_stream,
                obfuscation_enabled: self.obfuscation_enabled,
            })
        }
    }

    impl Default for ShadowTlsConnector {
        fn default() -> Self {
            Self::new().expect("Failed to create default Shadow TLS connector")
        }
    }

    pub struct ShadowTlsStream<S> {
        inner: tokio_veloguard_tls::TlsStream<S>,
        #[allow(dead_code)]
        obfuscation_enabled: bool,
    }

    impl<S> ShadowTlsStream<S>
    where
        S: io::Read + io::Write + Send + Unpin,
    {
        pub fn new(inner: tokio_veloguard_tls::TlsStream<S>) -> Self {
            Self {
                inner,
                obfuscation_enabled: true,
            }
        }

        pub fn into_inner(self) -> S {
            self.inner.into_inner()
        }

        pub fn is_established(&self) -> bool {
            self.inner.is_established()
        }
    }

    impl<S> io::Read for ShadowTlsStream<S>
    where
        S: io::Read + io::Write + Send + Unpin,
    {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl<S> io::Write for ShadowTlsStream<S>
    where
        S: io::Read + io::Write + Send + Unpin,
    {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }
}
