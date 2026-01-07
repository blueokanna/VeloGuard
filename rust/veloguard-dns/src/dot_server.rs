//! DNS over TLS (DoT) server implementation
//!
//! RFC 7858 compliant DoT server for secure DNS queries.

use crate::error::{DnsError, Result};
use crate::resolver::DnsResolver;
use crate::RecordType;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};

/// DoT server configuration
#[derive(Debug, Clone)]
pub struct DotServerConfig {
    /// Listen address (default: 127.0.0.1:853)
    pub listen: SocketAddr,
    /// TLS certificate path
    pub cert_path: String,
    /// TLS private key path
    pub key_path: String,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

impl Default for DotServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:853".parse().unwrap(),
            cert_path: String::new(),
            key_path: String::new(),
            timeout_secs: 30,
        }
    }
}

/// DNS over TLS server
pub struct DotServer {
    /// Configuration
    config: DotServerConfig,
    /// DNS resolver
    resolver: Arc<DnsResolver>,
    /// TLS acceptor
    tls_acceptor: TlsAcceptor,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
}

impl DotServer {
    /// Create a new DoT server
    pub fn new(config: DotServerConfig, resolver: Arc<DnsResolver>) -> Result<Self> {
        if config.cert_path.is_empty() || config.key_path.is_empty() {
            return Err(DnsError::Config(
                "DoT server requires TLS certificate and key".to_string(),
            ));
        }

        let tls_acceptor = Self::create_tls_acceptor(&config.cert_path, &config.key_path)?;
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            resolver,
            tls_acceptor,
            shutdown_tx,
        })
    }

    /// Create TLS acceptor from certificate and key files
    fn create_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
        let certs = Self::load_certs(cert_path)?;
        let key = Self::load_private_key(key_path)?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| DnsError::Tls(format!("TLS config error: {}", e)))?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Load certificates from PEM file
    fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
        let file = File::open(path)
            .map_err(|e| DnsError::Config(format!("Failed to open cert file: {}", e)))?;
        let mut reader = BufReader::new(file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(DnsError::Config("No certificates found in file".to_string()));
        }

        Ok(certs)
    }

    /// Load private key from PEM file
    fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
        let file = File::open(path)
            .map_err(|e| DnsError::Config(format!("Failed to open key file: {}", e)))?;
        let mut reader = BufReader::new(file);

        loop {
            match rustls_pemfile::read_one(&mut reader) {
                Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
                    return Ok(PrivateKeyDer::Pkcs1(key));
                }
                Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
                    return Ok(PrivateKeyDer::Pkcs8(key));
                }
                Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
                    return Ok(PrivateKeyDer::Sec1(key));
                }
                Ok(None) => break,
                Ok(Some(_)) => continue,
                Err(e) => {
                    return Err(DnsError::Config(format!("Failed to parse key: {}", e)));
                }
            }
        }

        Err(DnsError::Config("No private key found in file".to_string()))
    }

    /// Start the DoT server
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen).await?;
        info!("DoT server listening on {}", self.config.listen);

        let resolver = self.resolver.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let timeout = std::time::Duration::from_secs(self.config.timeout_secs);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let resolver = resolver.clone();
                            let tls_acceptor = tls_acceptor.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    addr,
                                    resolver,
                                    tls_acceptor,
                                    timeout,
                                ).await {
                                    debug!("DoT connection error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("DoT accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("DoT server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single TLS connection
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        addr: SocketAddr,
        resolver: Arc<DnsResolver>,
        tls_acceptor: TlsAcceptor,
        timeout: std::time::Duration,
    ) -> Result<()> {
        trace!("DoT connection from {}", addr);

        let tls_stream = tokio::time::timeout(timeout, tls_acceptor.accept(stream))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Tls(format!("TLS handshake failed: {}", e)))?;

        let mut tls_stream = tls_stream;

        loop {
            // Read length prefix (2 bytes, big-endian)
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(timeout, tls_stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break, // Connection closed
                Err(_) => break,     // Timeout
            }

            let query_len = u16::from_be_bytes(len_buf) as usize;

            // Sanity check
            if query_len > 65535 || query_len == 0 {
                warn!("DoT invalid query length: {}", query_len);
                break;
            }

            // Read query
            let mut query_buf = vec![0u8; query_len];
            match tokio::time::timeout(timeout, tls_stream.read_exact(&mut query_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!("DoT read error: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("DoT read timeout");
                    break;
                }
            }

            // Process query
            let response = match Self::process_dns_query(&query_buf, &resolver).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("DoT query processing error: {}", e);
                    continue;
                }
            };

            // Serialize response
            let response_bytes = match response.to_bytes() {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!("DoT response serialization error: {}", e);
                    continue;
                }
            };

            // Write response with length prefix
            let len_bytes = (response_bytes.len() as u16).to_be_bytes();
            if let Err(e) = tls_stream.write_all(&len_bytes).await {
                debug!("DoT write error: {}", e);
                break;
            }
            if let Err(e) = tls_stream.write_all(&response_bytes).await {
                debug!("DoT write error: {}", e);
                break;
            }
        }

        Ok(())
    }

    /// Process DNS query and generate response
    async fn process_dns_query(query_bytes: &[u8], resolver: &DnsResolver) -> Result<Message> {
        let request = Message::from_bytes(query_bytes)
            .map_err(|e| DnsError::Protocol(format!("Invalid DNS message: {}", e)))?;

        let mut response = Message::new();
        response.set_id(request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_desired(request.recursion_desired());
        response.set_recursion_available(true);

        for query in request.queries() {
            response.add_query(query.clone());
        }

        for query in request.queries() {
            let name = query.name().to_string();
            let record_type = RecordType::from(query.query_type());

            trace!("DoT query: {} {:?}", name, record_type);

            match resolver.resolve(&name, record_type).await {
                Ok(ips) => {
                    for ip in ips {
                        let rdata = match ip {
                            IpAddr::V4(v4) => RData::A(hickory_proto::rr::rdata::A(v4)),
                            IpAddr::V6(v6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(v6)),
                        };

                        let record = Record::from_rdata(query.name().clone(), 300, rdata);
                        response.add_answer(record);
                    }

                    if response.answers().is_empty() {
                        response.set_response_code(ResponseCode::NXDomain);
                    } else {
                        response.set_response_code(ResponseCode::NoError);
                    }
                }
                Err(e) => {
                    warn!("DoT resolution failed for {}: {}", name, e);
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
        }

        Ok(response)
    }

    /// Stop the DoT server
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_server_config_default() {
        let config = DotServerConfig::default();
        assert_eq!(config.listen.port(), 853);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_dot_server_requires_tls() {
        use crate::config::DnsConfig;

        let dns_config = DnsConfig {
            nameservers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let resolver = Arc::new(DnsResolver::new(dns_config).unwrap());

        let config = DotServerConfig {
            listen: "127.0.0.1:18853".parse().unwrap(),
            cert_path: String::new(),
            key_path: String::new(),
            timeout_secs: 30,
        };

        let server = DotServer::new(config, resolver);
        assert!(server.is_err());
    }
}
