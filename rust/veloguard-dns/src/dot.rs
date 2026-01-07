//! DNS over TLS (DoT) client implementation
//!
//! RFC 7858 compliant implementation for secure DNS queries.

use crate::error::{DnsError, Result};
use crate::RecordType;
use bytes::{BufMut, BytesMut};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData};
use hickory_proto::serialize::binary::BinDecodable;
use rustls::pki_types::ServerName;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::{debug, trace, warn};

/// DoT client configuration
#[derive(Debug, Clone)]
pub struct DotClientConfig {
    /// Server address (IP or hostname)
    pub server: String,
    /// Server port (default: 853)
    pub port: u16,
    /// TLS server name (SNI)
    pub tls_name: Option<String>,
    /// Connection timeout
    pub timeout: Duration,
    /// Enable session resumption
    pub session_resumption: bool,
}

impl Default for DotClientConfig {
    fn default() -> Self {
        Self {
            server: "dns.google".to_string(),
            port: 853,
            tls_name: None,
            timeout: Duration::from_secs(5),
            session_resumption: true,
        }
    }
}

/// DoT client for DNS resolution
pub struct DotClient {
    /// Server address
    server: String,
    /// Server port
    port: u16,
    /// TLS server name
    tls_name: String,
    /// TLS connector
    tls_connector: TlsConnector,
    /// Connection timeout
    timeout: Duration,
}

impl DotClient {
    /// Create a new DoT client
    pub fn new(server: &str, port: u16, tls_name: Option<&str>) -> Result<Self> {
        let tls_connector = Self::create_tls_connector()?;

        Ok(Self {
            server: server.to_string(),
            port,
            tls_name: tls_name.unwrap_or(server).to_string(),
            tls_connector,
            timeout: Duration::from_secs(5),
        })
    }

    /// Create with configuration
    pub fn with_config(config: DotClientConfig) -> Result<Self> {
        let tls_connector = Self::create_tls_connector()?;

        Ok(Self {
            server: config.server.clone(),
            port: config.port,
            tls_name: config.tls_name.unwrap_or(config.server),
            tls_connector,
            timeout: config.timeout,
        })
    }

    /// Create TLS connector with system root certificates
    fn create_tls_connector() -> Result<TlsConnector> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// Resolve a domain name to IP addresses
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // Try A records first
        let mut ips = self.query(domain, RecordType::A).await.unwrap_or_default();
        
        // Also try AAAA records
        if let Ok(ipv6) = self.query(domain, RecordType::AAAA).await {
            ips.extend(ipv6);
        }

        if ips.is_empty() {
            return Err(DnsError::QueryFailed(format!(
                "No addresses found for {}",
                domain
            )));
        }

        Ok(ips)
    }

    /// Query DNS records
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let query_bytes = self.build_query(domain, record_type.into())?;
        let response_bytes = self.send_query(&query_bytes).await?;
        self.parse_response(&response_bytes)
    }

    /// Build DNS query message
    fn build_query(&self, domain: &str, record_type: hickory_proto::rr::RecordType) -> Result<Vec<u8>> {
        let name = Name::from_str(domain)
            .map_err(|e| DnsError::NameError(format!("Invalid domain name: {}", e)))?;

        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let query = Query::query(name, record_type);
        message.add_query(query);

        message
            .to_vec()
            .map_err(|e| DnsError::Protocol(format!("Failed to serialize query: {}", e)))
    }

    /// Send DNS query via DoT
    async fn send_query(&self, query: &[u8]) -> Result<Vec<u8>> {
        // Connect to the DoT server
        let addr = format!("{}:{}", self.server, self.port);
        
        let tcp_stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(DnsError::Io)?;

        // Parse server name for TLS
        let server_name = ServerName::try_from(self.tls_name.clone())
            .map_err(|e| DnsError::Tls(format!("Invalid server name: {}", e)))?;

        // Perform TLS handshake
        let mut tls_stream = tokio::time::timeout(
            self.timeout,
            self.tls_connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::Tls(format!("TLS handshake failed: {}", e)))?;

        // DNS over TLS uses a 2-byte length prefix (RFC 7858)
        let mut request = BytesMut::with_capacity(2 + query.len());
        request.put_u16(query.len() as u16);
        request.put_slice(query);

        // Send the query
        tls_stream
            .write_all(&request)
            .await
            .map_err(DnsError::Io)?;

        // Read the response length
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, tls_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(DnsError::Io)?;

        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Sanity check response length
        if response_len > 65535 {
            return Err(DnsError::Protocol("Response too large".to_string()));
        }

        // Read the response
        let mut response = vec![0u8; response_len];
        tokio::time::timeout(self.timeout, tls_stream.read_exact(&mut response))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(DnsError::Io)?;

        trace!("DoT received {} bytes response", response.len());
        Ok(response)
    }

    /// Parse DNS response
    fn parse_response(&self, response: &[u8]) -> Result<Vec<IpAddr>> {
        let message = Message::from_bytes(response)
            .map_err(|e| DnsError::Protocol(format!("Failed to parse DNS response: {}", e)))?;

        let mut ips = Vec::new();

        for answer in message.answers() {
            match answer.data() {
                RData::A(a) => ips.push(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => ips.push(IpAddr::V6(aaaa.0)),
                _ => {}
            }
        }

        Ok(ips)
    }

    /// Get server address
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Get server port
    pub fn port(&self) -> u16 {
        self.port
    }
}


/// DoT resolver with multiple upstream servers and load balancing
pub struct DotResolver {
    /// DoT clients
    clients: Vec<DotClient>,
    /// Current client index (round-robin)
    current: Arc<RwLock<usize>>,
    /// Prefer IPv4 over IPv6
    prefer_ipv4: bool,
}

impl DotResolver {
    /// Create a new DoT resolver with multiple upstream servers
    /// 
    /// # Arguments
    /// * `servers` - List of (server, port, tls_name) tuples
    pub fn new(servers: &[(String, u16, Option<String>)]) -> Result<Self> {
        if servers.is_empty() {
            return Err(DnsError::Config("No DoT servers configured".to_string()));
        }

        let mut clients = Vec::new();
        for (server, port, tls_name) in servers {
            match DotClient::new(server, *port, tls_name.as_deref()) {
                Ok(client) => {
                    debug!("DoT client created for {}:{}", server, port);
                    clients.push(client);
                }
                Err(e) => {
                    warn!("Failed to create DoT client for {}:{}: {}", server, port, e);
                }
            }
        }

        if clients.is_empty() {
            return Err(DnsError::Config("No valid DoT servers configured".to_string()));
        }

        Ok(Self {
            clients,
            current: Arc::new(RwLock::new(0)),
            prefer_ipv4: true,
        })
    }

    /// Create from URL strings (e.g., "tls://dns.google:853")
    pub fn from_urls(urls: &[String]) -> Result<Self> {
        let mut servers = Vec::new();

        for url in urls {
            if let Some(rest) = url.strip_prefix("tls://") {
                let (host, port) = if let Some((h, p)) = rest.rsplit_once(':') {
                    (h.to_string(), p.parse().unwrap_or(853))
                } else {
                    (rest.to_string(), 853)
                };
                servers.push((host.clone(), port, Some(host)));
            }
        }

        Self::new(&servers)
    }

    /// Create with custom configurations
    pub fn with_configs(configs: Vec<DotClientConfig>) -> Result<Self> {
        if configs.is_empty() {
            return Err(DnsError::Config("No DoT servers configured".to_string()));
        }

        let mut clients = Vec::new();
        for config in configs {
            match DotClient::with_config(config.clone()) {
                Ok(client) => {
                    debug!("DoT client created for {}:{}", config.server, config.port);
                    clients.push(client);
                }
                Err(e) => {
                    warn!("Failed to create DoT client for {}:{}: {}", config.server, config.port, e);
                }
            }
        }

        if clients.is_empty() {
            return Err(DnsError::Config("No valid DoT servers configured".to_string()));
        }

        Ok(Self {
            clients,
            current: Arc::new(RwLock::new(0)),
            prefer_ipv4: true,
        })
    }

    /// Set IPv4 preference
    pub fn set_prefer_ipv4(&mut self, prefer: bool) {
        self.prefer_ipv4 = prefer;
    }

    /// Resolve a domain name using round-robin load balancing
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let mut last_error = None;

        // Try each client in round-robin fashion
        for _ in 0..self.clients.len() {
            let idx = {
                let mut current = self.current.write().await;
                let idx = *current;
                *current = (*current + 1) % self.clients.len();
                idx
            };

            let client = &self.clients[idx];

            match client.resolve(domain).await {
                Ok(mut ips) if !ips.is_empty() => {
                    // Sort by preference
                    if self.prefer_ipv4 {
                        ips.sort_by_key(|ip| match ip {
                            IpAddr::V4(_) => 0,
                            IpAddr::V6(_) => 1,
                        });
                    }
                    debug!(
                        "DoT resolved {} to {:?} via {}:{}",
                        domain, ips, client.server(), client.port()
                    );
                    return Ok(ips);
                }
                Ok(_) => {
                    debug!(
                        "DoT returned empty result for {} via {}:{}",
                        domain, client.server(), client.port()
                    );
                }
                Err(e) => {
                    debug!(
                        "DoT resolution failed for {} via {}:{}: {}",
                        domain, client.server(), client.port(), e
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::QueryFailed(format!("All DoT servers failed for {}", domain))
        }))
    }

    /// Query specific record type
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let mut last_error = None;

        for _ in 0..self.clients.len() {
            let idx = {
                let mut current = self.current.write().await;
                let idx = *current;
                *current = (*current + 1) % self.clients.len();
                idx
            };

            let client = &self.clients[idx];

            match client.query(domain, record_type).await {
                Ok(ips) if !ips.is_empty() => {
                    return Ok(ips);
                }
                Ok(_) => continue,
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::QueryFailed(format!("All DoT servers failed for {} {:?}", domain, record_type))
        }))
    }

    /// Get number of configured servers
    pub fn server_count(&self) -> usize {
        self.clients.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_client_creation() {
        let client = DotClient::new("dns.google", 853, Some("dns.google"));
        assert!(client.is_ok());
    }

    #[test]
    fn test_dot_resolver_from_urls() {
        let urls = vec![
            "tls://dns.google:853".to_string(),
            "tls://1.1.1.1:853".to_string(),
        ];
        let resolver = DotResolver::from_urls(&urls);
        assert!(resolver.is_ok());
        assert_eq!(resolver.unwrap().server_count(), 2);
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_dot_resolve() {
        let client = DotClient::new("dns.google", 853, Some("dns.google")).unwrap();
        let result = client.resolve("google.com").await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }
}
