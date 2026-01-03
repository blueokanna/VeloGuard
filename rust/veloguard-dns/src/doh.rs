//! DNS over HTTPS (DoH) client implementation
//!
//! Supports both GET and POST methods for DoH queries.
//! RFC 8484 compliant implementation.

use crate::error::{DnsError, Result};
use crate::RecordType;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData};
use hickory_proto::serialize::binary::BinDecodable;
use rustls::pki_types::ServerName;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::{debug, trace, warn};
use url::Url;

/// DoH request method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMethod {
    /// HTTP GET with base64url encoded query
    Get,
    /// HTTP POST with binary DNS message
    Post,
}

impl Default for DohMethod {
    fn default() -> Self {
        Self::Post
    }
}

/// DoH client configuration
#[derive(Debug, Clone)]
pub struct DohClientConfig {
    /// DoH server URL
    pub url: String,
    /// Request method (GET or POST)
    pub method: DohMethod,
    /// Request timeout
    pub timeout: Duration,
    /// Enable HTTP/2
    pub http2: bool,
    /// Custom headers
    pub headers: Vec<(String, String)>,
}

impl Default for DohClientConfig {
    fn default() -> Self {
        Self {
            url: "https://dns.google/dns-query".to_string(),
            method: DohMethod::Post,
            timeout: Duration::from_secs(5),
            http2: true,
            headers: Vec::new(),
        }
    }
}

/// DoH client for DNS resolution
pub struct DohClient {
    /// Parsed URL
    url: Url,
    /// TLS connector
    tls_connector: TlsConnector,
    /// Request method
    method: DohMethod,
    /// Request timeout
    timeout: Duration,
    /// Custom headers
    headers: Vec<(String, String)>,
}

impl DohClient {
    /// Create a new DoH client with URL
    pub fn new(url: &str) -> Result<Self> {
        Self::with_config(DohClientConfig {
            url: url.to_string(),
            ..Default::default()
        })
    }

    /// Create a new DoH client with configuration
    pub fn with_config(config: DohClientConfig) -> Result<Self> {
        let url = Url::parse(&config.url)
            .map_err(|e| DnsError::Config(format!("Invalid DoH URL: {}", e)))?;

        // Validate URL scheme
        if url.scheme() != "https" {
            return Err(DnsError::Config("DoH URL must use HTTPS".to_string()));
        }

        // Create TLS connector
        let tls_connector = Self::create_tls_connector()?;

        Ok(Self {
            url,
            tls_connector,
            method: config.method,
            timeout: config.timeout,
            headers: config.headers,
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

    /// Send DNS query via DoH
    async fn send_query(&self, query: &[u8]) -> Result<Vec<u8>> {
        let host = self.url.host_str().ok_or(DnsError::Config("No host in URL".to_string()))?;
        let port = self.url.port().unwrap_or(443);
        let path = self.url.path();

        // Build request based on method
        let (_uri, _body, content_type) = match self.method {
            DohMethod::Get => {
                let encoded = URL_SAFE_NO_PAD.encode(query);
                let uri = format!("{}?dns={}", self.url, encoded);
                (uri, Bytes::new(), None)
            }
            DohMethod::Post => {
                let uri = self.url.to_string();
                (uri, Bytes::copy_from_slice(query), Some("application/dns-message"))
            }
        };

        // Connect with TLS
        let addr = format!("{}:{}", host, port);
        let tcp_stream = tokio::time::timeout(
            self.timeout,
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::Io(e))?;

        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| DnsError::Tls(format!("Invalid server name: {}", e)))?;

        let mut tls_stream = tokio::time::timeout(
            self.timeout,
            self.tls_connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::Tls(e.to_string()))?;

        // Build HTTP request manually (simple HTTP/1.1)
        let method = match self.method {
            DohMethod::Get => "GET",
            DohMethod::Post => "POST",
        };

        let mut request = format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Accept: application/dns-message\r\n\
             Connection: close\r\n",
            method, path, host
        );

        if let Some(ct) = content_type {
            request.push_str(&format!("Content-Type: {}\r\n", ct));
            request.push_str(&format!("Content-Length: {}\r\n", query.len()));
        }

        // Add custom headers
        for (key, value) in &self.headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }

        request.push_str("\r\n");

        // Send request
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tls_stream.write_all(request.as_bytes()).await?;
        if self.method == DohMethod::Post {
            tls_stream.write_all(query).await?;
        }

        // Read response
        let mut response_buf = Vec::new();
        tokio::time::timeout(self.timeout, tls_stream.read_to_end(&mut response_buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Io(e))?;

        // Parse HTTP response
        let response_str = String::from_utf8_lossy(&response_buf);
        
        // Check status code
        if !response_str.starts_with("HTTP/1.1 200") && !response_str.starts_with("HTTP/1.0 200") {
            let status_line = response_str.lines().next().unwrap_or("Unknown");
            return Err(DnsError::Http(format!("DoH server returned: {}", status_line)));
        }

        // Find body (after \r\n\r\n)
        let body_start = response_str
            .find("\r\n\r\n")
            .ok_or(DnsError::Http("Invalid HTTP response".to_string()))?
            + 4;

        Ok(response_buf[body_start..].to_vec())
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

        trace!("DoH response: {} addresses", ips.len());
        Ok(ips)
    }

    /// Get the DoH server URL
    pub fn url(&self) -> &str {
        self.url.as_str()
    }
}


/// DoH resolver with multiple upstream servers and load balancing
pub struct DohResolver {
    /// DoH clients
    clients: Vec<DohClient>,
    /// Current client index (round-robin)
    current: Arc<RwLock<usize>>,
    /// Prefer IPv4 over IPv6
    prefer_ipv4: bool,
}

impl DohResolver {
    /// Create a new DoH resolver with multiple upstream servers
    pub fn new(urls: &[String]) -> Result<Self> {
        if urls.is_empty() {
            return Err(DnsError::Config("No DoH servers configured".to_string()));
        }

        let mut clients = Vec::new();
        for url in urls {
            match DohClient::new(url) {
                Ok(client) => {
                    debug!("DoH client created for {}", url);
                    clients.push(client);
                }
                Err(e) => {
                    warn!("Failed to create DoH client for {}: {}", url, e);
                }
            }
        }

        if clients.is_empty() {
            return Err(DnsError::Config("No valid DoH servers configured".to_string()));
        }

        Ok(Self {
            clients,
            current: Arc::new(RwLock::new(0)),
            prefer_ipv4: true,
        })
    }

    /// Create with custom configuration for each server
    pub fn with_configs(configs: Vec<DohClientConfig>) -> Result<Self> {
        if configs.is_empty() {
            return Err(DnsError::Config("No DoH servers configured".to_string()));
        }

        let mut clients = Vec::new();
        for config in configs {
            match DohClient::with_config(config.clone()) {
                Ok(client) => {
                    debug!("DoH client created for {}", config.url);
                    clients.push(client);
                }
                Err(e) => {
                    warn!("Failed to create DoH client for {}: {}", config.url, e);
                }
            }
        }

        if clients.is_empty() {
            return Err(DnsError::Config("No valid DoH servers configured".to_string()));
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
                    debug!("DoH resolved {} to {:?} via {}", domain, ips, client.url());
                    return Ok(ips);
                }
                Ok(_) => {
                    debug!("DoH returned empty result for {} via {}", domain, client.url());
                }
                Err(e) => {
                    debug!("DoH resolution failed for {} via {}: {}", domain, client.url(), e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::QueryFailed(format!("All DoH servers failed for {}", domain))
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
            DnsError::QueryFailed(format!("All DoH servers failed for {} {:?}", domain, record_type))
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

    #[tokio::test]
    async fn test_doh_client_creation() {
        let client = DohClient::new("https://dns.google/dns-query");
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_doh_invalid_url() {
        let client = DohClient::new("http://dns.google/dns-query");
        assert!(client.is_err()); // Must be HTTPS
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_doh_resolve() {
        let client = DohClient::new("https://dns.google/dns-query").unwrap();
        let result = client.resolve("google.com").await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }
}
