//! DNS over HTTPS (DoH) implementation

use crate::dns::error::{DnsError, DnsResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use url::Url;

/// DoH client for DNS resolution
pub struct DohClient {
    url: Url,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    use_post: bool,
}

impl DohClient {
    /// Create a new DoH client
    pub fn new(url: &str) -> DnsResult<Self> {
        let url = Url::parse(url)
            .map_err(|e| DnsError::ConfigError(format!("Invalid DoH URL: {}", e)))?;

        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let client = Client::builder(TokioExecutor::new()).build(connector);

        Ok(Self {
            url,
            client,
            use_post: true,
        })
    }

    /// Create a new DoH client with TLS
    pub fn new_with_tls(url: &str) -> DnsResult<Self> {
        let url = Url::parse(url)
            .map_err(|e| DnsError::ConfigError(format!("Invalid DoH URL: {}", e)))?;

        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let client = Client::builder(TokioExecutor::new()).build(connector);

        Ok(Self {
            url,
            client,
            use_post: true,
        })
    }

    /// Resolve a domain name using DoH
    pub async fn resolve(&self, domain: &str, record_type: RecordType) -> DnsResult<Vec<IpAddr>> {
        let query = self.build_query(domain, record_type)?;
        let response = self.send_query(&query).await?;
        self.parse_response(&response)
    }

    /// Build a DNS query message
    fn build_query(&self, domain: &str, record_type: RecordType) -> DnsResult<Vec<u8>> {
        let name = Name::from_str(domain)
            .map_err(|e| DnsError::ConfigError(format!("Invalid domain name: {}", e)))?;

        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let query = Query::query(name, record_type);
        message.add_query(query);

        let bytes = message.to_vec()
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to serialize query: {}", e)))?;

        Ok(bytes)
    }

    /// Send DNS query via DoH
    async fn send_query(&self, query: &[u8]) -> DnsResult<Vec<u8>> {
        let uri = if self.use_post {
            self.url.to_string()
        } else {
            // GET method with base64url encoded query
            let encoded = URL_SAFE_NO_PAD.encode(query);
            format!("{}?dns={}", self.url, encoded)
        };

        let request = if self.use_post {
            Request::builder()
                .method(Method::POST)
                .uri(&uri)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(Full::new(Bytes::copy_from_slice(query)))
                .map_err(|e| DnsError::ResolutionFailed(format!("Failed to build request: {}", e)))?
        } else {
            Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .header("Accept", "application/dns-message")
                .body(Full::new(Bytes::new()))
                .map_err(|e| DnsError::ResolutionFailed(format!("Failed to build request: {}", e)))?
        };

        let response = self.client.request(request).await
            .map_err(|e| DnsError::ResolutionFailed(format!("DoH request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(DnsError::ResolutionFailed(format!(
                "DoH server returned status: {}",
                response.status()
            )));
        }

        let body = response.into_body().collect().await
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to read response body: {}", e)))?;

        Ok(body.to_bytes().to_vec())
    }

    /// Parse DNS response
    fn parse_response(&self, response: &[u8]) -> DnsResult<Vec<IpAddr>> {
        let message = Message::from_bytes(response)
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to parse DNS response: {}", e)))?;

        let mut ips = Vec::new();

        for answer in message.answers() {
            let data = answer.data();
            match data {
                hickory_proto::rr::RData::A(a) => {
                    ips.push(IpAddr::V4(a.0));
                }
                hickory_proto::rr::RData::AAAA(aaaa) => {
                    ips.push(IpAddr::V6(aaaa.0));
                }
                _ => {}
            }
        }

        Ok(ips)
    }
}

/// DoH resolver with multiple upstream servers
pub struct DohResolver {
    clients: Vec<DohClient>,
    current: Arc<RwLock<usize>>,
}

impl DohResolver {
    /// Create a new DoH resolver with multiple upstream servers
    pub fn new(urls: &[String]) -> DnsResult<Self> {
        let mut clients = Vec::new();
        for url in urls {
            match DohClient::new(url) {
                Ok(client) => clients.push(client),
                Err(e) => warn!("Failed to create DoH client for {}: {}", url, e),
            }
        }

        if clients.is_empty() {
            return Err(DnsError::ConfigError("No valid DoH servers configured".to_string()));
        }

        Ok(Self {
            clients,
            current: Arc::new(RwLock::new(0)),
        })
    }

    /// Resolve a domain name
    pub async fn resolve(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
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

            // Try A records first
            match client.resolve(domain, RecordType::A).await {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => {
                    // Try AAAA records
                    match client.resolve(domain, RecordType::AAAA).await {
                        Ok(ips) if !ips.is_empty() => return Ok(ips),
                        Ok(_) => continue,
                        Err(e) => {
                            debug!("DoH AAAA resolution failed for {}: {}", domain, e);
                            last_error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    debug!("DoH A resolution failed for {}: {}", domain, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::ResolutionFailed(format!("All DoH servers failed for {}", domain))
        }))
    }
}
