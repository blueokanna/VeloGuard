//! DNS over TLS (DoT) implementation

use crate::dns::error::{DnsError, DnsResult};
use bytes::{BufMut, BytesMut};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use rustls::pki_types::ServerName;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

/// DoT client for DNS resolution
pub struct DotClient {
    server: String,
    port: u16,
    tls_name: String,
    tls_connector: TlsConnector,
}

impl DotClient {
    /// Create a new DoT client
    pub fn new(server: &str, port: u16, tls_name: Option<&str>) -> DnsResult<Self> {
        // Create TLS config with system root certificates
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(config));

        Ok(Self {
            server: server.to_string(),
            port,
            tls_name: tls_name.unwrap_or(server).to_string(),
            tls_connector,
        })
    }

    /// Resolve a domain name using DoT
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

    /// Send DNS query via DoT
    async fn send_query(&self, query: &[u8]) -> DnsResult<Vec<u8>> {
        // Connect to the DoT server
        let addr = format!("{}:{}", self.server, self.port);
        let tcp_stream = TcpStream::connect(&addr).await
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to connect to DoT server: {}", e)))?;

        // Parse server name for TLS
        let server_name = ServerName::try_from(self.tls_name.clone())
            .map_err(|e| DnsError::TlsError(format!("Invalid server name: {}", e)))?;

        // Perform TLS handshake
        let mut tls_stream = self.tls_connector.connect(server_name, tcp_stream).await
            .map_err(|e| DnsError::TlsError(format!("TLS handshake failed: {}", e)))?;

        // DNS over TLS uses a 2-byte length prefix
        let mut request = BytesMut::with_capacity(2 + query.len());
        request.put_u16(query.len() as u16);
        request.put_slice(query);

        // Send the query
        tls_stream.write_all(&request).await
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to send DoT query: {}", e)))?;

        // Read the response length
        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to read DoT response length: {}", e)))?;

        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Read the response
        let mut response = vec![0u8; response_len];
        tls_stream.read_exact(&mut response).await
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to read DoT response: {}", e)))?;

        Ok(response)
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

/// DoT resolver with multiple upstream servers
pub struct DotResolver {
    clients: Vec<DotClient>,
    current: Arc<RwLock<usize>>,
}

impl DotResolver {
    /// Create a new DoT resolver with multiple upstream servers
    pub fn new(servers: &[(String, u16, Option<String>)]) -> DnsResult<Self> {
        let mut clients = Vec::new();
        for (server, port, tls_name) in servers {
            match DotClient::new(server, *port, tls_name.as_deref()) {
                Ok(client) => clients.push(client),
                Err(e) => warn!("Failed to create DoT client for {}:{}: {}", server, port, e),
            }
        }

        if clients.is_empty() {
            return Err(DnsError::ConfigError("No DoT servers configured".to_string()));
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
                            debug!("DoT AAAA resolution failed for {}: {}", domain, e);
                            last_error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    debug!("DoT A resolution failed for {}: {}", domain, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::ResolutionFailed(format!("All DoT servers failed for {}", domain))
        }))
    }
}
