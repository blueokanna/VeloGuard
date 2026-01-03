//! DNS client for upstream queries

use crate::config::{UpstreamConfig, UpstreamProtocol};
use crate::error::{DnsError, Result};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

/// DNS protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProtocol {
    Udp,
    Tcp,
    DoT,
    DoH,
    DoQ,
}

/// DNS client for querying upstream servers
pub struct DnsClient {
    /// Upstream configuration
    config: UpstreamConfig,
    /// Query timeout
    timeout: Duration,
    /// TLS connector for DoT/DoH
    tls_connector: Option<Arc<tokio_rustls::TlsConnector>>,
}

impl DnsClient {
    /// Create a new DNS client
    pub fn new(config: UpstreamConfig, timeout: Duration) -> Result<Self> {
        let tls_connector = if matches!(
            config.protocol,
            UpstreamProtocol::DoT | UpstreamProtocol::DoH
        ) {
            Some(Arc::new(Self::create_tls_connector()?))
        } else {
            None
        };

        Ok(Self {
            config,
            timeout,
            tls_connector,
        })
    }

    /// Create TLS connector
    fn create_tls_connector() -> Result<tokio_rustls::TlsConnector> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
    }

    /// Query DNS
    pub async fn query(&self, name: &str, record_type: RecordType) -> Result<Message> {
        let message = self.build_query(name, record_type)?;

        match self.config.protocol {
            UpstreamProtocol::Udp => self.query_udp(&message).await,
            UpstreamProtocol::Tcp => self.query_tcp(&message).await,
            UpstreamProtocol::DoT => self.query_dot(&message).await,
            UpstreamProtocol::DoH => self.query_doh(&message).await,
            UpstreamProtocol::DoQ => {
                // DoQ not implemented yet
                Err(DnsError::NotImplemented)
            }
        }
    }

    /// Build DNS query message
    fn build_query(&self, name: &str, record_type: RecordType) -> Result<Message> {
        let name = Name::from_ascii(name)
            .map_err(|e| DnsError::NameError(format!("Invalid domain name: {}", e)))?;

        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let query = Query::query(name, record_type);
        message.add_query(query);

        Ok(message)
    }

    /// Query via UDP
    async fn query_udp(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address().await?;
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        let data = message.to_bytes().map_err(|e| DnsError::Protocol(e.to_string()))?;

        socket.send_to(&data, addr).await?;

        let mut buf = vec![0u8; 4096];
        let result = timeout(self.timeout, socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, _))) => {
                let response = Message::from_bytes(&buf[..len])
                    .map_err(|e| DnsError::Protocol(e.to_string()))?;
                Ok(response)
            }
            Ok(Err(e)) => Err(DnsError::Io(e)),
            Err(_) => Err(DnsError::Timeout),
        }
    }

    /// Query via TCP
    async fn query_tcp(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address().await?;
        let mut stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DnsError::Timeout)??;

        let data = message.to_bytes().map_err(|e| DnsError::Protocol(e.to_string()))?;

        // TCP DNS uses 2-byte length prefix
        let len = (data.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&data).await?;

        // Read response length
        let mut len_buf = [0u8; 2];
        timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::Timeout)??;
        let len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut buf = vec![0u8; len];
        timeout(self.timeout, stream.read_exact(&mut buf))
            .await
            .map_err(|_| DnsError::Timeout)??;

        let response = Message::from_bytes(&buf)
            .map_err(|e| DnsError::Protocol(e.to_string()))?;
        Ok(response)
    }

    /// Query via DNS over TLS (DoT)
    async fn query_dot(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address().await?;
        let connector = self.tls_connector.as_ref().ok_or(DnsError::Tls(
            "TLS connector not initialized".to_string(),
        ))?;

        let server_name = self
            .config
            .server_name
            .as_ref()
            .ok_or(DnsError::Config("Server name required for DoT".to_string()))?;

        let server_name = rustls::pki_types::ServerName::try_from(server_name.as_str())
            .map_err(|e| DnsError::Tls(format!("Invalid server name: {}", e)))?
            .to_owned();

        let tcp_stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DnsError::Timeout)??;

        let mut tls_stream = timeout(self.timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Tls(e.to_string()))?;

        let data = message.to_bytes().map_err(|e| DnsError::Protocol(e.to_string()))?;

        // TCP DNS uses 2-byte length prefix
        let len = (data.len() as u16).to_be_bytes();
        tls_stream.write_all(&len).await?;
        tls_stream.write_all(&data).await?;

        // Read response length
        let mut len_buf = [0u8; 2];
        timeout(self.timeout, tls_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::Timeout)??;
        let len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut buf = vec![0u8; len];
        timeout(self.timeout, tls_stream.read_exact(&mut buf))
            .await
            .map_err(|_| DnsError::Timeout)??;

        let response = Message::from_bytes(&buf)
            .map_err(|e| DnsError::Protocol(e.to_string()))?;
        Ok(response)
    }

    /// Query via DNS over HTTPS (DoH)
    async fn query_doh(&self, message: &Message) -> Result<Message> {
        let data = message.to_bytes().map_err(|e| DnsError::Protocol(e.to_string()))?;

        // Build DoH URL
        let host = &self.config.address;
        let path = self.config.path.as_deref().unwrap_or("/dns-query");
        let port = self.config.port.unwrap_or(443);

        // Use base64url encoding for GET request
        let _encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &data,
        );

        let url = format!("https://{}:{}{}", host, port, path);

        // For simplicity, we'll use POST with application/dns-message
        // A full implementation would use hyper client
        debug!("DoH query to {}", url);

        // Create TLS connection
        let connector = self.tls_connector.as_ref().ok_or(DnsError::Tls(
            "TLS connector not initialized".to_string(),
        ))?;

        let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
            .map_err(|e| DnsError::Tls(format!("Invalid server name: {}", e)))?
            .to_owned();

        let addr = self.resolve_address().await?;
        let tcp_stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DnsError::Timeout)??;

        let mut tls_stream = timeout(self.timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Tls(e.to_string()))?;

        // Build HTTP/1.1 POST request
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            path,
            host,
            data.len()
        );

        tls_stream.write_all(request.as_bytes()).await?;
        tls_stream.write_all(&data).await?;

        // Read HTTP response
        let mut response_buf = Vec::new();
        timeout(self.timeout, tls_stream.read_to_end(&mut response_buf))
            .await
            .map_err(|_| DnsError::Timeout)??;

        // Parse HTTP response (simple parsing)
        let response_str = String::from_utf8_lossy(&response_buf);
        let body_start = response_str
            .find("\r\n\r\n")
            .ok_or(DnsError::Http("Invalid HTTP response".to_string()))?
            + 4;

        let body = &response_buf[body_start..];

        let response = Message::from_bytes(body)
            .map_err(|e| DnsError::Protocol(e.to_string()))?;
        Ok(response)
    }

    /// Resolve upstream server address
    async fn resolve_address(&self) -> Result<SocketAddr> {
        // If we have a direct socket address, use it
        if let Some(addr) = self.config.socket_addr() {
            return Ok(addr);
        }

        // Otherwise, we need to resolve the hostname
        // This is a bootstrap problem - we use system DNS for this
        let port = self.config.port.unwrap_or(match self.config.protocol {
            UpstreamProtocol::Udp | UpstreamProtocol::Tcp => 53,
            UpstreamProtocol::DoT | UpstreamProtocol::DoQ => 853,
            UpstreamProtocol::DoH => 443,
        });

        // Use tokio's built-in DNS resolution (system resolver)
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", self.config.address, port))
            .await?
            .collect();

        addrs
            .into_iter()
            .next()
            .ok_or(DnsError::QueryFailed("Failed to resolve upstream DNS server".to_string()))
    }

    /// Get protocol type
    pub fn protocol(&self) -> DnsProtocol {
        match self.config.protocol {
            UpstreamProtocol::Udp => DnsProtocol::Udp,
            UpstreamProtocol::Tcp => DnsProtocol::Tcp,
            UpstreamProtocol::DoT => DnsProtocol::DoT,
            UpstreamProtocol::DoH => DnsProtocol::DoH,
            UpstreamProtocol::DoQ => DnsProtocol::DoQ,
        }
    }

    /// Get server address
    pub fn address(&self) -> &str {
        &self.config.address
    }
}

/// Create DNS clients from configuration strings
pub fn create_clients(servers: &[String], timeout: Duration) -> Vec<DnsClient> {
    servers
        .iter()
        .filter_map(|s| {
            UpstreamConfig::parse(s).and_then(|config| {
                DnsClient::new(config, timeout).ok()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_query() {
        let config = UpstreamConfig::parse("8.8.8.8").unwrap();
        let client = DnsClient::new(config, Duration::from_secs(5)).unwrap();

        let result = client.query("google.com", RecordType::A).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.answers().is_empty());
    }
}
