//! DNS server implementation (UDP/TCP/DoH/DoT)

use crate::config::DnsConfig;
use crate::error::{DnsError, Result};
use crate::resolver::DnsResolver;
use crate::RecordType;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace, warn};

/// DNS server
pub struct DnsServer {
    /// DNS resolver
    resolver: Arc<DnsResolver>,
    /// Configuration
    config: DnsConfig,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
}

impl DnsServer {
    /// Create a new DNS server
    pub fn new(config: DnsConfig) -> Result<Self> {
        let resolver = Arc::new(DnsResolver::new(config.clone())?);
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            resolver,
            config,
            shutdown_tx,
        })
    }

    /// Start the DNS server
    pub async fn start(&self) -> Result<()> {
        info!("Starting DNS server on {}", self.config.listen);

        // Start UDP server
        let udp_handle = self.start_udp_server().await?;

        // Start TCP server if enabled
        let tcp_handle = if self.config.tcp_enable {
            Some(self.start_tcp_server().await?)
        } else {
            None
        };

        // Wait for shutdown
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("DNS server shutting down");
            }
            _ = udp_handle => {
                warn!("UDP server stopped unexpectedly");
            }
            _ = async {
                if let Some(handle) = tcp_handle {
                    let _ = handle.await;
                } else {
                    std::future::pending::<()>().await
                }
            } => {
                warn!("TCP server stopped unexpectedly");
            }
        }

        Ok(())
    }

    /// Start UDP DNS server
    async fn start_udp_server(&self) -> Result<tokio::task::JoinHandle<()>> {
        let socket = Arc::new(UdpSocket::bind(self.config.listen).await?);
        let resolver = self.resolver.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("UDP DNS server listening on {}", self.config.listen);

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, addr)) => {
                                let data = buf[..len].to_vec();
                                let resolver = resolver.clone();
                                let socket = socket.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = handle_udp_query(&socket, &resolver, &data, addr).await {
                                        debug!("UDP query error from {}: {}", addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("UDP recv error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Start TCP DNS server
    async fn start_tcp_server(&self) -> Result<tokio::task::JoinHandle<()>> {
        let listener = TcpListener::bind(self.config.listen).await?;
        let resolver = self.resolver.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("TCP DNS server listening on {}", self.config.listen);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                let resolver = resolver.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_tcp_connection(stream, &resolver).await {
                                        debug!("TCP connection error from {}: {}", addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("TCP accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Stop the DNS server
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Get resolver reference
    pub fn resolver(&self) -> &Arc<DnsResolver> {
        &self.resolver
    }
}

/// Handle UDP DNS query
async fn handle_udp_query(
    socket: &UdpSocket,
    resolver: &DnsResolver,
    data: &[u8],
    addr: SocketAddr,
) -> Result<()> {
    let request = Message::from_bytes(data).map_err(|e| DnsError::Protocol(e.to_string()))?;

    let response = process_query(resolver, &request).await?;
    let response_data = response.to_bytes().map_err(|e| DnsError::Protocol(e.to_string()))?;

    socket.send_to(&response_data, addr).await?;
    Ok(())
}

/// Handle TCP DNS connection
async fn handle_tcp_connection(mut stream: TcpStream, resolver: &DnsResolver) -> Result<()> {
    loop {
        // Read length prefix
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; // Connection closed
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        // Read query
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        let request = Message::from_bytes(&buf).map_err(|e| DnsError::Protocol(e.to_string()))?;
        let response = process_query(resolver, &request).await?;
        let response_data = response.to_bytes().map_err(|e| DnsError::Protocol(e.to_string()))?;

        // Write response with length prefix
        let len = (response_data.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&response_data).await?;
    }

    Ok(())
}

/// Process DNS query and generate response
async fn process_query(resolver: &DnsResolver, request: &Message) -> Result<Message> {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);

    // Copy queries to response
    for query in request.queries() {
        response.add_query(query.clone());
    }

    // Process each query
    for query in request.queries() {
        let name = query.name().to_string();
        let record_type = RecordType::from(query.query_type());

        trace!("DNS query: {} {:?}", name, record_type);

        match resolver.resolve(&name, record_type).await {
            Ok(ips) => {
                for ip in ips {
                    let rdata = match ip {
                        IpAddr::V4(v4) => RData::A(hickory_proto::rr::rdata::A(v4)),
                        IpAddr::V6(v6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(v6)),
                    };

                    let record = Record::from_rdata(
                        query.name().clone(),
                        300, // TTL
                        rdata,
                    );
                    response.add_answer(record);
                }

                if response.answers().is_empty() {
                    response.set_response_code(ResponseCode::NXDomain);
                } else {
                    response.set_response_code(ResponseCode::NoError);
                }
            }
            Err(e) => {
                warn!("DNS resolution failed for {}: {}", name, e);
                response.set_response_code(ResponseCode::ServFail);
            }
        }
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_server_creation() {
        let config = DnsConfig {
            listen: "127.0.0.1:15353".parse().unwrap(),
            nameservers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };

        let server = DnsServer::new(config);
        assert!(server.is_ok());
    }
}
