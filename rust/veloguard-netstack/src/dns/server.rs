//! DNS server implementation

use crate::dns::cache::DnsCache;
use crate::dns::error::{DnsError, DnsResult};
use crate::dns::fake_ip::FakeIpPool;
use crate::dns::resolver::Resolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

/// DNS server configuration
#[derive(Debug, Clone)]
pub struct DnsServerConfig {
    /// Listen address
    pub listen: SocketAddr,
    /// Enable fake IP mode
    pub fake_ip_enabled: bool,
    /// Fake IP range
    pub fake_ip_range: Option<String>,
    /// Fake IP filter (domains that bypass fake IP)
    pub fake_ip_filter: Vec<String>,
    /// Cache size
    pub cache_size: usize,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
}

impl Default for DnsServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5353),
            fake_ip_enabled: false,
            fake_ip_range: None,
            fake_ip_filter: Vec::new(),
            cache_size: 1000,
            cache_ttl: 600,
        }
    }
}

/// DNS server implementation
pub struct DnsServer {
    config: DnsServerConfig,
    resolver: Resolver,
    cache: Arc<DnsCache>,
    fake_ip_pool: Option<Arc<RwLock<FakeIpPool>>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DnsServer {
    /// Create a new DNS server
    pub async fn new(listen_addr: &str, resolver: Resolver) -> DnsResult<Self> {
        let listen: SocketAddr = listen_addr.parse()
            .map_err(|e| DnsError::ConfigError(format!("Invalid listen address: {}", e)))?;

        let config = DnsServerConfig {
            listen,
            ..Default::default()
        };

        Self::with_config(config, resolver).await
    }

    /// Create a new DNS server with custom configuration
    pub async fn with_config(config: DnsServerConfig, resolver: Resolver) -> DnsResult<Self> {
        let cache = Arc::new(DnsCache::new(config.cache_size));

        let fake_ip_pool = if config.fake_ip_enabled {
            let range = config.fake_ip_range.as_deref().unwrap_or("198.18.0.0/16");
            match FakeIpPool::new(range) {
                Ok(pool) => Some(Arc::new(RwLock::new(pool))),
                Err(e) => {
                    warn!("Failed to create fake IP pool: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            resolver,
            cache,
            fake_ip_pool,
            shutdown_tx,
        })
    }

    /// Start the DNS server
    pub async fn start(&self) -> DnsResult<()> {
        let socket = UdpSocket::bind(self.config.listen).await
            .map_err(|e| DnsError::ServerError(format!("Failed to bind DNS server: {}", e)))?;

        info!("DNS server listening on {}", self.config.listen);

        let resolver = self.resolver.clone();
        let cache = self.cache.clone();
        let fake_ip_pool = self.fake_ip_pool.clone();
        let fake_ip_filter = self.config.fake_ip_filter.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                let query = buf[..len].to_vec();
                                let socket_clone = socket.local_addr().ok();
                                let resolver_clone = resolver.clone();
                                let cache_clone = cache.clone();
                                let fake_ip_pool_clone = fake_ip_pool.clone();
                                let fake_ip_filter_clone = fake_ip_filter.clone();

                                tokio::spawn(async move {
                                    match Self::handle_query(
                                        &query,
                                        &resolver_clone,
                                        &cache_clone,
                                        fake_ip_pool_clone.as_ref(),
                                        &fake_ip_filter_clone,
                                    ).await {
                                        Ok(response) => {
                                            if socket_clone.is_some() {
                                                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                                                    let _ = sock.send_to(&response, src).await;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            debug!("Failed to handle DNS query: {}", e);
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to receive DNS query: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("DNS server shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle a DNS query
    async fn handle_query(
        query: &[u8],
        resolver: &Resolver,
        cache: &DnsCache,
        fake_ip_pool: Option<&Arc<RwLock<FakeIpPool>>>,
        fake_ip_filter: &[String],
    ) -> DnsResult<Vec<u8>> {
        let message = Message::from_bytes(query)
            .map_err(|e| DnsError::ServerError(format!("Failed to parse DNS query: {}", e)))?;

        let mut response = Message::new();
        response.set_id(message.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_desired(message.recursion_desired());
        response.set_recursion_available(true);

        // Copy queries to response
        for query in message.queries() {
            response.add_query(query.clone());
        }

        // Process each query
        for query in message.queries() {
            let name = query.name().to_string();
            let name = name.trim_end_matches('.');
            let record_type = query.query_type();

            debug!("DNS query: {} {:?}", name, record_type);

            // Check cache first
            if let Some(ips) = cache.get(name) {
                for ip in ips {
                    let record = Self::create_record(query.name(), ip, 300);
                    response.add_answer(record);
                }
                continue;
            }

            // Check if we should use fake IP
            let use_fake_ip = fake_ip_pool.is_some()
                && (record_type == RecordType::A || record_type == RecordType::AAAA)
                && !Self::matches_fake_ip_filter(name, fake_ip_filter);

            if use_fake_ip {
                if let Some(pool) = fake_ip_pool {
                    let mut pool = pool.write().await;
                    if let Some(fake_ip) = pool.allocate(name) {
                        let record = Self::create_record(query.name(), fake_ip, 1);
                        response.add_answer(record);
                        continue;
                    }
                }
            }

            // Resolve using upstream
            match resolver.resolve(name).await {
                Ok(ips) => {
                    // Cache the result
                    cache.put(name.to_string(), ips.clone());

                    for ip in ips {
                        // Filter by record type
                        match (record_type, ip) {
                            (RecordType::A, IpAddr::V4(_)) |
                            (RecordType::AAAA, IpAddr::V6(_)) |
                            (RecordType::ANY, _) => {
                                let record = Self::create_record(query.name(), ip, 300);
                                response.add_answer(record);
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    debug!("DNS resolution failed for {}: {}", name, e);
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
        }

        response.to_vec()
            .map_err(|e| DnsError::ServerError(format!("Failed to serialize DNS response: {}", e)))
    }

    /// Create a DNS record
    fn create_record(name: &Name, ip: IpAddr, ttl: u32) -> Record {
        match ip {
            IpAddr::V4(v4) => {
                Record::from_rdata(name.clone(), ttl, RData::A(A(v4)))
            }
            IpAddr::V6(v6) => {
                Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(v6)))
            }
        }
    }

    /// Check if a domain matches the fake IP filter
    fn matches_fake_ip_filter(domain: &str, filter: &[String]) -> bool {
        for pattern in filter {
            if pattern.starts_with("*.") {
                // Wildcard match
                let suffix = &pattern[2..];
                if domain.ends_with(suffix) || domain == &suffix[1..] {
                    return true;
                }
            } else if pattern.starts_with('+') {
                // Suffix match
                let suffix = &pattern[1..];
                if domain.ends_with(suffix) {
                    return true;
                }
            } else if domain == pattern {
                // Exact match
                return true;
            }
        }
        false
    }

    /// Stop the DNS server
    pub async fn stop(self) -> DnsResult<()> {
        let _ = self.shutdown_tx.send(());
        Ok(())
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.cache.len(), self.config.cache_size)
    }
}
