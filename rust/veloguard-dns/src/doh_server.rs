//! DNS over HTTPS (DoH) server implementation
//!
//! RFC 8484 compliant DoH server supporting both GET and POST methods.

use crate::error::{DnsError, Result};
use crate::resolver::DnsResolver;
use crate::RecordType;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};

/// DoH server configuration
#[derive(Debug, Clone)]
pub struct DohServerConfig {
    /// Listen address
    pub listen: SocketAddr,
    /// TLS certificate path
    pub cert_path: String,
    /// TLS private key path
    pub key_path: String,
    /// DNS query path (default: /dns-query)
    pub path: String,
    /// Enable HTTP/2
    pub http2: bool,
}

impl Default for DohServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8443".parse().unwrap(),
            cert_path: String::new(),
            key_path: String::new(),
            path: "/dns-query".to_string(),
            http2: true,
        }
    }
}

/// DNS over HTTPS server
pub struct DohServer {
    /// Configuration
    config: DohServerConfig,
    /// DNS resolver
    resolver: Arc<DnsResolver>,
    /// TLS acceptor
    tls_acceptor: Option<TlsAcceptor>,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
}

impl DohServer {
    /// Create a new DoH server
    pub fn new(config: DohServerConfig, resolver: Arc<DnsResolver>) -> Result<Self> {
        let tls_acceptor = if !config.cert_path.is_empty() && !config.key_path.is_empty() {
            Some(Self::create_tls_acceptor(&config.cert_path, &config.key_path)?)
        } else {
            None
        };

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

    /// Start the DoH server
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen).await?;
        info!("DoH server listening on {}", self.config.listen);

        let resolver = self.resolver.clone();
        let path = self.config.path.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let resolver = resolver.clone();
                            let path = path.clone();
                            let tls_acceptor = tls_acceptor.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    addr,
                                    resolver,
                                    path,
                                    tls_acceptor,
                                ).await {
                                    debug!("DoH connection error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("DoH accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("DoH server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single connection
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        addr: SocketAddr,
        resolver: Arc<DnsResolver>,
        path: String,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> Result<()> {
        trace!("DoH connection from {}", addr);

        if let Some(acceptor) = tls_acceptor {
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| DnsError::Tls(format!("TLS handshake failed: {}", e)))?;

            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |req| {
                let resolver = resolver.clone();
                let path = path.clone();
                async move { Self::handle_request(req, resolver, path).await }
            });

            hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
                .map_err(|e| DnsError::Http(format!("HTTP error: {}", e)))?;
        } else {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let resolver = resolver.clone();
                let path = path.clone();
                async move { Self::handle_request(req, resolver, path).await }
            });

            hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
                .map_err(|e| DnsError::Http(format!("HTTP error: {}", e)))?;
        }

        Ok(())
    }

    /// Handle HTTP request
    async fn handle_request(
        req: Request<Incoming>,
        resolver: Arc<DnsResolver>,
        expected_path: String,
    ) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
        let path = req.uri().path();
        
        if path != expected_path {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap());
        }

        let result = match *req.method() {
            Method::GET => Self::handle_get_request(&req, &resolver).await,
            Method::POST => Self::handle_post_request(req, &resolver).await,
            _ => {
                return Ok(Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::new(Bytes::from("Method Not Allowed")))
                    .unwrap());
            }
        };

        match result {
            Ok(dns_response) => {
                let response_bytes = dns_response
                    .to_bytes()
                    .unwrap_or_else(|_| vec![]);

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/dns-message")
                    .header("Cache-Control", "max-age=300")
                    .body(Full::new(Bytes::from(response_bytes)))
                    .unwrap())
            }
            Err(e) => {
                warn!("DoH query error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from(format!("DNS Error: {}", e))))
                    .unwrap())
            }
        }
    }

    /// Handle GET request (base64url encoded DNS query in ?dns= parameter)
    async fn handle_get_request(
        req: &Request<Incoming>,
        resolver: &DnsResolver,
    ) -> Result<Message> {
        let query_string = req.uri().query().unwrap_or("");
        
        let dns_param = query_string
            .split('&')
            .find_map(|param| {
                let (key, value) = param.split_once('=')?;
                
                
                if key == "dns" {
                    Some(value)
                } else {
                    None
                }
            })
            .ok_or_else(|| DnsError::Protocol("Missing 'dns' query parameter".to_string()))?;

        let query_bytes = URL_SAFE_NO_PAD
            .decode(dns_param)
            .map_err(|e| DnsError::Protocol(format!("Invalid base64: {}", e)))?;

        Self::process_dns_query(&query_bytes, resolver).await
    }

    /// Handle POST request (binary DNS message in body)
    async fn handle_post_request(
        req: Request<Incoming>,
        resolver: &DnsResolver,
    ) -> Result<Message> {
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.contains("application/dns-message") {
            return Err(DnsError::Protocol(format!(
                "Invalid content-type: {}",
                content_type
            )));
        }

        let body = req
            .collect()
            .await
            .map_err(|e| DnsError::Http(format!("Failed to read body: {}", e)))?
            .to_bytes();

        Self::process_dns_query(&body, resolver).await
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

            trace!("DoH query: {} {:?}", name, record_type);

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
                    warn!("DoH resolution failed for {}: {}", name, e);
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
        }

        Ok(response)
    }

    /// Stop the DoH server
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
    use crate::config::DnsConfig;

    #[test]
    fn test_doh_server_config_default() {
        let config = DohServerConfig::default();
        assert_eq!(config.path, "/dns-query");
        assert!(config.http2);
    }

    #[tokio::test]
    async fn test_doh_server_creation_without_tls() {
        let dns_config = DnsConfig {
            nameservers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let resolver = Arc::new(DnsResolver::new(dns_config).unwrap());

        let config = DohServerConfig {
            listen: "127.0.0.1:18443".parse().unwrap(),
            cert_path: String::new(),
            key_path: String::new(),
            path: "/dns-query".to_string(),
            http2: true,
        };

        let server = DohServer::new(config, resolver);
        assert!(server.is_ok());
    }
}
