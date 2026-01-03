use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use tokio::net::TcpStream;

/// Trojan outbound proxy
/// TODO: Full Trojan protocol requires TLS and SHA224 password hashing
pub struct TrojanOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    password: String,
    #[allow(dead_code)]
    sni: String,
    #[allow(dead_code)]
    skip_cert_verify: bool,
}

#[async_trait::async_trait]
impl OutboundProxy for TrojanOutbound {
    async fn connect(&self) -> Result<()> {
        let addr = format!("{}:{}", self.server, self.port);
        let _stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to connect to Trojan server {}: {}", addr, e)))?;
        tracing::info!(
            "Trojan outbound '{}' can reach {}",
            self.config.tag,
            addr
        );
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
    
    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
    
    async fn test_http_latency(
        &self,
        _test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;
        
        let start = Instant::now();
        let addr = format!("{}:{}", self.server, self.port);
        
        // For Trojan, we just test TCP connectivity to the server
        // Full Trojan protocol test requires TLS implementation
        tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::network("Connection timeout"))?
            .map_err(|e| Error::network(format!("Failed to connect: {}", e)))?;
        
        Ok(start.elapsed())
    }
    
    async fn relay_tcp(
        &self,
        _inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
    ) -> Result<()> {
        // Trojan protocol requires TLS implementation
        // TODO: Implement full Trojan protocol with TLS
        tracing::warn!("Trojan outbound not fully implemented, connection to {} will fail", target);
        Err(Error::protocol("Trojan protocol not implemented"))
    }
}

impl TrojanOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for Trojan"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for Trojan"))?;

        let password = config
            .options
            .get("password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        let sni = config
            .options
            .get("sni")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| server.clone());
        
        let skip_cert_verify = config
            .options
            .get("skip-cert-verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(Self {
            config,
            server: server.clone(),
            port,
            password,
            sni,
            skip_cert_verify,
        })
    }
}
