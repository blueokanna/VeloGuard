use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};

/// WireGuard outbound proxy
/// TODO: WireGuard requires kernel integration or userspace implementation
pub struct WireguardOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    private_key: String,
    #[allow(dead_code)]
    public_key: String,
}

#[async_trait::async_trait]
impl OutboundProxy for WireguardOutbound {
    async fn connect(&self) -> Result<()> {
        tracing::info!(
            "WireGuard outbound '{}' configured for {}:{}",
            self.config.tag,
            self.server,
            self.port
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
        
        // For WireGuard, we just test UDP port reachability via a TCP probe
        // Note: WireGuard uses UDP, but we can test TCP connectivity as a proxy
        // In reality, WireGuard servers don't respond to TCP, so this tests basic network path
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
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
        // WireGuard requires complex integration
        // TODO: Implement WireGuard properly (using boringtun or kernel module)
        tracing::warn!("WireGuard outbound not fully implemented, connection to {} will fail", target);
        Err(Error::protocol("WireGuard protocol not implemented"))
    }
}

impl WireguardOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for WireGuard"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for WireGuard"))?;

        // Get private key from options
        let private_key = config
            .options
            .get("private-key")
            .or_else(|| config.options.get("privateKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        // Get peer public key from options
        let public_key = config
            .options
            .get("public-key")
            .or_else(|| config.options.get("publicKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        Ok(Self {
            config,
            server,
            port,
            private_key,
            public_key,
        })
    }
}
