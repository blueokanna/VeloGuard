use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};

/// VMess outbound proxy
/// TODO: VMess protocol is complex and requires proper implementation
pub struct VmessOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    uuid: String,
    #[allow(dead_code)]
    alter_id: u16,
    #[allow(dead_code)]
    cipher: String,
}

#[async_trait::async_trait]
impl OutboundProxy for VmessOutbound {
    async fn connect(&self) -> Result<()> {
        let addr = format!("{}:{}", self.server, self.port);
        let _stream = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| Error::network(format!("Failed to connect to VMess server {}: {}", addr, e)))?;
        tracing::info!(
            "VMess outbound '{}' connected to {}",
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
        
        // For VMess, we test TCP connectivity to the server
        // Full VMess protocol test requires complex encryption implementation
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
        // VMess protocol requires complex encryption implementation
        // TODO: Implement VMess protocol properly
        tracing::warn!("VMess outbound not fully implemented, connection to {} will fail", target);
        Err(Error::protocol("VMess protocol not implemented"))
    }
}

impl VmessOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for VMess"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for VMess"))?;

        // Get UUID from options
        let uuid = config
            .options
            .get("uuid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        // Get alterId from options
        let alter_id = config
            .options
            .get("alterId")
            .or_else(|| config.options.get("alter-id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as u16;

        // Get cipher from options
        let cipher = config
            .options
            .get("cipher")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "auto".to_string());

        Ok(Self {
            config,
            server,
            port,
            uuid,
            alter_id,
            cipher,
        })
    }
}
