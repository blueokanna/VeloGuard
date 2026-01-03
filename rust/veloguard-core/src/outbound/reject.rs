use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};

/// Reject outbound - drops all connections
pub struct RejectOutbound {
    config: OutboundConfig,
}

#[async_trait::async_trait]
impl OutboundProxy for RejectOutbound {
    async fn connect(&self) -> Result<()> {
        // Reject outbound doesn't need to connect
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        // Nothing to disconnect
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
    
    fn server_addr(&self) -> Option<(String, u16)> {
        // Reject outbound has no server
        None
    }
    
    async fn test_http_latency(
        &self,
        _test_url: &str,
        _timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        // Reject outbound always fails
        Err(Error::network("Connection rejected by policy"))
    }
    
    async fn relay_tcp(
        &self,
        _inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
    ) -> Result<()> {
        tracing::debug!("Rejecting connection to {}", target);
        // Simply drop the connection by returning an error
        Err(Error::network("Connection rejected by policy"))
    }
}

impl RejectOutbound {
    pub fn new(config: OutboundConfig) -> Self {
        Self { config }
    }
}
