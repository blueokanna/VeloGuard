//! Dispatcher module - Core traffic routing between Inbound and Outbound
//! 
//! The Dispatcher is responsible for:
//! - Receiving connections from Inbound handlers
//! - Using Router to determine the target Outbound
//! - Forwarding traffic to the selected Outbound
//! - Managing connection lifecycle

use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundManager, TargetAddr};
use crate::routing::Router;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Dispatcher handles traffic routing between Inbound and Outbound proxies
pub struct Dispatcher {
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
}

impl Dispatcher {
    pub fn new(router: Arc<Router>, outbound_manager: Arc<OutboundManager>) -> Self {
        Self {
            router,
            outbound_manager,
        }
    }

    /// Dispatch a TCP connection to the appropriate outbound
    pub async fn dispatch_tcp(
        &self,
        inbound_stream: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        inbound_tag: &str,
        source_addr: Option<std::net::SocketAddr>,
    ) -> Result<()> {
        // Use router to determine outbound
        let outbound_tag = self.router.match_outbound(
            Some(&target.host()),
            source_addr.map(|a| a.ip()),
            Some(target.port()),
            None,
        ).await;

        tracing::info!(
            "[Dispatcher] {} -> {} via {} from {:?}",
            inbound_tag, target, outbound_tag, source_addr
        );

        // Get the outbound proxy
        let outbound = self.outbound_manager.get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        // Create tracked connection
        let tracked_conn = TrackedConnection::new_with_ip(
            inbound_tag.to_string(),
            outbound_tag.clone(),
            target.host(),
            source_addr.map(|a| a.ip().to_string()),
            target.port(),
            inbound_tag.to_string(),
            "tcp".to_string(),
            inbound_tag.to_string(),
            target.to_string(),
        );

        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);

        // Relay traffic through outbound
        let result = outbound.relay_tcp_with_connection(
            inbound_stream,
            target.clone(),
            Some(conn_arc),
        ).await;

        tracker.untrack(&tracked.id);

        if let Err(ref e) = result {
            tracing::debug!("[Dispatcher] Relay error: {}", e);
        }

        result
    }

    /// Dispatch a UDP packet to the appropriate outbound
    pub async fn dispatch_udp(
        &self,
        data: &[u8],
        target: TargetAddr,
        inbound_tag: &str,
        source_addr: Option<std::net::SocketAddr>,
    ) -> Result<Vec<u8>> {
        // Use router to determine outbound
        let outbound_tag = self.router.match_outbound(
            Some(&target.host()),
            source_addr.map(|a| a.ip()),
            Some(target.port()),
            None,
        ).await;

        tracing::debug!(
            "[Dispatcher] UDP {} -> {} via {}",
            inbound_tag, target, outbound_tag
        );

        // Get the outbound proxy
        let outbound = self.outbound_manager.get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        if !outbound.supports_udp() {
            return Err(Error::protocol(format!(
                "Outbound '{}' does not support UDP",
                outbound_tag
            )));
        }

        outbound.relay_udp_packet(&target, data).await
    }

    /// Get the router reference
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// Get the outbound manager reference
    pub fn outbound_manager(&self) -> &Arc<OutboundManager> {
        &self.outbound_manager
    }

    /// Resolve outbound tag for a target (useful for logging/debugging)
    pub async fn resolve_outbound(&self, target: &TargetAddr) -> String {
        self.router.match_outbound(
            Some(&target.host()),
            None,
            Some(target.port()),
            None,
        ).await
    }
}

/// DispatchContext carries information about a dispatched connection
#[derive(Debug, Clone)]
pub struct DispatchContext {
    pub inbound_tag: String,
    pub outbound_tag: String,
    pub target: TargetAddr,
    pub source_addr: Option<std::net::SocketAddr>,
    pub protocol: String,
    pub network: String,
}

impl DispatchContext {
    pub fn new(
        inbound_tag: String,
        outbound_tag: String,
        target: TargetAddr,
        source_addr: Option<std::net::SocketAddr>,
        protocol: &str,
        network: &str,
    ) -> Self {
        Self {
            inbound_tag,
            outbound_tag,
            target,
            source_addr,
            protocol: protocol.to_string(),
            network: network.to_string(),
        }
    }
}

/// Trait for streams that can be dispatched
pub trait Dispatchable: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Dispatchable for T {}
