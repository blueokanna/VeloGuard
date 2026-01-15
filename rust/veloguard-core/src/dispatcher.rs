use crate::connection_tracker::{global_tracker, TrackedConnection};
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundManager, TargetAddr};
use crate::routing::Router;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

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
        // For domain targets, route based on domain first, not resolved IP
        // This prevents private IP detection from interfering with domain-based routing
        let (domain_for_routing, ip_for_routing) = match &target {
            TargetAddr::Ip(addr) => (None, Some(addr.ip())),
            TargetAddr::Domain(domain, _) => {
                // Use domain for routing, don't resolve IP here
                // IP resolution will happen in the outbound proxy
                (Some(domain.as_str()), None)
            }
        };

        let outbound_tag = self
            .router
            .match_outbound(domain_for_routing.or(Some(&target.host())), ip_for_routing, Some(target.port()), None)
            .await;

        tracing::info!(
            "[Dispatcher] TCP {} -> {} via '{}' (source: {:?})",
            inbound_tag,
            target,
            outbound_tag,
            source_addr
        );

        let outbound = self
            .outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| {
                tracing::error!("[Dispatcher] Outbound '{}' not found in manager!", outbound_tag);
                Error::config(format!("Outbound '{}' not found", outbound_tag))
            })?;
        
        tracing::debug!("[Dispatcher] Using outbound '{}' (type: {})", 
            outbound.tag(), std::any::type_name_of_val(&*outbound));

        // Only resolve IP for connection tracking display, not for routing
        let destination_ip = match &target {
            TargetAddr::Ip(addr) => Some(addr.ip().to_string()),
            TargetAddr::Domain(domain, _) => {
                // Try to resolve for display purposes only
                tokio::net::lookup_host(format!("{}:0", domain))
                    .await
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .map(|addr| addr.ip().to_string())
            }
        };

        let tracked_conn = TrackedConnection::new_with_ip(
            inbound_tag.to_string(),
            outbound_tag.clone(),
            target.host(),
            destination_ip,
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
        let result = outbound
            .relay_tcp_with_connection(inbound_stream, target.clone(), Some(conn_arc))
            .await;

        tracker.untrack(&tracked.id);

        if let Err(ref e) = result {
            tracing::info!("[Dispatcher] Relay error for {}: {}", target, e);
        }

        result
    }

    pub async fn dispatch_udp(
        &self,
        data: &[u8],
        target: TargetAddr,
        inbound_tag: &str,
        _source_addr: Option<std::net::SocketAddr>,
    ) -> Result<Vec<u8>> {
        // For domain targets, route based on domain first, not resolved IP
        let (domain_for_routing, ip_for_routing) = match &target {
            TargetAddr::Ip(addr) => (None, Some(addr.ip())),
            TargetAddr::Domain(domain, _) => (Some(domain.as_str()), None),
        };

        let outbound_tag = self
            .router
            .match_outbound(domain_for_routing.or(Some(&target.host())), ip_for_routing, Some(target.port()), None)
            .await;

        tracing::debug!(
            "[Dispatcher] UDP {} -> {} via {}",
            inbound_tag,
            target,
            outbound_tag
        );

        let outbound = self
            .outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        if !outbound.supports_udp() {
            return Err(Error::protocol(format!(
                "Outbound '{}' does not support UDP",
                outbound_tag
            )));
        }

        outbound.relay_udp_packet(&target, data).await
    }

    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    pub fn outbound_manager(&self) -> &Arc<OutboundManager> {
        &self.outbound_manager
    }

    pub async fn resolve_outbound(&self, target: &TargetAddr) -> String {
        self.router
            .match_outbound(Some(&target.host()), None, Some(target.port()), None)
            .await
    }
}

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

pub trait Dispatchable: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Dispatchable for T {}
