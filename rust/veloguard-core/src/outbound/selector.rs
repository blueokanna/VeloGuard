use crate::config::OutboundConfig;
use crate::error::{Error, Result};
use crate::outbound::{AsyncReadWrite, OutboundProxy, ProxyRegistry, TargetAddr};
use std::sync::Arc;
use parking_lot::RwLock as ParkingRwLock;
use std::collections::HashMap;

// Use the shared global selector selections from the parent module
pub use crate::outbound::get_global_selector_selections;

fn get_global_selections() -> &'static ParkingRwLock<HashMap<String, String>> {
    get_global_selector_selections()
}

/// Selector proxy group - allows manual selection of outbound
/// Also used for url-test, fallback, load-balance, and relay groups
pub struct SelectorOutbound {
    config: OutboundConfig,
    outbounds: Vec<String>,
    default_selected: String,
    registry: ProxyRegistry,
}

impl SelectorOutbound {
    pub fn new(config: OutboundConfig, registry: ProxyRegistry) -> Result<Self> {
        // Parse outbounds from options - the options field contains a YAML value
        // that was converted from JSON, so we need to handle both formats
        let outbounds: Vec<String> = if let Some(outbounds_value) = config.options.get("outbounds") {
            tracing::debug!("Selector '{}' outbounds_value type: {:?}", config.tag, outbounds_value);
            
            // Try to parse as array directly
            if let Some(arr) = outbounds_value.as_sequence() {
                let result: Vec<String> = arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                tracing::debug!("Selector '{}' parsed {} outbounds from sequence", config.tag, result.len());
                result
            } else if let Some(s) = outbounds_value.as_str() {
                // Try to parse as JSON string
                let result = serde_json::from_str::<Vec<String>>(s).unwrap_or_default();
                tracing::debug!("Selector '{}' parsed {} outbounds from JSON string", config.tag, result.len());
                result
            } else {
                tracing::warn!("Selector '{}' outbounds_value is neither sequence nor string", config.tag);
                Vec::new()
            }
        } else {
            tracing::warn!("Selector '{}' has no 'outbounds' in options. Available keys: {:?}", 
                config.tag, config.options.keys().collect::<Vec<_>>());
            Vec::new()
        };
        
        // If no outbounds specified, default to DIRECT
        let default_selected = outbounds.first().cloned().unwrap_or_else(|| "DIRECT".to_string());
        
        tracing::info!("Selector '{}' created with {} outbounds: {:?}, default: {}", 
            config.tag, outbounds.len(), outbounds, default_selected);
        
        Ok(Self {
            config,
            outbounds,
            default_selected,
            registry,
        })
    }
    
    /// Get the currently selected outbound tag
    /// First checks global selections, then falls back to default
    pub fn get_selected(&self) -> String {
        let selections = get_global_selections();
        selections.read()
            .get(&self.config.tag)
            .cloned()
            .unwrap_or_else(|| self.default_selected.clone())
    }
    
    /// Set the selected outbound (updates global selection)
    pub fn set_selected(&self, tag: &str) -> Result<()> {
        if self.outbounds.contains(&tag.to_string()) || tag == "DIRECT" || tag == "REJECT" {
            let selections = get_global_selections();
            selections.write().insert(self.config.tag.clone(), tag.to_string());
            tracing::info!("Selector '{}' switched to '{}'", self.config.tag, tag);
            Ok(())
        } else {
            Err(Error::config(format!("Outbound '{}' not in selector group '{}'", tag, self.config.tag)))
        }
    }
    
    /// Get available outbounds
    pub fn get_outbounds(&self) -> &[String] {
        &self.outbounds
    }
    
    /// Find a proxy by tag from the registry
    async fn find_proxy(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        self.registry.read().await.get(tag).cloned()
    }
    
    /// Resolve the actual proxy to use (handles nested selectors)
    async fn resolve_proxy(&self, max_depth: usize) -> Result<Arc<dyn OutboundProxy>> {
        if max_depth == 0 {
            return Err(Error::config("Selector chain too deep"));
        }
        
        let selected = self.get_selected();
        tracing::debug!("Selector '{}' resolving to '{}'", self.config.tag, selected);
        
        if let Some(proxy) = self.find_proxy(&selected).await {
            // Check if the selected proxy is also a selector (nested group)
            // For now, we just return the proxy directly
            // In a full implementation, we'd check if it's a SelectorOutbound and resolve recursively
            Ok(proxy)
        } else {
            Err(Error::config(format!("Selected outbound '{}' not found in registry", selected)))
        }
    }
}

#[async_trait::async_trait]
impl OutboundProxy for SelectorOutbound {
    async fn connect(&self) -> Result<()> {
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
    
    fn server_addr(&self) -> Option<(String, u16)> {
        // Try to get the server address from the currently selected proxy
        let selected = self.get_selected();
        
        // Use blocking read since this is a sync function
        // We need to check the registry for the selected proxy
        let registry = self.registry.blocking_read();
        if let Some(proxy) = registry.get(&selected) {
            proxy.server_addr()
        } else {
            None
        }
    }
    
    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        let proxy = self.resolve_proxy(10).await?;
        proxy.test_http_latency(test_url, timeout).await
    }
    
    async fn relay_tcp(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
    ) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None).await
    }
    
    async fn relay_tcp_with_connection(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        let proxy = self.resolve_proxy(10).await?;
        tracing::debug!("Selector '{}' relaying to '{}' for target {}", 
            self.config.tag, proxy.tag(), target);
        proxy.relay_tcp_with_connection(inbound, target, connection).await
    }
    
    fn supports_udp(&self) -> bool {
        // Check if the currently selected proxy supports UDP
        let selected = self.get_selected();
        let registry = self.registry.blocking_read();
        if let Some(proxy) = registry.get(&selected) {
            proxy.supports_udp()
        } else {
            false
        }
    }
    
    async fn relay_udp_packet(
        &self,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let proxy = self.resolve_proxy(10).await?;
        if !proxy.supports_udp() {
            return Err(Error::config(format!(
                "Selected proxy '{}' does not support UDP",
                proxy.tag()
            )));
        }
        tracing::debug!("Selector '{}' relaying UDP to '{}' for target {}", 
            self.config.tag, proxy.tag(), target);
        proxy.relay_udp_packet(target, data).await
    }
}
