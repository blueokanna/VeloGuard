use crate::config::{Config, InboundType};
use crate::error::Result;
use crate::outbound::OutboundManager;
use crate::routing::Router;
use std::sync::Arc;
use tokio::sync::RwLock;

mod http;
mod mixed;
mod socks5;

use http::HttpInbound;
use mixed::MixedInbound;
use socks5::Socks5Inbound;

/// Inbound connection manager
pub struct InboundManager {
    _config: Arc<RwLock<Config>>,
    _router: Arc<Router>,
    listeners: Vec<Box<dyn InboundListener>>,
}

#[async_trait::async_trait]
pub trait InboundListener: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn tag(&self) -> &str;
}

impl InboundManager {
    pub async fn new(
        config: Arc<RwLock<Config>>,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Self> {
        let mut listeners: Vec<Box<dyn InboundListener>> = Vec::new();

        {
            let config_read = config.read().await;
            for inbound_config in &config_read.inbounds {
                let listener: Box<dyn InboundListener> = match inbound_config.inbound_type {
                    InboundType::Http => {
                        Box::new(HttpInbound::new(
                            inbound_config.clone(),
                            Arc::clone(&router),
                            Arc::clone(&outbound_manager),
                        ))
                    }
                    InboundType::Socks5 => {
                        Box::new(Socks5Inbound::new(
                            inbound_config.clone(),
                            Arc::clone(&router),
                            Arc::clone(&outbound_manager),
                        ))
                    }
                    InboundType::Mixed => {
                        // Mixed supports both HTTP and SOCKS5 with auto-detection
                        Box::new(MixedInbound::new(
                            inbound_config.clone(),
                            Arc::clone(&router),
                            Arc::clone(&outbound_manager),
                        ))
                    }
                    _ => {
                        tracing::warn!("Unsupported inbound type: {:?}", inbound_config.inbound_type);
                        continue;
                    }
                };
                listeners.push(listener);
            }
        } // config_read is dropped here

        Ok(Self {
            _config: config,
            _router: router,
            listeners,
        })
    }

    pub async fn start(&self) -> Result<()> {
        for listener in &self.listeners {
            listener.start().await?;
        }
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        for listener in &self.listeners {
            listener.stop().await?;
        }
        Ok(())
    }

    pub async fn reload(&self) -> Result<()> {
        Ok(())
    }
}
