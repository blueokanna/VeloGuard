use crate::error::Result;
#[cfg(feature = "jaeger")]
use crate::error::Error;
use std::sync::Once;

static INIT: Once = Once::new();

#[cfg(feature = "jaeger")]
use opentelemetry::trace::TracerProvider;
#[cfg(feature = "jaeger")]
use opentelemetry_otlp::WithExportConfig;
#[cfg(feature = "jaeger")]
use opentelemetry_sdk::trace::SdkTracerProvider;
#[cfg(feature = "jaeger")]
use tracing_subscriber::layer::SubscriberExt;
#[cfg(feature = "jaeger")]
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Clone)]
pub struct TracingConfig {
    pub enabled: bool,
    pub jaeger_endpoint: Option<String>,
    pub service_name: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            jaeger_endpoint: None,
            service_name: "veloguard".to_string(),
        }
    }
}

impl TracingConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_jaeger(mut self, endpoint: impl Into<String>) -> Self {
        self.enabled = true;
        self.jaeger_endpoint = Some(endpoint.into());
        self
    }

    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }
}

#[cfg(feature = "jaeger")]
static TRACER_PROVIDER: once_cell::sync::OnceCell<SdkTracerProvider> = once_cell::sync::OnceCell::new();

pub fn init_tracing(config: TracingConfig) -> Result<()> {
    let mut result = Ok(());

    INIT.call_once(|| {
        result = init_tracing_inner(config);
    });

    result
}

#[cfg(feature = "jaeger")]
fn init_tracing_inner(config: TracingConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let endpoint = config.jaeger_endpoint.unwrap_or_else(|| "http://localhost:4317".to_string());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .map_err(|e| Error::config(format!("Failed to create OTLP exporter: {}", e)))?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(opentelemetry_sdk::Resource::builder()
            .with_service_name(config.service_name.clone())
            .build())
        .build();

    let tracer = tracer_provider.tracer(config.service_name);

    TRACER_PROVIDER.set(tracer_provider).map_err(|_| {
        Error::config("Tracer provider already initialized".to_string())
    })?;

    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(telemetry_layer)
        .try_init()
        .map_err(|e| Error::config(format!("Failed to initialize tracing subscriber: {}", e)))?;

    tracing::info!("Jaeger tracing initialized with endpoint: {}", endpoint);
    Ok(())
}

#[cfg(not(feature = "jaeger"))]
fn init_tracing_inner(_config: TracingConfig) -> Result<()> {
    Ok(())
}

pub fn shutdown_tracing() {
    #[cfg(feature = "jaeger")]
    {
        if let Some(provider) = TRACER_PROVIDER.get() {
            if let Err(e) = provider.shutdown() {
                tracing::error!("Failed to shutdown tracer provider: {:?}", e);
            }
        }
    }
}

#[cfg(feature = "jaeger")]
#[macro_export]
macro_rules! trace_dns_resolution {
    ($domain:expr, $body:expr) => {{
        use tracing::Instrument;
        let span = tracing::info_span!(
            "dns_resolution",
            domain = %$domain,
            otel.kind = "client"
        );
        async move { $body }.instrument(span).await
    }};
}

#[cfg(not(feature = "jaeger"))]
#[macro_export]
macro_rules! trace_dns_resolution {
    ($domain:expr, $body:expr) => {{
        $body
    }};
}

#[cfg(feature = "jaeger")]
#[macro_export]
macro_rules! trace_proxy_connection {
    ($target:expr, $protocol:expr, $body:expr) => {{
        use tracing::Instrument;
        let span = tracing::info_span!(
            "proxy_connection",
            target = %$target,
            protocol = %$protocol,
            otel.kind = "client"
        );
        async move { $body }.instrument(span).await
    }};
}

#[cfg(not(feature = "jaeger"))]
#[macro_export]
macro_rules! trace_proxy_connection {
    ($target:expr, $protocol:expr, $body:expr) => {{
        $body
    }};
}

#[cfg(feature = "jaeger")]
#[macro_export]
macro_rules! trace_routing_decision {
    ($domain:expr, $ip:expr, $rule:expr, $outbound:expr) => {{
        tracing::info_span!(
            "routing_decision",
            domain = ?$domain,
            ip = ?$ip,
            matched_rule = %$rule,
            outbound = %$outbound,
            otel.kind = "internal"
        )
        .in_scope(|| {
            tracing::info!(
                "Routing decision: domain={:?}, ip={:?}, rule={}, outbound={}",
                $domain, $ip, $rule, $outbound
            );
        });
    }};
}

#[cfg(not(feature = "jaeger"))]
#[macro_export]
macro_rules! trace_routing_decision {
    ($domain:expr, $ip:expr, $rule:expr, $outbound:expr) => {{}};
}

pub struct DnsResolutionSpan {
    #[cfg(feature = "jaeger")]
    _span: tracing::span::EnteredSpan,
}

impl DnsResolutionSpan {
    #[cfg(feature = "jaeger")]
    pub fn new(domain: &str) -> Self {
        let span = tracing::info_span!(
            "dns_resolution",
            domain = %domain,
            otel.kind = "client"
        );
        Self {
            _span: span.entered(),
        }
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn new(_domain: &str) -> Self {
        Self {}
    }

    #[cfg(feature = "jaeger")]
    pub fn record_result(&self, success: bool, ip_count: usize) {
        tracing::Span::current().record("success", success);
        tracing::Span::current().record("ip_count", ip_count);
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn record_result(&self, _success: bool, _ip_count: usize) {}
}

pub struct ProxyConnectionSpan {
    #[cfg(feature = "jaeger")]
    _span: tracing::span::EnteredSpan,
}

impl ProxyConnectionSpan {
    #[cfg(feature = "jaeger")]
    pub fn new(target: &str, protocol: &str) -> Self {
        let span = tracing::info_span!(
            "proxy_connection",
            target = %target,
            protocol = %protocol,
            otel.kind = "client"
        );
        Self {
            _span: span.entered(),
        }
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn new(_target: &str, _protocol: &str) -> Self {
        Self {}
    }

    #[cfg(feature = "jaeger")]
    pub fn record_success(&self, bytes_sent: u64, bytes_received: u64) {
        tracing::Span::current().record("success", true);
        tracing::Span::current().record("bytes_sent", bytes_sent);
        tracing::Span::current().record("bytes_received", bytes_received);
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn record_success(&self, _bytes_sent: u64, _bytes_received: u64) {}

    #[cfg(feature = "jaeger")]
    pub fn record_error(&self, error: &str) {
        tracing::Span::current().record("success", false);
        tracing::Span::current().record("error", error);
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn record_error(&self, _error: &str) {}
}

pub struct RoutingDecisionSpan {
    #[cfg(feature = "jaeger")]
    _span: tracing::span::EnteredSpan,
}

impl RoutingDecisionSpan {
    #[cfg(feature = "jaeger")]
    pub fn new(domain: Option<&str>, ip: Option<&str>) -> Self {
        let span = tracing::info_span!(
            "routing_decision",
            domain = ?domain,
            ip = ?ip,
            otel.kind = "internal"
        );
        Self {
            _span: span.entered(),
        }
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn new(_domain: Option<&str>, _ip: Option<&str>) -> Self {
        Self {}
    }

    #[cfg(feature = "jaeger")]
    pub fn record_match(&self, rule_type: &str, rule_payload: &str, outbound: &str) {
        tracing::info!(
            rule_type = %rule_type,
            rule_payload = %rule_payload,
            outbound = %outbound,
            "Routing rule matched"
        );
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn record_match(&self, _rule_type: &str, _rule_payload: &str, _outbound: &str) {}
}

pub struct InboundConnectionSpan {
    #[cfg(feature = "jaeger")]
    _span: tracing::span::EnteredSpan,
}

impl InboundConnectionSpan {
    #[cfg(feature = "jaeger")]
    pub fn new(inbound_type: &str, src_addr: &str) -> Self {
        let span = tracing::info_span!(
            "inbound_connection",
            inbound_type = %inbound_type,
            src_addr = %src_addr,
            otel.kind = "server"
        );
        Self {
            _span: span.entered(),
        }
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn new(_inbound_type: &str, _src_addr: &str) -> Self {
        Self {}
    }

    #[cfg(feature = "jaeger")]
    pub fn record_target(&self, target: &str) {
        tracing::Span::current().record("target", target);
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn record_target(&self, _target: &str) {}
}

pub struct OutboundConnectionSpan {
    #[cfg(feature = "jaeger")]
    _span: tracing::span::EnteredSpan,
}

impl OutboundConnectionSpan {
    #[cfg(feature = "jaeger")]
    pub fn new(outbound_type: &str, target: &str) -> Self {
        let span = tracing::info_span!(
            "outbound_connection",
            outbound_type = %outbound_type,
            target = %target,
            otel.kind = "client"
        );
        Self {
            _span: span.entered(),
        }
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn new(_outbound_type: &str, _target: &str) -> Self {
        Self {}
    }

    #[cfg(feature = "jaeger")]
    pub fn record_latency(&self, latency_ms: u64) {
        tracing::Span::current().record("latency_ms", latency_ms);
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn record_latency(&self, _latency_ms: u64) {}

    #[cfg(feature = "jaeger")]
    pub fn record_error(&self, error: &str) {
        tracing::Span::current().record("error", error);
    }

    #[cfg(not(feature = "jaeger"))]
    pub fn record_error(&self, _error: &str) {}
}

#[cfg(feature = "jaeger")]
#[macro_export]
macro_rules! trace_inbound_connection {
    ($inbound_type:expr, $src_addr:expr, $body:expr) => {{
        use tracing::Instrument;
        let span = tracing::info_span!(
            "inbound_connection",
            inbound_type = %$inbound_type,
            src_addr = %$src_addr,
            otel.kind = "server"
        );
        async move { $body }.instrument(span).await
    }};
}

#[cfg(not(feature = "jaeger"))]
#[macro_export]
macro_rules! trace_inbound_connection {
    ($inbound_type:expr, $src_addr:expr, $body:expr) => {{
        $body
    }};
}

#[cfg(feature = "jaeger")]
#[macro_export]
macro_rules! trace_outbound_connection {
    ($outbound_type:expr, $target:expr, $body:expr) => {{
        use tracing::Instrument;
        let span = tracing::info_span!(
            "outbound_connection",
            outbound_type = %$outbound_type,
            target = %$target,
            otel.kind = "client"
        );
        async move { $body }.instrument(span).await
    }};
}

#[cfg(not(feature = "jaeger"))]
#[macro_export]
macro_rules! trace_outbound_connection {
    ($outbound_type:expr, $target:expr, $body:expr) => {{
        $body
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracing_config_default() {
        let config = TracingConfig::default();
        assert!(!config.enabled);
        assert!(config.jaeger_endpoint.is_none());
        assert_eq!(config.service_name, "veloguard");
    }

    #[test]
    fn test_tracing_config_with_jaeger() {
        let config = TracingConfig::new()
            .with_jaeger("http://localhost:4317")
            .with_service_name("test-service");
        
        assert!(config.enabled);
        assert_eq!(config.jaeger_endpoint, Some("http://localhost:4317".to_string()));
        assert_eq!(config.service_name, "test-service");
    }

    #[test]
    fn test_span_creation_without_jaeger() {
        let _dns_span = DnsResolutionSpan::new("example.com");
        let _proxy_span = ProxyConnectionSpan::new("example.com:443", "https");
        let _routing_span = RoutingDecisionSpan::new(Some("example.com"), None);
    }
}
