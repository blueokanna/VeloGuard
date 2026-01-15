use crate::config::Config;
use crate::health_check::{HealthMonitor, HealthStatus};
use crate::proxy::ProxyManager;
use crate::traffic_stats::TrafficStatsManager;
use axum::{
    extract::{Path, State},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// API server state
#[derive(Clone)]
pub struct ApiState {
    pub proxy_manager: Arc<ProxyManager>,
    pub health_monitor: Arc<HealthMonitor>,
    pub traffic_stats: Arc<TrafficStatsManager>,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

/// Server info response
#[derive(Serialize)]
struct ServerInfo {
    version: String,
    uptime: u64,
    active_connections: usize,
}

#[derive(Serialize)]
struct TrafficResponse {
    upload_bytes: u64,
    download_bytes: u64,
    total_bytes: u64,
    connections: u64,
    connection_time_secs: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    tag: String,
    status: String,
    details: Option<String>,
}

/// Proxy info response
#[derive(Serialize)]
struct ProxyInfo {
    tag: String,
    proxy_type: String,
    server: Option<String>,
    port: Option<u16>,
    healthy: bool,
}

/// Config update request
#[derive(Deserialize)]
struct ConfigUpdateRequest {
    config: Config,
}

/// API server
pub struct ApiServer {
    state: ApiState,
    router: Router,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(
        proxy_manager: Arc<ProxyManager>,
        health_monitor: Arc<HealthMonitor>,
        traffic_stats: Arc<TrafficStatsManager>,
    ) -> Self {
        let state = ApiState {
            proxy_manager,
            health_monitor,
            traffic_stats,
        };

        let router = Router::new()
            .route("/api/v1/info", get(get_server_info))
            .route("/api/v1/traffic", get(get_traffic_stats))
            .route("/api/v1/traffic/reset", post(reset_traffic_stats))
            .route("/api/v1/health", get(get_health_status))
            .route("/api/v1/proxies", get(get_proxies))
            .route("/api/v1/proxies/:tag", get(get_proxy))
            .route("/api/v1/config", get(get_config))
            .route("/api/v1/config", post(update_config))
            .route("/api/v1/rules", get(get_rules))
            .with_state(state.clone());

        Self { state, router }
    }

    /// Get the router for embedding in a server
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Get the API state
    pub fn state(&self) -> &ApiState {
        &self.state
    }
}

/// Get server information
async fn get_server_info(State(state): State<ApiState>) -> Json<ApiResponse<ServerInfo>> {
    let active_connections = state.traffic_stats.active_connections();

    Json(ApiResponse::success(ServerInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: 0,
        active_connections,
    }))
}

/// Get traffic statistics
async fn get_traffic_stats(State(state): State<ApiState>) -> Json<ApiResponse<TrafficResponse>> {
    let stats = state.traffic_stats.global_stats();
    Json(ApiResponse::success(TrafficResponse {
        upload_bytes: stats.upload_bytes,
        download_bytes: stats.download_bytes,
        total_bytes: stats.total_bytes(),
        connections: stats.connections,
        connection_time_secs: stats.connection_time_secs,
    }))
}

/// Reset traffic statistics
async fn reset_traffic_stats(State(state): State<ApiState>) -> Json<ApiResponse<String>> {
    state.traffic_stats.reset().await;
    Json(ApiResponse::success("Traffic statistics reset".to_string()))
}

/// Get health status of all proxies
async fn get_health_status(
    State(state): State<ApiState>,
) -> Json<ApiResponse<Vec<HealthResponse>>> {
    let health_statuses = state
        .health_monitor
        .get_all_health()
        .into_iter()
        .map(|(tag, status)| {
            let (status_str, details) = match status {
                HealthStatus::Healthy => ("healthy".to_string(), None),
                HealthStatus::Unhealthy { reason, last_error } => {
                    let details = match (reason, last_error) {
                        (r, Some(e)) => format!("{}: {}", r, e),
                        (r, None) => r,
                    };
                    ("unhealthy".to_string(), Some(details))
                }
                HealthStatus::Unknown => ("unknown".to_string(), None),
            };

            HealthResponse {
                tag,
                status: status_str,
                details,
            }
        })
        .collect();

    Json(ApiResponse::success(health_statuses))
}

/// Get all proxies
async fn get_proxies(State(state): State<ApiState>) -> Json<ApiResponse<Vec<ProxyInfo>>> {
    let config = state.proxy_manager.get_config().await;
    let proxies = config
        .outbounds
        .into_iter()
        .map(|outbound| {
            let healthy = state
                .health_monitor
                .get_health(&outbound.tag)
                .map(|status| matches!(status, HealthStatus::Healthy))
                .unwrap_or(false);

            ProxyInfo {
                tag: outbound.tag,
                proxy_type: format!("{:?}", outbound.outbound_type),
                server: outbound.server,
                port: outbound.port,
                healthy,
            }
        })
        .collect();

    Json(ApiResponse::success(proxies))
}

/// Get specific proxy information
async fn get_proxy(
    State(state): State<ApiState>,
    Path(tag): Path<String>,
) -> Json<ApiResponse<ProxyInfo>> {
    let config = state.proxy_manager.get_config().await;

    if let Some(outbound) = config.outbounds.into_iter().find(|o| o.tag == tag) {
        let healthy = state
            .health_monitor
            .get_health(&outbound.tag)
            .map(|status| matches!(status, HealthStatus::Healthy))
            .unwrap_or(false);

        Json(ApiResponse::success(ProxyInfo {
            tag: outbound.tag,
            proxy_type: format!("{:?}", outbound.outbound_type),
            server: outbound.server,
            port: outbound.port,
            healthy,
        }))
    } else {
        Json(ApiResponse::error(format!("Proxy '{}' not found", tag)))
    }
}

/// Get current configuration
async fn get_config(State(state): State<ApiState>) -> Json<ApiResponse<Config>> {
    let config = state.proxy_manager.get_config().await;
    Json(ApiResponse::success(config))
}

/// Update configuration
async fn update_config(
    State(state): State<ApiState>,
    Json(request): Json<ConfigUpdateRequest>,
) -> Json<ApiResponse<String>> {
    match state.proxy_manager.reload(request.config).await {
        Ok(()) => Json(ApiResponse::success(
            "Configuration updated successfully".to_string(),
        )),
        Err(e) => Json(ApiResponse::error(format!(
            "Failed to update configuration: {}",
            e
        ))),
    }
}

/// Get routing rules
async fn get_rules(State(state): State<ApiState>) -> Json<ApiResponse<Vec<serde_json::Value>>> {
    let config = state.proxy_manager.get_config().await;
    let rules = config
        .rules
        .into_iter()
        .map(|rule| {
            serde_json::json!({
                "type": format!("{:?}", rule.rule_type),
                "payload": rule.payload,
                "outbound": rule.outbound,
                "process_name": rule.process_name,
            })
        })
        .collect();

    Json(ApiResponse::success(rules))
}

/// Create API router for embedding
pub fn create_router(
    proxy_manager: Arc<ProxyManager>,
    health_monitor: Arc<HealthMonitor>,
    traffic_stats: Arc<TrafficStatsManager>,
) -> Router {
    let api_server = ApiServer::new(proxy_manager, health_monitor, traffic_stats);
    api_server.router()
}
