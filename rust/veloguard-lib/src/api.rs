use crate::error::{Result, VeloGuardError};
use crate::logging::FlutterLogLayer;
use crate::types::*;
use crate::{get_veloguard_instance, VELOGUARD_INSTANCE};
use flutter_rust_bridge::frb;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use veloguard_core::Config;

static TRACING_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
    if TRACING_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let _ = init_tracing_safe();
    }
}

fn init_tracing_safe() -> std::result::Result<(), ()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(
            "debug,veloguard_core=debug,veloguard_lib=debug,veloguard_netstack=debug,hyper=warn,tokio=warn,rustls=warn"
        ));

    let flutter_log_layer = FlutterLogLayer;
    #[cfg(target_os = "android")]
    {
        let android_layer =
            tracing_android::layer("VeloGuard").expect("Failed to create Android tracing layer");

        let result = tracing_subscriber::registry()
            .with(filter)
            .with(android_layer)
            .with(flutter_log_layer)
            .try_init();

        if result.is_ok() {
            tracing::info!("VeloGuard FFI bridge initialized (Android) - logs visible in logcat and Flutter UI");
        }
        result.map_err(|_| ())
    }

    #[cfg(not(target_os = "android"))]
    {
        use tracing_subscriber::fmt;
        let result = tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_thread_ids(true),
            )
            .with(flutter_log_layer)
            .try_init();

        if result.is_ok() {
            tracing::info!("VeloGuard FFI bridge initialized");
        }
        result.map_err(|_| ())
    }
}

// ============== Proxy Control API (Design Document Compliant) ==============
#[frb]
pub async fn start_proxy_from_yaml(yaml_config: String) -> std::result::Result<(), String> {
    tracing::info!("Starting proxy from YAML config...");

    let config: Config =
        serde_yaml::from_str(&yaml_config).map_err(|e| format!("Invalid YAML config: {}", e))?;
    {
        let mut instance = VELOGUARD_INSTANCE.write().await;
        if let Some(ref veloguard) = *instance {
            tracing::info!("Stopping existing VeloGuard instance before re-initialization");
            if let Err(e) = veloguard.stop().await {
                tracing::warn!("Error stopping existing instance: {}", e);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
        *instance = None;
    }

    let veloguard = veloguard_core::VeloGuard::new(config)
        .await
        .map_err(|e| format!("Failed to create VeloGuard: {}", e))?;

    veloguard
        .start()
        .await
        .map_err(|e| format!("Failed to start proxy: {}", e))?;

    let mut instance = VELOGUARD_INSTANCE.write().await;
    *instance = Some(veloguard);

    tracing::info!("Proxy started successfully from YAML config");
    Ok(())
}

#[frb]
pub async fn start_proxy_from_file(config_path: String) -> std::result::Result<(), String> {
    tracing::info!("Starting proxy from file: {}", config_path);

    let yaml_content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config file '{}': {}", config_path, e))?;
    start_proxy_from_yaml(yaml_content).await
}

#[frb]
pub async fn stop_proxy() -> std::result::Result<(), String> {
    tracing::info!("Stopping proxy and VPN service...");

    // 步骤 1: 停止代理核心（先停止代理，避免新连接）
    {
        let instance = get_veloguard_instance()
            .await
            .map_err(|e| format!("Failed to get instance: {}", e))?;
        let veloguard_guard = instance.read().await;

        if let Some(veloguard) = veloguard_guard.as_ref() {
            tracing::info!("Stopping proxy core...");
            veloguard
                .stop()
                .await
                .map_err(|e| format!("Failed to stop proxy: {}", e))?;
            tracing::info!("Proxy core stopped");
        } else {
            tracing::warn!("Proxy was not running");
        }
    }

    // 步骤 2: 断开VPN连接（Android和Windows）
    #[cfg(target_os = "android")]
    {
        tracing::info!("Disconnecting Android VPN...");
        veloguard_netstack::clear_android_vpn_fd();
        if let Some(processor) = crate::get_android_vpn_processor() {
            processor.stop();
            processor.reset();
        }
        crate::clear_android_vpn_processor();
        tracing::info!("Android VPN disconnected");
    }

    #[cfg(windows)]
    {
        tracing::info!("Disconnecting Windows VPN (TUN mode)...");
        if let Some(processor) = crate::get_windows_vpn_processor() {
            processor.stop();
            processor.reset();
        }
        crate::clear_windows_vpn_processor();
        
        if let Some(mut route_manager) = crate::get_windows_route_manager_mut() {
            let _ = route_manager.disable_global_mode();
        }
        crate::clear_windows_route_manager();
        
        if let Some(mut tun_device) = crate::take_windows_tun_device() {
            let _ = tun_device.stop().await;
        }
        tracing::info!("Windows VPN (TUN mode) disconnected");
    }

    // 步骤 3: 重置连接追踪器
    let tracker = veloguard_core::connection_tracker::global_tracker();
    tracker.reset();
    tracing::info!("Connection tracker reset");
    
    // 步骤 4: 等待清理完成
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // 步骤 5: 清理实例
    {
        let mut instance = VELOGUARD_INSTANCE.write().await;
        *instance = None;
    }

    // 步骤 6: 重置代理模式
    veloguard_core::set_runtime_proxy_mode(0);
    #[cfg(target_os = "android")]
    {
        veloguard_netstack::set_android_proxy_mode(0);
    }
    #[cfg(windows)]
    {
        veloguard_netstack::set_windows_proxy_mode(0);
    }

    tracing::info!("✓ Proxy and VPN service stopped successfully");
    Ok(())
}

#[frb]
pub async fn is_proxy_running() -> std::result::Result<bool, String> {
    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        veloguard
            .is_running()
            .await
            .map_err(|e| format!("Failed to check running status: {}", e))
    } else {
        Ok(false)
    }
}

#[frb]
pub async fn reload_config_from_yaml(yaml_config: String) -> std::result::Result<(), String> {
    tracing::info!("Reloading config from YAML...");
    let config: Config =
        serde_yaml::from_str(&yaml_config).map_err(|e| format!("Invalid YAML config: {}", e))?;

    // Validate configuration before applying
    config.validate().map_err(|e| format!("Configuration validation failed: {}", e))?;

    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let mut veloguard_guard = instance.write().await;

    if let Some(veloguard) = veloguard_guard.as_mut() {
        veloguard
            .reload(config)
            .await
            .map_err(|e| format!("Failed to reload config: {}", e))?;
        tracing::info!("Config reloaded successfully");
        Ok(())
    } else {
        Err("Proxy not initialized".to_string())
    }
}

#[frb]
pub async fn reload_config_from_file(config_path: String) -> std::result::Result<(), String> {
    tracing::info!("Reloading config from file: {}", config_path);
    let yaml_content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config file '{}': {}", config_path, e))?;

    reload_config_from_yaml(yaml_content).await
}

// ============== Clash Configuration Compatibility API ==============

/// Start proxy from a Clash-format configuration file
/// This automatically converts Clash config to VeloGuard format
#[frb]
pub async fn start_proxy_from_clash_yaml(clash_yaml: String) -> std::result::Result<(), String> {
    tracing::info!("Starting proxy from Clash config...");
    
    let config = veloguard_core::config::parse_clash_config(&clash_yaml)
        .map_err(|e| format!("Failed to parse Clash config: {}", e))?;
    
    // Validate the converted config
    config.validate().map_err(|e| format!("Configuration validation failed: {}", e))?;
    
    {
        let mut instance = VELOGUARD_INSTANCE.write().await;
        if let Some(ref veloguard) = *instance {
            tracing::info!("Stopping existing VeloGuard instance before re-initialization");
            if let Err(e) = veloguard.stop().await {
                tracing::warn!("Error stopping existing instance: {}", e);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
        *instance = None;
    }

    let veloguard = veloguard_core::VeloGuard::new(config)
        .await
        .map_err(|e| format!("Failed to create VeloGuard: {}", e))?;

    veloguard
        .start()
        .await
        .map_err(|e| format!("Failed to start proxy: {}", e))?;

    let mut instance = VELOGUARD_INSTANCE.write().await;
    *instance = Some(veloguard);

    tracing::info!("Proxy started successfully from Clash config");
    Ok(())
}

/// Start proxy from a Clash-format configuration file
#[frb]
pub async fn start_proxy_from_clash_file(config_path: String) -> std::result::Result<(), String> {
    tracing::info!("Starting proxy from Clash file: {}", config_path);
    
    let yaml_content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config file '{}': {}", config_path, e))?;
    
    start_proxy_from_clash_yaml(yaml_content).await
}

/// Reload configuration from a Clash-format YAML string
#[frb]
pub async fn reload_config_from_clash_yaml(clash_yaml: String) -> std::result::Result<(), String> {
    tracing::info!("Reloading config from Clash YAML...");
    
    let config = veloguard_core::config::parse_clash_config(&clash_yaml)
        .map_err(|e| format!("Failed to parse Clash config: {}", e))?;
    
    // Validate the converted config
    config.validate().map_err(|e| format!("Configuration validation failed: {}", e))?;

    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let mut veloguard_guard = instance.write().await;

    if let Some(veloguard) = veloguard_guard.as_mut() {
        veloguard
            .reload(config)
            .await
            .map_err(|e| format!("Failed to reload config: {}", e))?;
        tracing::info!("Config reloaded successfully from Clash format");
        Ok(())
    } else {
        Err("Proxy not initialized".to_string())
    }
}

/// Reload configuration from a Clash-format file
#[frb]
pub async fn reload_config_from_clash_file(config_path: String) -> std::result::Result<(), String> {
    tracing::info!("Reloading config from Clash file: {}", config_path);
    
    let yaml_content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config file '{}': {}", config_path, e))?;
    
    reload_config_from_clash_yaml(yaml_content).await
}

/// Download and start proxy from a subscription URL
/// This fetches the Clash config from the URL and starts the proxy
#[frb]
pub async fn start_proxy_from_url(url: String) -> std::result::Result<(), String> {
    tracing::info!("Downloading config from URL: {}", url);
    
    // Download config from URL
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    
    let response = client.get(&url)
        .header("User-Agent", veloguard_core::USER_AGENT)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch config from URL: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()));
    }
    
    let yaml_content = response.text()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;
    
    tracing::info!("Downloaded {} bytes of config", yaml_content.len());
    
    // Start proxy with the downloaded config
    start_proxy_from_clash_yaml(yaml_content).await
}

/// Download config from URL and return the YAML content
/// Useful for saving the config locally before starting
#[frb]
pub async fn download_config_from_url(url: String) -> std::result::Result<String, String> {
    tracing::info!("Downloading config from URL: {}", url);
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    
    let response = client.get(&url)
        .header("User-Agent", veloguard_core::USER_AGENT)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch config from URL: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()));
    }
    
    let yaml_content = response.text()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;
    
    tracing::info!("Downloaded {} bytes of config", yaml_content.len());
    Ok(yaml_content)
}

/// Convert a Clash config to VeloGuard format (for debugging/preview)
#[frb]
pub fn convert_clash_to_veloguard(clash_yaml: String) -> std::result::Result<String, String> {
    let config = veloguard_core::config::parse_clash_config(&clash_yaml)
        .map_err(|e| format!("Failed to parse Clash config: {}", e))?;
    
    serde_yaml::to_string(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))
}

// ============== Traffic Statistics API (Design Document Compliant) ==============
#[frb]
pub async fn get_traffic_stats_dto() -> std::result::Result<TrafficStatsDto, String> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    tracker.update_speed();

    #[cfg(target_os = "android")]
    {
        if let Some(processor) = crate::get_android_vpn_processor() {
            let vpn_stats = processor.get_traffic_stats();
            return Ok(TrafficStatsDto {
                upload: vpn_stats.bytes_received,
                download: vpn_stats.bytes_sent,
                total_upload: vpn_stats.bytes_received,
                total_download: vpn_stats.bytes_sent,
                connection_count: (vpn_stats.tcp_connections + vpn_stats.udp_sessions) as u32,
                uptime_secs: 0,
            });
        }
    }
    let uptime_secs = {
        let instance = get_veloguard_instance()
            .await
            .map_err(|e| format!("Failed to get instance: {}", e))?;
        let guard = instance.read().await;
        guard.as_ref().map(|v| v.uptime_secs()).unwrap_or(0)
    };

    Ok(TrafficStatsDto {
        upload: tracker.total_upload(),
        download: tracker.total_download(),
        total_upload: tracker.total_upload(),
        total_download: tracker.total_download(),
        connection_count: tracker.active_count() as u32,
        uptime_secs,
    })
}

#[frb]
pub async fn get_connections_dto() -> std::result::Result<Vec<ConnectionDto>, String> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    let connections = tracker.get_all();

    let result: Vec<ConnectionDto> = connections
        .iter()
        .map(|conn| ConnectionDto {
            id: conn.id.clone(),
            src_addr: format!("{}:{}", conn.host, conn.destination_port),
            dst_addr: conn.destination_ip.clone().unwrap_or_default(),
            dst_domain: Some(conn.host.clone()),
            protocol: conn.protocol.clone(),
            outbound: conn.outbound_tag.clone(),
            upload: conn.get_upload(),
            download: conn.get_download(),
            start_time: conn.start_timestamp as i64,
            rule: Some(conn.rule.clone()),
        })
        .collect();

    Ok(result)
}

#[frb]
pub async fn close_connection_by_id(id: String) -> std::result::Result<(), String> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    if tracker.close_connection(&id) {
        tracing::info!("Connection {} closed", id);
        Ok(())
    } else {
        Err(format!("Connection {} not found", id))
    }
}

#[frb]
pub async fn close_all_connections_dto() -> std::result::Result<(), String> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    tracker.close_all();
    tracing::info!("All connections closed");
    Ok(())
}

// ============== Proxy Management API (Design Document Compliant) ==============
#[frb]
pub async fn get_proxies() -> std::result::Result<Vec<ProxyInfoDto>, String> {
    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let guard = instance.read().await;

    if let Some(veloguard) = guard.as_ref() {
        let config = veloguard.config();
        let proxy_manager = veloguard.proxy_manager();
        let outbound_manager = proxy_manager.outbound_manager();

        let mut result = Vec::new();
        for outbound_config in &config.outbounds {
            let tag = &outbound_config.tag;
            let protocol_type = format!("{:?}", outbound_config.outbound_type).to_lowercase();
            let (server, port) = if let Some(proxy) = outbound_manager.get_proxy(tag) {
                proxy
                    .server_addr()
                    .map(|(s, p)| (Some(s), Some(p)))
                    .unwrap_or((outbound_config.server.clone(), outbound_config.port))
            } else {
                (outbound_config.server.clone(), outbound_config.port)
            };

            result.push(ProxyInfoDto {
                tag: tag.clone(),
                protocol_type,
                server,
                port,
                latency_ms: None,
                alive: true,
            });
        }

        Ok(result)
    } else {
        Err("Proxy not initialized".to_string())
    }
}

#[frb]
pub async fn get_proxy_groups() -> std::result::Result<Vec<ProxyGroupDto>, String> {
    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let guard = instance.read().await;

    if let Some(veloguard) = guard.as_ref() {
        let config = veloguard.config();
        let mut groups = Vec::new();

        for outbound in &config.outbounds {
            let group_type = match outbound.outbound_type {
                veloguard_core::OutboundType::Selector => "selector",
                veloguard_core::OutboundType::Urltest => "url-test",
                veloguard_core::OutboundType::Fallback => "fallback",
                veloguard_core::OutboundType::Loadbalance => "load-balance",
                veloguard_core::OutboundType::Relay => "relay",
                _ => continue,
            };

            let proxies: Vec<String> = outbound
                .options
                .get("proxies")
                .and_then(|v| v.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let selected = proxies.first().cloned().unwrap_or_default();

            groups.push(ProxyGroupDto {
                tag: outbound.tag.clone(),
                group_type: group_type.to_string(),
                proxies,
                selected,
            });
        }

        Ok(groups)
    } else {
        Err("Proxy not initialized".to_string())
    }
}

#[frb]
pub async fn select_proxy(group_tag: String, proxy_tag: String) -> std::result::Result<(), String> {
    tracing::info!(
        "Selecting proxy: group='{}', proxy='{}'",
        group_tag,
        proxy_tag
    );

    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let guard = instance.read().await;

    if let Some(veloguard) = guard.as_ref() {
        let proxy_manager = veloguard.proxy_manager();
        let outbound_manager = proxy_manager.outbound_manager();
        if outbound_manager.get_proxy(&group_tag).is_none() {
            return Err(format!("Proxy group '{}' not found", group_tag));
        }

        outbound_manager
            .set_selector_proxy(&group_tag, &proxy_tag)
            .await
            .map_err(|e| format!("Failed to set proxy selection: {}", e))?;

        tracing::info!("Proxy selection updated: {} -> {}", group_tag, proxy_tag);
        Ok(())
    } else {
        Err("Proxy not initialized".to_string())
    }
}

#[frb]
pub async fn test_proxy_latency_dto(
    tag: String,
    test_url: String,
    timeout_ms: u64,
) -> std::result::Result<u64, String> {
    use tokio::time::Duration;

    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let guard = instance.read().await;
    if let Some(veloguard) = guard.as_ref() {
        let proxy_manager = veloguard.proxy_manager();

        if let Some(proxy) = proxy_manager.outbound_manager().get_proxy(&tag) {
            let timeout = Duration::from_millis(timeout_ms);
            match proxy.test_http_latency(&test_url, timeout).await {
                Ok(duration) => Ok(duration.as_millis() as u64),
                Err(e) => Err(format!("Latency test failed: {}", e)),
            }
        } else {
            Err(format!("Proxy '{}' not found", tag))
        }
    } else {
        Err("Proxy not initialized".to_string())
    }
}

#[frb]
pub async fn test_all_proxies_latency(
    test_url: String,
    timeout_ms: u64,
) -> std::result::Result<Vec<ProxyLatencyDto>, String> {
    use futures::future::join_all;
    use tokio::time::Duration;

    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let guard = instance.read().await;

    if let Some(veloguard) = guard.as_ref() {
        let proxy_manager = veloguard.proxy_manager();
        let outbound_manager = proxy_manager.outbound_manager();
        let tags = outbound_manager.get_all_tags();
        let timeout = Duration::from_millis(timeout_ms);

        let mut futures = Vec::new();
        for tag in tags {
            if let Some(proxy) = outbound_manager.get_proxy(&tag) {
                let url = test_url.clone();
                futures.push(async move {
                    match proxy.test_http_latency(&url, timeout).await {
                        Ok(duration) => ProxyLatencyDto {
                            tag,
                            latency_ms: Some(duration.as_millis() as u64),
                            error: None,
                        },
                        Err(e) => ProxyLatencyDto {
                            tag,
                            latency_ms: None,
                            error: Some(e.to_string()),
                        },
                    }
                });
            }
        }

        let results = join_all(futures).await;
        Ok(results)
    } else {
        Err("Proxy not initialized".to_string())
    }
}

// ============== Configuration Query API (Design Document Compliant) ==============
#[frb]
pub async fn get_rules() -> std::result::Result<Vec<RuleDto>, String> {
    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let guard = instance.read().await;

    if let Some(veloguard) = guard.as_ref() {
        let config = veloguard.config();

        let rules: Vec<RuleDto> = config
            .rules
            .iter()
            .map(|rule| RuleDto {
                rule_type: format!("{:?}", rule.rule_type).to_lowercase(),
                payload: rule.payload.clone(),
                outbound: rule.outbound.clone(),
                matched_count: 0,
            })
            .collect();

        Ok(rules)
    } else {
        Err("Proxy not initialized".to_string())
    }
}

#[frb]
pub async fn get_dns_config() -> std::result::Result<DnsConfigDto, String> {
    let instance = get_veloguard_instance()
        .await
        .map_err(|e| format!("Failed to get instance: {}", e))?;
    let guard = instance.read().await;

    if let Some(veloguard) = guard.as_ref() {
        let config = veloguard.config();
        Ok(DnsConfigDto {
            enable: config.dns.enable,
            listen: config.dns.listen.clone(),
            enhanced_mode: format!("{:?}", config.dns.enhanced_mode).to_lowercase(),
            nameservers: config.dns.nameservers.clone(),
            fallback: config.dns.fallback.clone(),
        })
    } else {
        Err("Proxy not initialized".to_string())
    }
}

#[frb]
pub async fn set_proxy_mode(mode: i32) -> std::result::Result<(), String> {
    veloguard_core::set_runtime_proxy_mode(mode);

    #[cfg(target_os = "android")]
    {
        veloguard_netstack::set_android_proxy_mode(mode);
    }

    #[cfg(windows)]
    {
        veloguard_netstack::set_windows_proxy_mode(mode);
    }

    let mode_str = match mode {
        1 => "global",
        2 => "direct",
        3 => "rule",
        _ => "config",
    };
    tracing::info!("Proxy mode set to {} ({})", mode_str, mode);
    Ok(())
}

#[frb]
pub async fn get_proxy_mode() -> std::result::Result<i32, String> {
    Ok(veloguard_core::get_runtime_proxy_mode())
}

// ============== Platform-Specific API (Design Document Compliant) ==============
#[frb]
pub fn set_vpn_fd(fd: i32) {
    #[cfg(target_os = "android")]
    {
        veloguard_netstack::set_android_vpn_fd(fd);
        tracing::info!("VPN fd set to {}", fd);
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = fd;
        tracing::warn!("set_vpn_fd called on non-Android platform");
    }
}
#[frb]
pub fn clear_vpn_fd() {
    #[cfg(target_os = "android")]
    {
        veloguard_netstack::clear_android_vpn_fd();
        tracing::info!("VPN fd cleared");
    }

    #[cfg(not(target_os = "android"))]
    {
        tracing::warn!("clear_vpn_fd called on non-Android platform");
    }
}
#[frb]
pub fn set_protect_socket_callback_enabled(enabled: bool) {
    #[cfg(target_os = "android")]
    {
        if enabled {
            tracing::info!("Socket protect callback enabled");
        } else {
            veloguard_netstack::clear_protect_callback();
            tracing::info!("Socket protect callback disabled");
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = enabled;
        tracing::warn!("set_protect_socket_callback called on non-Android platform");
    }
}

#[frb]
pub async fn start_tun_mode(
    tun_name: String,
    tun_address: String,
    tun_netmask: String,
) -> std::result::Result<(), String> {
    #[cfg(windows)]
    {
        use veloguard_netstack::{TunConfig, TunDevice};
        tracing::info!(
            "Starting TUN mode: name={}, address={}, netmask={}",
            tun_name,
            tun_address,
            tun_netmask
        );

        let address: std::net::Ipv4Addr = tun_address
            .parse()
            .map_err(|e| format!("Invalid TUN address: {}", e))?;
        let netmask: std::net::Ipv4Addr = tun_netmask
            .parse()
            .map_err(|e| format!("Invalid TUN netmask: {}", e))?;

        veloguard_netstack::ensure_wintun()
            .await
            .map_err(|e| format!("Failed to load wintun.dll: {}", e))?;
        let config = TunConfig {
            name: tun_name,
            address,
            netmask,
            mtu: 1500,
            gateway: Some(address),
            dns: vec![std::net::Ipv4Addr::new(198, 18, 0, 2)],
        };

        let mut tun = TunDevice::with_config(config)
            .await
            .map_err(|e| format!("Failed to create TUN device: {}", e))?;

        tun.start()
            .await
            .map_err(|e| format!("Failed to start TUN device: {}", e))?;

        crate::set_windows_tun_device(tun);
        tracing::info!("TUN mode started successfully");
        Ok(())
    }

    #[cfg(not(windows))]
    {
        (tun_name, tun_address, tun_netmask);
        Err("TUN mode is only supported on Windows".to_string())
    }
}

#[frb]
pub async fn stop_tun_mode() -> std::result::Result<(), String> {
    #[cfg(windows)]
    {
        tracing::info!("Stopping TUN mode...");

        if let Some(processor) = crate::get_windows_vpn_processor() {
            processor.stop();
            processor.reset();
        }
        crate::clear_windows_vpn_processor();
        if let Some(mut route_manager) = crate::get_windows_route_manager_mut() {
            let _ = route_manager.disable_global_mode();
        }
        crate::clear_windows_route_manager();
        if let Some(mut tun_device) = crate::take_windows_tun_device() {
            tun_device
                .stop()
                .await
                .map_err(|e| format!("Failed to stop TUN device: {}", e))?;
        }

        veloguard_core::set_runtime_proxy_mode(0);
        veloguard_netstack::set_windows_proxy_mode(0);

        tracing::info!("TUN mode stopped successfully");
        Ok(())
    }

    #[cfg(not(windows))]
    {
        Err("TUN mode is only supported on Windows".to_string())
    }
}

#[frb]
pub async fn initialize_veloguard(config_json: String) -> Result<()> {
    tracing::info!("Initializing veloguard...");

    let config: VeloGuardConfig = serde_json::from_str(&config_json)
        .map_err(|e| VeloGuardError::Parse(format!("Invalid config JSON: {}", e)))?;
    let core_config = convert_ffi_config_to_core(config)?;

    {
        let mut instance = VELOGUARD_INSTANCE.write().await;
        if let Some(ref veloguard) = *instance {
            tracing::info!("Stopping existing VeloGuard instance before re-initialization");
            if let Err(e) = veloguard.stop().await {
                tracing::warn!("Error stopping existing instance: {}", e);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
        *instance = None;
    }

    let veloguard = veloguard_core::VeloGuard::new(core_config)
        .await
        .map_err(VeloGuardError::from)?;

    let mut instance = VELOGUARD_INSTANCE.write().await;
    *instance = Some(veloguard);

    tracing::info!("VeloGuard initialized successfully");
    Ok(())
}

#[frb]
pub async fn start_veloguard() -> Result<()> {
    tracing::info!("Starting VeloGuard proxy server...");

    let instance = get_veloguard_instance().await?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        veloguard.start().await.map_err(VeloGuardError::from)?;
        tracing::info!("VeloGuard proxy server started successfully");
    } else {
        return Err(VeloGuardError::Internal(
            "VeloGuard not initialized".to_string(),
        ));
    }

    Ok(())
}

#[frb]
pub async fn stop_veloguard() -> Result<()> {
    tracing::info!("Stopping VeloGuard proxy server...");

    let tracker = veloguard_core::connection_tracker::global_tracker();
    tracker.reset();
    tracing::info!("Connection tracker reset");
    {
        let instance = get_veloguard_instance().await?;
        let veloguard_guard = instance.read().await;

        if let Some(veloguard) = veloguard_guard.as_ref() {
            veloguard.stop().await.map_err(VeloGuardError::from)?;
        } else {
            tracing::warn!("VeloGuard was not initialized, nothing to stop");
            return Ok(());
        }
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    {
        let mut instance = VELOGUARD_INSTANCE.write().await;
        *instance = None;
    }

    tracing::info!("VeloGuard proxy server stopped successfully");
    Ok(())
}

#[frb]
pub async fn reload_veloguard(config_json: String) -> Result<()> {
    let config: VeloGuardConfig = serde_json::from_str(&config_json)
        .map_err(|e| VeloGuardError::Parse(format!("Invalid config JSON: {}", e)))?;

    let core_config = convert_ffi_config_to_core(config)?;

    let instance = get_veloguard_instance().await?;
    let mut veloguard_guard = instance.write().await;

    if let Some(veloguard) = veloguard_guard.as_mut() {
        veloguard
            .reload(core_config)
            .await
            .map_err(VeloGuardError::from)?;
    } else {
        return Err(VeloGuardError::Internal(
            "VeloGuard not initialized".to_string(),
        ));
    }

    Ok(())
}

#[frb]
pub async fn get_veloguard_status() -> Result<ProxyStatus> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

    let instance = get_veloguard_instance().await?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        let tracker = veloguard_core::connection_tracker::global_tracker();
        let config = veloguard.config();

        let memory_usage = {
            let mut sys = System::new_with_specifics(
                RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
            );
            let pid = Pid::from_u32(std::process::id());
            sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
            sys.process(pid).map(|p| p.memory()).unwrap_or(0)
        };

        let uptime = veloguard.uptime_secs();
        let connection_count = {
            let base_count = tracker.active_count() as u32;
            #[cfg(target_os = "android")]
            {
                if let Some(processor) = crate::get_android_vpn_processor() {
                    let vpn_stats = processor.get_traffic_stats();
                    let vpn_connections =
                        (vpn_stats.tcp_connections + vpn_stats.udp_sessions) as u32;
                    base_count.max(vpn_connections)
                } else {
                    base_count
                }
            }
            #[cfg(not(target_os = "android"))]
            {
                base_count
            }
        };

        Ok(ProxyStatus {
            running: veloguard.is_running().await.unwrap_or(false),
            inbound_count: config.inbounds.len() as u32,
            outbound_count: config.outbounds.len() as u32,
            connection_count,
            memory_usage,
            uptime,
        })
    } else {
        Ok(ProxyStatus {
            running: false,
            inbound_count: 0,
            outbound_count: 0,
            connection_count: 0,
            memory_usage: 0,
            uptime: 0,
        })
    }
}

#[frb]
pub async fn get_traffic_stats() -> Result<TrafficStats> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    tracker.update_speed();
    #[cfg(target_os = "android")]
    {
        if let Some(processor) = crate::get_android_vpn_processor() {
            let vpn_stats = processor.get_traffic_stats();
            return Ok(TrafficStats {
                upload: vpn_stats.bytes_received,
                download: vpn_stats.bytes_sent,
                upload_speed: tracker.upload_speed(),
                download_speed: tracker.download_speed(),
            });
        }
    }

    Ok(TrafficStats {
        upload: tracker.total_upload(),
        download: tracker.total_download(),
        upload_speed: tracker.upload_speed(),
        download_speed: tracker.download_speed(),
    })
}

#[frb]
pub async fn test_config(config_json: String) -> Result<bool> {
    let config: VeloGuardConfig = serde_json::from_str(&config_json)
        .map_err(|e| VeloGuardError::Parse(format!("Invalid config JSON: {}", e)))?;

    let core_config = convert_ffi_config_to_core(config)?;
    match veloguard_core::VeloGuard::new(core_config).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[frb]
pub async fn get_connections() -> Result<Vec<ConnectionInfo>> {
    let instance = get_veloguard_instance().await?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        veloguard.traffic_stats().active_connections();
        Ok(vec![])
    } else {
        Ok(vec![])
    }
}

#[frb]
pub async fn close_connection(_connection_id: String) -> Result<()> {
    Ok(())
}

#[frb]
pub async fn get_logs(lines: Option<u32>) -> Result<Vec<String>> {
    let max_lines = lines.unwrap_or(100) as usize;
    let logs = veloguard_core::logging::get_recent_logs(max_lines);
    if logs.is_empty() {
        Ok(vec![
            "[INFO] VeloGuard log buffer initialized. Logs will appear here.".to_string(),
        ])
    } else {
        Ok(logs)
    }
}

#[frb]
pub async fn set_log_level(level: String) -> Result<()> {
    match level.to_lowercase().as_str() {
        "error" => tracing::Level::ERROR,
        "warn" | "warning" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => {
            return Err(VeloGuardError::Parse(format!(
                "Invalid log level: {}",
                level
            )))
        }
    };

    tracing::info!("Log level change requested: {}", level);
    Ok(())
}

#[frb]
pub async fn get_system_info() -> Result<SystemInfo> {
    use sysinfo::System;

    let platform = if cfg!(target_os = "windows") {
        "Windows".to_string()
    } else if cfg!(target_os = "linux") {
        "Linux".to_string()
    } else if cfg!(target_os = "macos") {
        "macOS".to_string()
    } else if cfg!(target_os = "ios") {
        "iOS".to_string()
    } else if cfg!(target_os = "android") {
        "Android".to_string()
    } else {
        "Unknown".to_string()
    };

    let version = env!("CARGO_PKG_VERSION").to_string();

    let mut sys = System::new_all();
    sys.refresh_all();

    let memory_total = sys.total_memory();
    let memory_used = sys.used_memory();
    let cpu_threads = sys.cpus().len() as u32;
    let cpu_cores = System::physical_core_count()
        .map(|c| c as u32)
        .unwrap_or(cpu_threads);

    let cpu_name = get_cpu_name(&sys);
    let cpu_usage = if sys.cpus().is_empty() {
        0.0
    } else {
        sys.cpus()
            .iter()
            .map(|cpu| cpu.cpu_usage() as f64)
            .sum::<f64>()
            / sys.cpus().len() as f64
    };

    Ok(SystemInfo {
        platform,
        version,
        memory_total,
        memory_used,
        cpu_cores,
        cpu_threads,
        cpu_name,
        cpu_usage,
    })
}

fn get_cpu_name(sys: &sysinfo::System) -> String {
    let sysinfo_name = sys
        .cpus()
        .first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_default();

    if !sysinfo_name.is_empty() && sysinfo_name != "Unknown" && !sysinfo_name.contains("Unknown") {
        return sysinfo_name;
    }

    #[cfg(target_os = "android")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("Hardware") {
                    if let Some(value) = line.split(':').nth(1) {
                        let name = value.trim();
                        if !name.is_empty() {
                            return name.to_string();
                        }
                    }
                }
            }
            for line in cpuinfo.lines() {
                if line.starts_with("model name") {
                    if let Some(value) = line.split(':').nth(1) {
                        let name = value.trim();
                        if !name.is_empty() {
                            return name.to_string();
                        }
                    }
                }
            }
            for line in cpuinfo.lines() {
                if line.starts_with("Processor") && !line.starts_with("Processors") {
                    if let Some(value) = line.split(':').nth(1) {
                        let name = value.trim();
                        if !name.is_empty() {
                            return name.to_string();
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("model name") {
                    if let Some(value) = line.split(':').nth(1) {
                        let name = value.trim();
                        if !name.is_empty() {
                            return name.to_string();
                        }
                    }
                }
            }
        }
    }
    if !sysinfo_name.is_empty() {
        sysinfo_name
    } else {
        "Unknown CPU".to_string()
    }
}

#[frb]
pub fn get_version() -> String {
    format!("VeloGuard v{}", env!("CARGO_PKG_VERSION"))
}

/// Get build information
#[frb]
pub fn get_build_info() -> String {
    let target = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "android") {
        "android"
    } else {
        "unknown"
    };
    format!(
        "VeloGuard v{}\nBuilt with Rust\nTarget: {}",
        env!("CARGO_PKG_VERSION"),
        target
    )
}

fn convert_ffi_config_to_core(ffi_config: VeloGuardConfig) -> Result<Config> {
    use veloguard_core::config::*;
    let general = GeneralConfig {
        port: ffi_config.general.port,
        socks_port: ffi_config.general.socks_port,
        redir_port: ffi_config.general.redir_port,
        tproxy_port: ffi_config.general.tproxy_port,
        mixed_port: ffi_config.general.mixed_port,
        authentication: ffi_config.general.authentication.map(|auths| {
            auths
                .into_iter()
                .map(|auth| AuthenticationConfig {
                    username: auth.username,
                    password: auth.password,
                })
                .collect()
        }),
        allow_lan: ffi_config.general.allow_lan,
        bind_address: ffi_config.general.bind_address,
        mode: match ffi_config.general.mode.as_str() {
            "global" => Mode::Global,
            "direct" => Mode::Direct,
            _ => Mode::Rule,
        },
        log_level: match ffi_config.general.log_level.as_str() {
            "warning" => LogLevel::Warning,
            "error" => LogLevel::Error,
            "debug" => LogLevel::Debug,
            "silent" => LogLevel::Silent,
            _ => LogLevel::Info,
        },
        ipv6: ffi_config.general.ipv6,
        tcp_concurrent: ffi_config.general.tcp_concurrent,
        external_controller: ffi_config.general.external_controller,
        external_ui: ffi_config.general.external_ui,
        secret: ffi_config.general.secret,
    };

    let dns = DnsConfig {
        enable: ffi_config.dns.enable,
        listen: ffi_config.dns.listen,
        nameservers: ffi_config.dns.nameservers,
        fallback: ffi_config.dns.fallback,
        enhanced_mode: match ffi_config.dns.enhanced_mode.as_str() {
            "fake-ip" => DnsMode::FakeIp,
            _ => DnsMode::Normal,
        },
    };

    let inbounds = ffi_config
        .inbounds
        .into_iter()
        .map(|inbound| {
            let opts: HashMap<String, serde_yaml::Value> = if inbound.options.is_empty() {
                HashMap::new()
            } else {
                let json_map: HashMap<String, serde_json::Value> =
                    serde_json::from_str(&inbound.options).unwrap_or_default();
                json_map
                    .into_iter()
                    .filter_map(|(k, v)| match serde_yaml::to_value(v) {
                        Ok(val) => Some((k, val)),
                        Err(err) => {
                            tracing::warn!("Failed to convert inbound option {}: {}", k, err);
                            None
                        }
                    })
                    .collect()
            };

            InboundConfig {
                inbound_type: match inbound.inbound_type.as_str() {
                    "http" => InboundType::Http,
                    "socks5" => InboundType::Socks5,
                    "mixed" => InboundType::Mixed,
                    "redir" => InboundType::Redir,
                    "tproxy" => InboundType::Tproxy,
                    "tun" => InboundType::Tun,
                    "socks" => InboundType::Socks5,
                    _ => InboundType::Http,
                },
                tag: inbound.tag,
                listen: inbound.listen,
                port: inbound.port,
                options: opts,
            }
        })
        .collect();

    let outbounds = ffi_config
        .outbounds
        .into_iter()
        .map(|outbound| {
            let opts: HashMap<String, serde_yaml::Value> = if outbound.options.is_empty() {
                HashMap::new()
            } else {
                tracing::debug!(
                    "Outbound '{}' options JSON: {}",
                    outbound.tag,
                    &outbound.options
                );
                let json_map: HashMap<String, serde_json::Value> =
                    serde_json::from_str(&outbound.options).unwrap_or_default();
                let result: HashMap<String, serde_yaml::Value> = json_map
                    .into_iter()
                    .filter_map(|(k, v)| match serde_yaml::to_value(&v) {
                        Ok(val) => {
                            tracing::debug!(
                                "Outbound '{}' option '{}' converted: {:?}",
                                outbound.tag,
                                k,
                                val
                            );
                            Some((k, val))
                        }
                        Err(err) => {
                            tracing::warn!("Failed to convert outbound option {}: {}", k, err);
                            None
                        }
                    })
                    .collect();
                tracing::debug!(
                    "Outbound '{}' converted {} options",
                    outbound.tag,
                    result.len()
                );
                result
            };

            OutboundConfig {
                outbound_type: match outbound.outbound_type.to_lowercase().as_str() {
                    "direct" => OutboundType::Direct,
                    "reject" => OutboundType::Reject,
                    "shadowsocks" => OutboundType::Shadowsocks,
                    "vmess" => OutboundType::Vmess,
                    "trojan" => OutboundType::Trojan,
                    "wireguard" => OutboundType::Wireguard,
                    "socks5" => OutboundType::Socks5,
                    "socks" => OutboundType::Socks5,
                    "http" => OutboundType::Http,
                    "tuic" => OutboundType::Tuic,
                    "hysteria2" | "hy2" | "hysteria" => OutboundType::Hysteria2,
                    "quic" | "shadowquic" => OutboundType::Quic,
                    "selector" => OutboundType::Selector,
                    "urltest" | "url-test" => OutboundType::Urltest,
                    "fallback" => OutboundType::Fallback,
                    "loadbalance" | "load-balance" => OutboundType::Loadbalance,
                    "relay" => OutboundType::Relay,
                    _ => OutboundType::Direct,
                },
                tag: outbound.tag,
                server: outbound.server,
                port: outbound.port,
                options: opts,
            }
        })
        .collect();

    let rules = ffi_config
        .rules
        .into_iter()
        .map(|rule| {
            let normalized = rule.rule_type.replace('_', "-").to_lowercase();
            RuleConfig {
                rule_type: match normalized.as_str() {
                    "domain" => RuleType::Domain,
                    "domain-suffix" => RuleType::DomainSuffix,
                    "domain-keyword" => RuleType::DomainKeyword,
                    "domain-regex" => RuleType::DomainRegex,
                    "geoip" => RuleType::Geoip,
                    "ip-cidr" => RuleType::IpCidr,
                    "src-ip-cidr" => RuleType::SrcIpCidr,
                    "src-port" => RuleType::SrcPort,
                    "dst-port" => RuleType::DstPort,
                    "process-name" => RuleType::ProcessName,
                    "rule-set" => RuleType::RuleSet,
                    "match" => RuleType::Match,
                    _ => RuleType::Domain,
                },
                payload: rule.payload,
                outbound: rule.outbound,
                process_name: rule.process_name,
            }
        })
        .collect();

    Ok(Config {
        general,
        dns,
        inbounds,
        outbounds,
        rules,
    })
}

// ============== Latency Testing ==============
#[frb]
pub async fn test_proxy_latency(
    server: String,
    port: u16,
    timeout_ms: u32,
) -> Result<LatencyTestResult> {
    use std::time::Instant;
    use tokio::time::Duration;

    let proxy_name = format!("{}:{}", server, port);
    let timeout_duration = Duration::from_millis(timeout_ms as u64);

    let proxy_port = {
        let instance = get_veloguard_instance().await;
        match instance {
            Ok(inst) => {
                let guard = inst.read().await;
                if let Some(veloguard) = guard.as_ref() {
                    let config = veloguard.config();
                    let mut port = 7890u16;
                    for inbound in &config.inbounds {
                        if matches!(
                            inbound.inbound_type,
                            veloguard_core::InboundType::Mixed | veloguard_core::InboundType::Http
                        ) {
                            port = inbound.port;
                            break;
                        }
                    }
                    port
                } else {
                    7890
                }
            }
            Err(_) => 7890,
        }
    };

    let test_url = "http://www.gstatic.com/generate_204";
    let start = Instant::now();
    let result = test_via_http_proxy(test_url, proxy_port, timeout_duration).await;

    match result {
        Ok(()) => {
            let latency = start.elapsed().as_millis() as u32;
            Ok(LatencyTestResult {
                proxy_name,
                latency_ms: Some(latency),
                success: true,
                error: None,
            })
        }
        Err(e) => Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some(e),
        }),
    }
}

#[frb]
pub async fn test_outbound_latency(
    outbound_name: String,
    timeout_ms: u32,
) -> Result<LatencyTestResult> {
    use tokio::time::Duration;

    let timeout_duration = Duration::from_millis(timeout_ms as u64);
    let test_url = "http://www.gstatic.com/generate_204";

    let proxy = {
        let instance = get_veloguard_instance().await?;
        let guard = instance.read().await;

        if let Some(veloguard) = guard.as_ref() {
            let proxy_manager = veloguard.proxy_manager();
            proxy_manager.outbound_manager().get_proxy(&outbound_name)
        } else {
            None
        }
    };

    let proxy = match proxy {
        Some(p) => p,
        None => {
            return Ok(LatencyTestResult {
                proxy_name: outbound_name,
                latency_ms: None,
                success: false,
                error: Some("Outbound not found".to_string()),
            });
        }
    };

    match proxy.test_http_latency(test_url, timeout_duration).await {
        Ok(duration) => {
            let latency = duration.as_millis() as u32;
            Ok(LatencyTestResult {
                proxy_name: outbound_name,
                latency_ms: Some(latency),
                success: true,
                error: None,
            })
        }
        Err(e) => Ok(LatencyTestResult {
            proxy_name: outbound_name,
            latency_ms: None,
            success: false,
            error: Some(e.to_string()),
        }),
    }
}

#[frb]
pub async fn test_tcp_connectivity(
    server: String,
    port: u16,
    timeout_ms: u32,
) -> Result<LatencyTestResult> {
    use std::time::Instant;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    let proxy_name = format!("{}:{}", server, port);
    let addr = format!("{}:{}", server, port);
    let timeout_duration = Duration::from_millis(timeout_ms as u64);

    let start = Instant::now();

    match timeout(timeout_duration, TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            let latency = start.elapsed().as_millis() as u32;
            Ok(LatencyTestResult {
                proxy_name,
                latency_ms: Some(latency),
                success: true,
                error: None,
            })
        }
        Ok(Err(e)) => Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some(format!("Connection failed: {}", e)),
        }),
        Err(_) => Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some("Timeout".to_string()),
        }),
    }
}

#[frb]
pub async fn test_shadowsocks_latency(
    server: String,
    port: u16,
    password: String,
    cipher: String,
    timeout_ms: u32,
) -> Result<LatencyTestResult> {
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::Duration;

    let proxy_name = format!("{}:{}", server, port);
    let timeout_duration = Duration::from_millis(timeout_ms as u64);
    let test_url = "http://www.gstatic.com/generate_204";
    let url = match url::Url::parse(test_url) {
        Ok(u) => u,
        Err(e) => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some(format!("Invalid URL: {}", e)),
            });
        }
    };

    let host = match url.host_str() {
        Some(h) => h.to_string(),
        None => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some("URL has no host".to_string()),
            });
        }
    };
    let url_port = url.port().unwrap_or(80);
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };

    let start = Instant::now();
    let server_addr = format!("{}:{}", server, port);
    let stream = match tokio::time::timeout(
        timeout_duration,
        tokio::net::TcpStream::connect(&server_addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some(format!("Connection failed: {}", e)),
            });
        }
        Err(_) => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some("Connection timeout".to_string()),
            });
        }
    };

    stream.set_nodelay(true).ok();
    let cipher_spec = match ss_cipher_spec(&cipher) {
        Ok(c) => c,
        Err(e) => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some(e),
            });
        }
    };

    let mut client_salt = vec![0u8; cipher_spec.salt_len];
    if let Err(e) = getrandom::fill(&mut client_salt) {
        return Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some(format!("Failed to generate salt: {}", e)),
        });
    }

    let enc_subkey = match ss_derive_subkey(&password, &client_salt, cipher_spec.key_len) {
        Ok(k) => k,
        Err(e) => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some(e),
            });
        }
    };

    let mut enc = match SsAeadCipher::new(&enc_subkey) {
        Ok(c) => c,
        Err(e) => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some(e),
            });
        }
    };

    let (mut ro, mut wo) = tokio::io::split(stream);
    let addr_header = ss_build_address_header(&host, url_port);
    let http_request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
        path, host, veloguard_core::USER_AGENT
    );

    let mut first_payload = addr_header;
    first_payload.extend_from_slice(http_request.as_bytes());

    let len = first_payload.len();
    let len_bytes = (len as u16).to_be_bytes();
    let enc_len = match enc.encrypt(&len_bytes) {
        Ok(d) => d,
        Err(e) => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some(format!("Encryption failed: {}", e)),
            });
        }
    };
    let enc_data = match enc.encrypt(&first_payload) {
        Ok(d) => d,
        Err(e) => {
            return Ok(LatencyTestResult {
                proxy_name,
                latency_ms: None,
                success: false,
                error: Some(format!("Encryption failed: {}", e)),
            });
        }
    };

    let mut send_buf = Vec::with_capacity(client_salt.len() + enc_len.len() + enc_data.len());
    send_buf.extend_from_slice(&client_salt);
    send_buf.extend_from_slice(&enc_len);
    send_buf.extend_from_slice(&enc_data);

    if let Err(e) = wo.write_all(&send_buf).await {
        return Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some(format!("Failed to send request: {}", e)),
        });
    }

    if let Err(e) = wo.flush().await {
        return Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some(format!("Flush failed: {}", e)),
        });
    }

    let password_clone = password.clone();
    let result = tokio::time::timeout(timeout_duration, async move {
        let mut server_salt = vec![0u8; cipher_spec.salt_len];
        if let Err(e) = ro.read_exact(&mut server_salt).await {
            return Err(format!("Failed to read server salt: {}", e));
        }

        let dec_subkey = match ss_derive_subkey(&password_clone, &server_salt, cipher_spec.key_len)
        {
            Ok(k) => k,
            Err(e) => return Err(e),
        };
        let mut dec = match SsAeadCipher::new(&dec_subkey) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        match ss_recv_decrypted_chunk(&mut ro, &mut dec).await {
            Ok(Some(chunk)) => {
                let response = String::from_utf8_lossy(&chunk);
                if response.starts_with("HTTP/") {
                    Ok(())
                } else {
                    Err(format!(
                        "Invalid HTTP response: {}",
                        &response[..response.len().min(50)]
                    ))
                }
            }
            Ok(None) => Err("No response received".to_string()),
            Err(e) => Err(e),
        }
    })
    .await;

    match result {
        Ok(Ok(())) => {
            let latency = start.elapsed().as_millis() as u32;
            Ok(LatencyTestResult {
                proxy_name,
                latency_ms: Some(latency),
                success: true,
                error: None,
            })
        }
        Ok(Err(e)) => Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some(e),
        }),
        Err(_) => Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some("Response timeout".to_string()),
        }),
    }
}

#[derive(Clone, Copy)]
struct SsCipherSpec {
    key_len: usize,
    salt_len: usize,
}

fn ss_cipher_spec(cipher: &str) -> std::result::Result<SsCipherSpec, String> {
    match cipher.to_lowercase().as_str() {
        "aes-256-gcm" | "aead_aes_256_gcm" => Ok(SsCipherSpec {
            key_len: 32,
            salt_len: 32,
        }),
        "aes-128-gcm" | "aead_aes_128_gcm" => Ok(SsCipherSpec {
            key_len: 16,
            salt_len: 16,
        }),
        "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => Ok(SsCipherSpec {
            key_len: 32,
            salt_len: 32,
        }),
        _ => Err(format!("Unsupported cipher: {}", cipher)),
    }
}

fn ss_derive_subkey(
    password: &str,
    salt: &[u8],
    key_len: usize,
) -> std::result::Result<Vec<u8>, String> {
    use hkdf::Hkdf;
    use md5::{Digest, Md5};
    use sha1::Sha1;

    let mut key = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password.as_bytes());
        prev = hasher.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);

    let hk = Hkdf::<Sha1>::new(Some(salt), &key);
    let mut subkey = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut subkey)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    Ok(subkey)
}

fn ss_build_address_header(host: &str, port: u16) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0x03);
    header.push(host.len() as u8);
    header.extend_from_slice(host.as_bytes());
    header.push((port >> 8) as u8);
    header.push((port & 0xff) as u8);
    header
}

#[allow(clippy::large_enum_variant)]
enum SsAeadCipherInner {
    Aes256Gcm(aes_gcm::Aes256Gcm),
    Aes128Gcm(aes_gcm::Aes128Gcm),
}

struct SsAeadCipher {
    inner: SsAeadCipherInner,
    counter: u64,
}

impl SsAeadCipher {
    fn new(key: &[u8]) -> std::result::Result<Self, String> {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::KeyInit;

        let inner = if key.len() == 32 {
            SsAeadCipherInner::Aes256Gcm(aes_gcm::Aes256Gcm::new(GenericArray::from_slice(key)))
        } else if key.len() == 16 {
            SsAeadCipherInner::Aes128Gcm(aes_gcm::Aes128Gcm::new(GenericArray::from_slice(key)))
        } else {
            return Err(format!("Invalid key length: {}", key.len()));
        };

        Ok(Self { inner, counter: 0 })
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> std::result::Result<Vec<u8>, String> {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::aead::Aead;

        let nonce = self.next_nonce();
        let nonce = GenericArray::from_slice(&nonce);

        match &self.inner {
            SsAeadCipherInner::Aes256Gcm(cipher) => cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| format!("Encryption failed: {}", e)),
            SsAeadCipherInner::Aes128Gcm(cipher) => cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| format!("Encryption failed: {}", e)),
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> std::result::Result<Vec<u8>, String> {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::aead::Aead;

        let nonce = self.next_nonce();
        let nonce = GenericArray::from_slice(&nonce);

        match &self.inner {
            SsAeadCipherInner::Aes256Gcm(cipher) => cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| format!("Decryption failed: {}", e)),
            SsAeadCipherInner::Aes128Gcm(cipher) => cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| format!("Decryption failed: {}", e)),
        }
    }
}

async fn ss_recv_decrypted_chunk<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
    cipher: &mut SsAeadCipher,
) -> std::result::Result<Option<Vec<u8>>, String> {
    let mut encrypted_len = vec![0u8; 2 + 16];
    match reader.read_exact(&mut encrypted_len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("Read length failed: {}", e)),
    }

    let len_bytes = cipher.decrypt(&encrypted_len)?;
    let data_len = ((len_bytes[0] as usize) << 8) | (len_bytes[1] as usize);

    if data_len == 0 {
        return Ok(None);
    }

    let mut encrypted_data = vec![0u8; data_len + 16];
    reader
        .read_exact(&mut encrypted_data)
        .await
        .map_err(|e| format!("Read data failed: {}", e))?;

    let data = cipher.decrypt(&encrypted_data)?;
    Ok(Some(data))
}

async fn test_via_http_proxy(
    url: &str,
    proxy_port: u16,
    timeout: tokio::time::Duration,
) -> std::result::Result<(), String> {
    use tokio::time::timeout as tokio_timeout;

    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let proxy =
        reqwest::Proxy::http(&proxy_url).map_err(|e| format!("Failed to create proxy: {}", e))?;

    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(timeout)
        .build()
        .map_err(|e| format!("Failed to build client: {}", e))?;

    let result = tokio_timeout(timeout, client.get(url).send()).await;

    match result {
        Ok(Ok(response)) => {
            if response.status().is_success() || response.status().as_u16() == 204 {
                Ok(())
            } else {
                Err(format!("HTTP {}", response.status().as_u16()))
            }
        }
        Ok(Err(e)) => Err(format!("{}", e)),
        Err(_) => Err("Timeout".to_string()),
    }
}

#[frb]
pub async fn test_proxies_latency(
    proxies: Vec<(String, u16)>,
    timeout_ms: u32,
) -> Result<Vec<LatencyTestResult>> {
    use futures::future::join_all;

    let futures: Vec<_> = proxies
        .into_iter()
        .map(|(server, port)| test_proxy_latency(server, port, timeout_ms))
        .collect();

    let results = join_all(futures).await;

    Ok(results.into_iter().filter_map(|r| r.ok()).collect())
}

// ============== Proxy Group Selection ==============
#[frb]
pub async fn select_proxy_in_group(group_name: String, proxy_name: String) -> Result<bool> {
    tracing::info!(
        "Selecting proxy in group: group='{}', proxy='{}'",
        group_name,
        proxy_name
    );

    let instance = get_veloguard_instance().await?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        let proxy_manager = veloguard.proxy_manager();
        let outbound_manager = proxy_manager.outbound_manager();

        if outbound_manager.get_proxy(&group_name).is_some() {
            outbound_manager
                .set_selector_proxy(&group_name, &proxy_name)
                .await
                .map_err(VeloGuardError::from)?;

            tracing::info!("Proxy selection updated: {} -> {}", group_name, proxy_name);
            Ok(true)
        } else {
            tracing::warn!("Proxy group '{}' not found", group_name);
            Ok(false)
        }
    } else {
        Err(VeloGuardError::Internal(
            "VeloGuard not initialized".to_string(),
        ))
    }
}

#[frb]
pub async fn get_selected_proxy_in_group(group_name: String) -> Result<Option<String>> {
    let instance = get_veloguard_instance().await?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        let proxy_manager = veloguard.proxy_manager();
        let outbound_manager = proxy_manager.outbound_manager();

        Ok(outbound_manager.get_selector_proxy(&group_name))
    } else {
        Ok(None)
    }
}

// ============== Connection Tracking ==============
#[frb]
pub async fn get_active_connections() -> Result<Vec<ActiveConnection>> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    let connections = tracker.get_all();

    #[allow(unused_mut)]
    let mut result: Vec<ActiveConnection> = connections
        .iter()
        .map(|conn| ActiveConnection {
            id: conn.id.clone(),
            inbound_tag: conn.inbound_tag.clone(),
            outbound_tag: conn.outbound_tag.clone(),
            host: conn.host.clone(),
            destination_ip: conn.destination_ip.clone(),
            destination_port: conn.destination_port,
            protocol: conn.protocol.clone(),
            network: conn.network.clone(),
            upload_bytes: conn.get_upload(),
            download_bytes: conn.get_download(),
            start_time: conn.start_timestamp,
            rule: conn.rule.clone(),
            rule_payload: conn.rule_payload.clone(),
            process_name: conn.process_name.clone(),
        })
        .collect();

    #[cfg(target_os = "android")]
    {
        if let Some(processor) = crate::get_android_vpn_processor() {
            let vpn_stats = processor.get_traffic_stats();

            if vpn_stats.tcp_connections > 0 || vpn_stats.udp_sessions > 0 {
                let start_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                if vpn_stats.tcp_connections > 0 {
                    result.push(ActiveConnection {
                        id: format!("vpn-tcp-{}", vpn_stats.tcp_connections),
                        inbound_tag: "tun".to_string(),
                        outbound_tag: "proxy".to_string(),
                        host: format!("{} TCP connections", vpn_stats.tcp_connections),
                        destination_ip: None,
                        destination_port: 0,
                        protocol: "TCP".to_string(),
                        network: "tcp".to_string(),
                        upload_bytes: vpn_stats.bytes_received,
                        download_bytes: vpn_stats.bytes_sent,
                        start_time,
                        rule: "VPN".to_string(),
                        rule_payload: "TUN".to_string(),
                        process_name: None,
                    });
                }

                if vpn_stats.udp_sessions > 0 {
                    result.push(ActiveConnection {
                        id: format!("vpn-udp-{}", vpn_stats.udp_sessions),
                        inbound_tag: "tun".to_string(),
                        outbound_tag: "proxy".to_string(),
                        host: format!("{} UDP sessions", vpn_stats.udp_sessions),
                        destination_ip: None,
                        destination_port: 0,
                        protocol: "UDP".to_string(),
                        network: "udp".to_string(),
                        upload_bytes: 0,
                        download_bytes: 0,
                        start_time,
                        rule: "VPN".to_string(),
                        rule_payload: "TUN".to_string(),
                        process_name: None,
                    });
                }
            }
        }
    }

    Ok(result)
}

#[frb]
pub async fn close_active_connection(connection_id: String) -> Result<bool> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    Ok(tracker.close_connection(&connection_id))
}

#[frb]
pub async fn close_all_connections() -> Result<()> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    tracker.close_all();
    Ok(())
}

#[frb]
pub async fn get_connection_stats() -> Result<(u64, u64, u64, u64)> {
    let tracker = veloguard_core::connection_tracker::global_tracker();

    #[allow(unused_mut)]
    let mut total_count = tracker.total_count();
    #[allow(unused_mut)]
    let mut total_upload = tracker.total_upload();
    #[allow(unused_mut)]
    let mut total_download = tracker.total_download();
    #[allow(unused_mut)]
    let mut active_count = tracker.active_count() as u64;

    #[cfg(target_os = "android")]
    {
        if let Some(processor) = crate::get_android_vpn_processor() {
            let vpn_stats = processor.get_traffic_stats();
            total_upload = vpn_stats.bytes_received;
            total_download = vpn_stats.bytes_sent;

            let vpn_connections = (vpn_stats.tcp_connections + vpn_stats.udp_sessions) as u64;
            active_count = vpn_connections;
            total_count = total_count.max(vpn_connections);
        }
    }

    Ok((total_count, total_upload, total_download, active_count))
}

// ============== TUN Mode ==============
#[frb]
pub fn is_wintun_available() -> bool {
    veloguard_netstack::check_wintun_available()
}

#[frb]
pub fn get_wintun_dll_path() -> Option<String> {
    veloguard_netstack::get_wintun_path().map(|p| p.to_string_lossy().to_string())
}

#[frb]
pub async fn ensure_wintun_dll() -> Result<String> {
    let path = veloguard_netstack::ensure_wintun()
        .await
        .map_err(|e| VeloGuardError::Internal(format!("Failed to ensure wintun: {}", e)))?;
    Ok(path.to_string_lossy().to_string())
}

#[frb]
pub async fn enable_tun_mode() -> Result<TunStatus> {
    enable_tun_mode_with_mode("rule".to_string()).await
}

#[frb]
pub async fn enable_tun_mode_with_mode(mode: String) -> Result<TunStatus> {
    #[cfg(target_os = "windows")]
    {
        use veloguard_netstack::{TunConfig, TunDevice, WindowsRouteManager, WindowsVpnProcessor};

        tracing::info!("=== Enabling TUN mode on Windows with mode={} ===", mode);
        if let Some(old_processor) = crate::get_windows_vpn_processor() {
            tracing::info!("Cleaning up existing Windows VPN processor");
            old_processor.stop();
            old_processor.reset();
        }
        crate::clear_windows_vpn_processor();

        if let Some(mut route_manager) = crate::get_windows_route_manager_mut() {
            let _ = route_manager.disable_global_mode();
        }
        crate::clear_windows_route_manager();

        if let Some(mut tun_device) = crate::take_windows_tun_device() {
            let _ = tun_device.stop().await;
            tracing::info!("Stopped existing TUN device");
        }

        match veloguard_netstack::ensure_wintun().await {
            Ok(path) => {
                tracing::info!("wintun.dll available at {:?}", path);
            }
            Err(e) => {
                return Ok(TunStatus {
                    enabled: false,
                    interface_name: None,
                    mtu: None,
                    error: Some(format!("Failed to load wintun.dll: {}. Please ensure you have administrator privileges.", e)),
                });
            }
        }

        let proxy_port = {
            let instance = get_veloguard_instance().await?;
            let veloguard_guard = instance.read().await;
            if let Some(ref veloguard) = *veloguard_guard {
                let is_running = veloguard.is_running().await.unwrap_or(false);
                if !is_running {
                    tracing::error!("VeloGuard proxy service is NOT running! TUN will not work.");
                    return Ok(TunStatus {
                        enabled: false,
                        interface_name: None,
                        mtu: None,
                        error: Some(
                            "VeloGuard proxy service is not running. Please start it first."
                                .to_string(),
                        ),
                    });
                }
                let config = veloguard.config();
                config
                    .general
                    .mixed_port
                    .or(config.general.socks_port)
                    .unwrap_or(7890)
            } else {
                return Ok(TunStatus {
                    enabled: false,
                    interface_name: None,
                    mtu: None,
                    error: Some("VeloGuard not initialized".to_string()),
                });
            }
        };

        tracing::info!("Using proxy port {} for Windows TUN", proxy_port);

        let mode_int = match mode.to_lowercase().as_str() {
            "global" => 1,
            "direct" => 2,
            "rule" => 3,
            _ => 3,
        };
        veloguard_core::set_runtime_proxy_mode(mode_int);
        veloguard_netstack::set_windows_proxy_mode(mode_int);
        tracing::info!("Proxy mode set to {} ({})", mode, mode_int);

        let tun_address = std::net::Ipv4Addr::new(198, 18, 0, 1);
        let config = TunConfig {
            name: "VeloGuard".to_string(),
            address: tun_address,
            netmask: std::net::Ipv4Addr::new(255, 255, 0, 0),
            mtu: 1500,
            gateway: Some(tun_address),
            dns: vec![std::net::Ipv4Addr::new(198, 18, 0, 2)],
        };

        let mut tun = match TunDevice::with_config(config.clone()).await {
            Ok(t) => t,
            Err(e) => {
                return Ok(TunStatus {
                    enabled: false,
                    interface_name: None,
                    mtu: None,
                    error: Some(format!("Failed to create TUN device: {}", e)),
                });
            }
        };

        if let Err(e) = tun.start().await {
            return Ok(TunStatus {
                enabled: false,
                interface_name: None,
                mtu: None,
                error: Some(format!(
                    "Failed to start TUN device: {}. Please run as administrator.",
                    e
                )),
            });
        }

        tracing::info!("TUN device started successfully");

        let tun_tx = match tun.get_sender() {
            Some(tx) => tx,
            None => {
                return Ok(TunStatus {
                    enabled: false,
                    interface_name: None,
                    mtu: None,
                    error: Some("Failed to get TUN sender channel".to_string()),
                });
            }
        };

        let mut tun_rx = match tun.take_receiver() {
            Some(rx) => rx,
            None => {
                return Ok(TunStatus {
                    enabled: false,
                    interface_name: None,
                    mtu: None,
                    error: Some("Failed to get TUN receiver channel".to_string()),
                });
            }
        };

        let processor = std::sync::Arc::new(WindowsVpnProcessor::new(proxy_port, tun_tx.clone()));
        crate::set_windows_vpn_processor(processor.clone());

        let processor_clone = processor.clone();
        tokio::spawn(async move {
            tracing::info!("=== Windows TUN packet processing task started ===");
            let mut packet_count = 0u64;

            while let Some(packet) = tun_rx.recv().await {
                packet_count += 1;
                if packet_count <= 10 || packet_count.is_multiple_of(100) {
                    tracing::debug!(
                        "Processing packet #{}: {} bytes",
                        packet_count,
                        packet.len()
                    );
                }
                if let Err(e) = processor_clone.process_packet(&packet).await {
                    tracing::debug!("Packet processing error: {}", e);
                }
            }

            tracing::info!(
                "Windows TUN packet processing task stopped, processed {} packets",
                packet_count
            );
        });

        let mut route_manager = WindowsRouteManager::new(&config.name, tun_address);

        if mode.to_lowercase() == "global" {
            if let Err(e) = route_manager.enable_global_mode() {
                tracing::warn!("Failed to enable global mode routes: {}", e);
            }
        }

        if let Err(e) = veloguard_netstack::set_tun_dns(&config.name, &config.dns) {
            tracing::warn!("Failed to set TUN DNS: {}", e);
        } else {
            tracing::info!("TUN DNS set to {:?}", config.dns);
        }

        if let Err(e) = veloguard_netstack::flush_dns_cache() {
            tracing::warn!("Failed to flush DNS cache: {}", e);
        }

        crate::set_windows_route_manager(route_manager);
        crate::set_windows_tun_device(tun);

        tracing::info!("=== Windows TUN mode enabled successfully ===");
        Ok(TunStatus {
            enabled: true,
            interface_name: Some(config.name),
            mtu: Some(config.mtu as u32),
            error: None,
        })
    }

    #[cfg(target_os = "linux")]
    {
        mode;
        tracing::info!("Enabling TUN mode on Linux");
        Ok(TunStatus {
            enabled: false,
            interface_name: None,
            mtu: None,
            error: Some("TUN mode requires root privileges on Linux.".to_string()),
        })
    }

    #[cfg(target_os = "macos")]
    {
        mode;
        tracing::info!("Enabling TUN mode on macOS");
        Ok(TunStatus {
            enabled: false,
            interface_name: None,
            mtu: None,
            error: Some("TUN mode requires System Extension approval on macOS.".to_string()),
        })
    }

    #[cfg(target_os = "android")]
    {
        mode;
        Ok(TunStatus {
            enabled: true,
            interface_name: Some("tun0".to_string()),
            mtu: Some(1500),
            error: None,
        })
    }

    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "android"
    )))]
    {
        mode;
        Ok(TunStatus {
            enabled: false,
            interface_name: None,
            mtu: None,
            error: Some("TUN mode is not supported on this platform.".to_string()),
        })
    }
}

#[frb]
pub async fn disable_tun_mode() -> Result<TunStatus> {
    tracing::info!("=== Disabling TUN mode ===");

    #[cfg(target_os = "windows")]
    {
        if let Some(processor) = crate::get_windows_vpn_processor() {
            processor.stop();
            processor.reset();
            tracing::info!("Windows VPN processor stopped");
        }
        crate::clear_windows_vpn_processor();
        if let Some(mut route_manager) = crate::get_windows_route_manager_mut() {
            if let Err(e) = route_manager.disable_global_mode() {
                tracing::warn!("Failed to disable global mode routes: {}", e);
            }
        }
        crate::clear_windows_route_manager();
        if let Some(mut tun_device) = crate::take_windows_tun_device() {
            if let Err(e) = tun_device.stop().await {
                tracing::warn!("Failed to stop TUN device: {}", e);
            }
            tracing::info!("Windows TUN device stopped");
        }

        veloguard_core::set_runtime_proxy_mode(0);
        veloguard_netstack::set_windows_proxy_mode(0);
    }

    Ok(TunStatus {
        enabled: false,
        interface_name: None,
        mtu: None,
        error: None,
    })
}

#[frb]
pub async fn get_tun_status() -> Result<TunStatus> {
    #[cfg(target_os = "windows")]
    {
        if let Some(processor) = crate::get_windows_vpn_processor() {
            if processor.is_running() {
                return Ok(TunStatus {
                    enabled: true,
                    interface_name: Some("VeloGuard".to_string()),
                    mtu: Some(1500),
                    error: None,
                });
            }
        }
    }

    Ok(TunStatus {
        enabled: false,
        interface_name: None,
        mtu: None,
        error: None,
    })
}

#[frb]
pub fn set_windows_proxy_mode(mode: String) -> Result<bool> {
    let mode_int = match mode.to_lowercase().as_str() {
        "global" => 1,
        "direct" => 2,
        "rule" => 3,
        _ => 3,
    };

    veloguard_core::set_runtime_proxy_mode(mode_int);
    tracing::info!("Runtime proxy mode set to {} ({})", mode, mode_int);

    #[cfg(target_os = "windows")]
    {
        veloguard_netstack::set_windows_proxy_mode(mode_int);

        if let Some(mut route_manager) = crate::get_windows_route_manager_mut() {
            if mode.to_lowercase() == "global" {
                if let Err(e) = route_manager.enable_global_mode() {
                    tracing::warn!("Failed to enable global mode routes: {}", e);
                }
            } else {
                if let Err(e) = route_manager.disable_global_mode() {
                    tracing::warn!("Failed to disable global mode routes: {}", e);
                }
            }
        }
    }

    Ok(true)
}

#[frb]
pub fn get_windows_proxy_mode_str() -> String {
    match veloguard_core::get_runtime_proxy_mode() {
        1 => "global".to_string(),
        2 => "direct".to_string(),
        3 => "rule".to_string(),
        _ => "rule".to_string(),
    }
}

#[frb]
pub fn get_windows_tun_stats() -> Result<(u64, u64, u64, u64, usize, usize)> {
    #[cfg(target_os = "windows")]
    {
        if let Some(processor) = crate::get_windows_vpn_processor() {
            let stats = processor.get_traffic_stats();
            return Ok((
                stats.packets_received,
                stats.packets_sent,
                stats.bytes_received,
                stats.bytes_sent,
                stats.tcp_connections,
                stats.udp_sessions,
            ));
        }
    }

    Ok((0, 0, 0, 0, 0, 0))
}

// ============== UWP Loopback ==============
#[frb]
pub async fn enable_uwp_loopback() -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        tracing::info!("Enabling UWP loopback exemption");
        let result = Command::new("CheckNetIsolation.exe")
            .args([
                "LoopbackExempt",
                "-a",
                "-n=Microsoft.MicrosoftEdge_8wekyb3d8bbwe",
            ])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    tracing::info!("UWP loopback exemption enabled successfully");
                    Ok(true)
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!("UWP loopback exemption failed: {}", stderr);
                    Ok(false)
                }
            }
            Err(e) => {
                tracing::error!("Failed to run CheckNetIsolation: {}", e);
                Ok(false)
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(true)
    }
}

#[frb]
pub async fn open_uwp_loopback_utility() -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        tracing::info!("Opening UWP loopback exemption utility");
        let result = Command::new("cmd")
            .args(["/C", "start", "ms-settings:developers"])
            .spawn();

        match result {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::warn!("Failed to open developer settings: {}", e);
                let fallback = Command::new("CheckNetIsolation.exe")
                    .arg("LoopbackExempt")
                    .arg("-s")
                    .spawn();
                Ok(fallback.is_ok())
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}

// ============== Android VPN Support ==============
#[frb]
pub fn set_android_vpn_fd(fd: i32) {
    #[cfg(target_os = "android")]
    {
        veloguard_netstack::set_android_vpn_fd(fd);
        tracing::info!("Android VPN fd set to {}", fd);
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = fd;
        tracing::warn!("set_android_vpn_fd called on non-Android platform");
    }
}

#[frb]
pub fn get_android_vpn_fd() -> i32 {
    #[cfg(target_os = "android")]
    {
        veloguard_netstack::get_android_vpn_fd()
    }

    #[cfg(not(target_os = "android"))]
    {
        -1
    }
}

#[frb]
pub fn clear_android_vpn_fd() {
    #[cfg(target_os = "android")]
    {
        veloguard_netstack::clear_android_vpn_fd();
        tracing::info!("Android VPN fd cleared");
    }

    #[cfg(not(target_os = "android"))]
    {
        tracing::warn!("clear_android_vpn_fd called on non-Android platform");
    }
}

#[frb]
pub fn set_android_proxy_mode(mode: String) {
    let mode_int = match mode.to_lowercase().as_str() {
        "global" => 1,
        "direct" => 2,
        "rule" => 3,
        _ => 3,
    };

    veloguard_core::set_runtime_proxy_mode(mode_int);
    tracing::info!("Runtime proxy mode set to {} ({})", mode, mode_int);

    #[cfg(target_os = "android")]
    {
        veloguard_netstack::set_android_proxy_mode(mode_int);
        tracing::info!("Android proxy mode set to {} ({})", mode, mode_int);
    }

    #[cfg(not(target_os = "android"))]
    {
        tracing::debug!("set_android_proxy_mode: mode={} applied to routing", mode);
    }
}

#[frb]
pub fn get_android_proxy_mode() -> String {
    match veloguard_core::get_runtime_proxy_mode() {
        1 => "global".to_string(),
        2 => "direct".to_string(),
        3 => "rule".to_string(),
        _ => "rule".to_string(),
    }
}

#[frb]
pub async fn start_android_vpn() -> Result<bool> {
    #[cfg(target_os = "android")]
    {
        use bytes::BytesMut;
        use std::os::unix::io::FromRawFd;
        use tokio::sync::mpsc;

        let fd = veloguard_netstack::get_android_vpn_fd();
        if fd < 0 {
            tracing::error!("Android VPN fd not set. Please call setAndroidVpnFd first.");
            return Ok(false);
        }

        // Validate fd is actually usable
        let fd_valid = unsafe {
            // Use fcntl to check if fd is valid
            libc::fcntl(fd, libc::F_GETFD) != -1
        };
        if !fd_valid {
            tracing::error!("Android VPN fd {} is invalid (fcntl check failed)", fd);
            return Ok(false);
        }

        tracing::info!("=== Starting Android VPN packet processing ===");
        tracing::info!("VPN fd={} (validated)", fd);

        // Cleanup any existing processor
        if let Some(old_processor) = crate::get_android_vpn_processor() {
            tracing::info!("Cleaning up existing VPN processor before restart");
            old_processor.stop();
            old_processor.reset();
        }
        crate::clear_android_vpn_processor();

        // Check JNI status
        let jni_status = crate::android_jni::get_jni_status();
        tracing::info!("JNI Status: {}", jni_status);

        if !crate::android_jni::is_jni_initialized() {
            tracing::error!("JNI bridge not initialized! Socket protection will not work.");
            tracing::error!("VPN service must call nativeInitRustBridge() in onCreate()");
            // Don't return false here - let it try anyway, but warn loudly
        }

        // Check protect callbacks in all modules
        let has_netstack_callback = veloguard_netstack::has_protect_callback();
        let has_solidtcp_callback = veloguard_netstack::solidtcp::has_protect_callback();
        let has_core_callback = veloguard_core::has_protect_callback();
        
        tracing::info!(
            "Protect callback status: netstack={}, solidtcp={}, core={}",
            has_netstack_callback, has_solidtcp_callback, has_core_callback
        );

        if !has_netstack_callback || !has_solidtcp_callback || !has_core_callback {
            tracing::warn!("Some protect callbacks are NOT SET! This may cause routing loops.");
            tracing::warn!("Ensure VPN service calls nativeInitRustBridge() before starting VPN.");
        }

        let proxy_port = {
            let instance = get_veloguard_instance().await?;
            let veloguard_guard = instance.read().await;
            if let Some(ref veloguard) = *veloguard_guard {
                let is_running = veloguard.is_running().await.unwrap_or(false);
                if !is_running {
                    tracing::error!("VeloGuard proxy service is NOT running! VPN will not work.");
                    tracing::error!(
                        "Please start VeloGuard proxy service first before enabling VPN."
                    );
                    return Ok(false);
                }
                tracing::info!("VeloGuard proxy service is running");

                let config = veloguard.config();
                let port = config
                    .general
                    .mixed_port
                    .or(config.general.socks_port)
                    .unwrap_or(7890);
                tracing::info!(
                    "Proxy port from config: mixed_port={:?}, socks_port={:?}, using={}",
                    config.general.mixed_port,
                    config.general.socks_port,
                    port
                );
                port
            } else {
                tracing::error!("VeloGuard instance not initialized! VPN will not work.");
                return Ok(false);
            }
        };

        tracing::info!("Using proxy port {} for Android VPN", proxy_port);
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).await {
            Ok(_) => {
                tracing::info!(
                    "Proxy port {} is listening and accepting connections",
                    proxy_port
                );
            }
            Err(e) => {
                tracing::error!("Proxy port {} is NOT listening: {}", proxy_port, e);
                tracing::error!("VeloGuard proxy may not have started correctly");
            }
        }

        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            let err = std::io::Error::last_os_error();
            tracing::error!(
                "Failed to duplicate VPN fd {}: {} (errno={})",
                fd, err, err.raw_os_error().unwrap_or(-1)
            );
            return Ok(false);
        }

        tracing::info!("Duplicated VPN fd: {} -> {}", fd, dup_fd);
        let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let async_fd = match tokio::io::unix::AsyncFd::new(file) {
            Ok(fd) => std::sync::Arc::new(fd),
            Err(e) => {
                tracing::error!("Failed to create AsyncFd: {}", e);
                return Ok(false);
            }
        };

        let (tun_tx, mut tun_rx) = mpsc::channel::<BytesMut>(4096);
        let processor = std::sync::Arc::new(veloguard_netstack::AndroidVpnProcessor::new(
            proxy_port, tun_tx,
        ));

        let async_fd_read = async_fd.clone();
        let async_fd_write = async_fd.clone();
        let processor_clone = processor.clone();

        crate::set_android_vpn_processor(processor.clone());
        tokio::spawn(async move {
            let mut read_buf = vec![0u8; 65535];
            let mut packet_count = 0u64;

            tracing::info!("=== Android VPN read task started ===");

            loop {
                let mut guard = match async_fd_read.readable().await {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::error!("AsyncFd readable error: {}", e);
                        break;
                    }
                };

                match guard.try_io(|inner| {
                    use std::io::Read;
                    inner.get_ref().read(&mut read_buf)
                }) {
                    Ok(Ok(n)) if n > 0 => {
                        packet_count += 1;
                        if packet_count <= 10 || packet_count % 100 == 0 {
                            tracing::info!("Read packet #{}: {} bytes from TUN", packet_count, n);
                        }
                        if let Err(e) = processor_clone.process_packet(&read_buf[..n]).await {
                            tracing::debug!("Packet processing error: {}", e);
                        }
                    }
                    Ok(Ok(_)) => {
                        tracing::info!("TUN read EOF");
                        break;
                    }
                    Ok(Err(e)) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            tracing::error!("TUN read error: {}", e);
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }

            processor_clone.stop();
            tracing::info!(
                "Android VPN read task stopped, processed {} packets",
                packet_count
            );
        });

        tokio::spawn(async move {
            let mut write_count = 0u64;
            tracing::info!("=== Android VPN write task started ===");

            loop {
                match tun_rx.recv().await {
                    Some(packet) => {
                        write_count += 1;
                        if write_count <= 10 || write_count % 100 == 0 {
                            tracing::info!(
                                "Writing packet #{}: {} bytes to TUN",
                                write_count,
                                packet.len()
                            );
                        }

                        let mut written = 0;
                        let packet_data = &packet[..];

                        while written < packet_data.len() {
                            if let Ok(mut guard) = async_fd_write.writable().await {
                                match guard.try_io(|inner| {
                                    use std::io::Write;
                                    inner.get_ref().write(&packet_data[written..])
                                }) {
                                    Ok(Ok(n)) => {
                                        written += n;
                                        if n == 0 {
                                            tracing::warn!("TUN write returned 0 bytes");
                                            break;
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        if e.kind() != std::io::ErrorKind::WouldBlock {
                                            tracing::error!("TUN write error: {}", e);
                                            break;
                                        }
                                    }
                                    Err(_) => {
                                        continue;
                                    }
                                }
                            } else {
                                tracing::error!("Failed to get writable guard");
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }
            tracing::info!(
                "Android VPN write task stopped, wrote {} packets",
                write_count
            );
        });

        tracing::info!("=== Android VPN packet processing started successfully ===");
        Ok(true)
    }

    #[cfg(not(target_os = "android"))]
    {
        tracing::warn!("start_android_vpn called on non-Android platform");
        Ok(false)
    }
}

#[frb]
pub async fn stop_android_vpn() -> Result<bool> {
    #[cfg(target_os = "android")]
    {
        tracing::info!("=== Stopping Android VPN packet processing ===");

        if let Some(processor) = crate::get_android_vpn_processor() {
            tracing::info!("Stopping VPN processor...");
            processor.stop();

            // Give spawned tasks a moment to notice the shutdown and exit
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            processor.reset();
            processor.reset_fake_ip_pool();
            tracing::info!("VPN processor stopped, reset, and Fake-IP pool cleared");
        } else {
            tracing::info!("No VPN processor to stop");
        }

        crate::clear_android_vpn_processor();
        tracing::info!("Global VPN processor reference cleared");

        veloguard_netstack::clear_android_vpn_fd();
        tracing::info!("VPN fd cleared");
        veloguard_netstack::clear_protect_callback();
        tracing::info!("Socket protect callback cleared");
        
        // Also clear the solidtcp protect callback
        veloguard_netstack::solidtcp::clear_protect_callback();
        tracing::info!("SolidTCP protect callback cleared");

        let tracker = veloguard_core::connection_tracker::global_tracker();
        tracker.reset();
        tracing::info!("Connection tracker reset");

        tracing::info!("=== Android VPN packet processing stopped completely ===");
        Ok(true)
    }

    #[cfg(not(target_os = "android"))]
    {
        tracing::warn!("stop_android_vpn called on non-Android platform");
        Ok(false)
    }
}
