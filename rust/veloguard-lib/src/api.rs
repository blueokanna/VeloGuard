use crate::error::{VeloGuardError, Result};
use crate::types::*;
use crate::{get_veloguard_instance, VELOGUARD_INSTANCE};
use veloguard_core::Config;
use flutter_rust_bridge::frb;
use std::collections::HashMap;

/// Initialize VeloGuard with configuration
#[frb]
pub async fn initialize_veloguard(config_json: String) -> Result<()> {
    tracing::info!("Initializing veloguard...");

    let config: VeloGuardConfig = serde_json::from_str(&config_json)
        .map_err(|e| VeloGuardError::Parse(format!("Invalid config JSON: {}", e)))?;

    // Convert FFI config to core config
    let core_config = convert_ffi_config_to_core(config)?;

    // Stop and clean up any existing instance first
    {
        let mut instance = VELOGUARD_INSTANCE.write().await;
        if let Some(ref veloguard) = *instance {
            tracing::info!("Stopping existing VeloGuard instance before re-initialization");
            if let Err(e) = veloguard.stop().await {
                tracing::warn!("Error stopping existing instance: {}", e);
            }
            // Wait for cleanup
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
        *instance = None;
    }

    // Create VeloGuard instance
    let veloguard = veloguard_core::VeloGuard::new(core_config)
        .await
        .map_err(VeloGuardError::from)?;

    // Store instance
    let mut instance = VELOGUARD_INSTANCE.write().await;
    *instance = Some(veloguard);

    tracing::info!("VeloGuard initialized successfully");
    Ok(())
}

/// Start the VeloGuard proxy server
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

/// Stop the VeloGuard proxy server
#[frb]
pub async fn stop_veloguard() -> Result<()> {
    tracing::info!("Stopping VeloGuard proxy server...");

    // Reset the global connection tracker
    let tracker = veloguard_core::connection_tracker::global_tracker();
    tracker.reset();
    tracing::info!("Connection tracker reset");

    // Get and stop the instance
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

    // Wait for cleanup
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Clear the instance so ports are released
    {
        let mut instance = VELOGUARD_INSTANCE.write().await;
        *instance = None;
    }

    tracing::info!("VeloGuard proxy server stopped successfully");
    Ok(())
}

/// Reload VeloGuard configuration
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

/// Get current VeloGuard status
#[frb]
pub async fn get_veloguard_status() -> Result<ProxyStatus> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

    let instance = get_veloguard_instance().await?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        let tracker = veloguard_core::connection_tracker::global_tracker();
        let config = veloguard.config();

        // Get actual memory usage of current process
        let memory_usage = {
            let mut sys = System::new_with_specifics(
                RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
            );
            let pid = Pid::from_u32(std::process::id());
            // Use refresh_processes with specific PID filter
            sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
            sys.process(pid).map(|p| p.memory()).unwrap_or(0)
        };

        // Get uptime from VeloGuard instance
        let uptime = veloguard.uptime_secs();

        // Get connection count - use core tracker for consistency with get_active_connections
        // The core tracker tracks connections that have been processed by proxy rules
        #[allow(unused_mut)]
        let mut connection_count = tracker.active_count() as u32;

        // On Android, add VPN connection count to show total activity
        #[cfg(target_os = "android")]
        {
            if let Some(processor) = crate::get_android_vpn_processor() {
                let vpn_stats = processor.get_traffic_stats();
                // Add VPN connections (TCP + UDP) to the count
                // This gives a more complete picture of network activity
                let vpn_connections = (vpn_stats.tcp_connections + vpn_stats.udp_sessions) as u32;
                // Use the larger of the two counts to show maximum activity
                connection_count = connection_count.max(vpn_connections);
            }
        }

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

/// Get traffic statistics
#[frb]
pub async fn get_traffic_stats() -> Result<TrafficStats> {
    // Use the global connection tracker for real-time speed and traffic data
    let tracker = veloguard_core::connection_tracker::global_tracker();

    // Force update speed calculation
    tracker.update_speed();

    // On Android, use VPN stats directly instead of syncing
    // The VPN stats represent actual traffic through the TUN device
    #[cfg(target_os = "android")]
    {
        if let Some(processor) = crate::get_android_vpn_processor() {
            let vpn_stats = processor.get_traffic_stats();

            // Use VPN stats directly - bytes_sent is upload (from device to network)
            // bytes_received is download (from network to device)
            // Note: VPN stats are more accurate for Android VPN mode
            return Ok(TrafficStats {
                upload: vpn_stats.bytes_sent,
                download: vpn_stats.bytes_received,
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

/// Test configuration validity
#[frb]
pub async fn test_config(config_json: String) -> Result<bool> {
    let config: VeloGuardConfig = serde_json::from_str(&config_json)
        .map_err(|e| VeloGuardError::Parse(format!("Invalid config JSON: {}", e)))?;

    let core_config = convert_ffi_config_to_core(config)?;

    // Try to create VeloGuard instance to validate config
    match veloguard_core::VeloGuard::new(core_config).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Get connection list
#[frb]
pub async fn get_connections() -> Result<Vec<ConnectionInfo>> {
    let instance = get_veloguard_instance().await?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        // TODO: Implement real connection tracking in core and expose it here
        let _ = veloguard.traffic_stats().active_connections();
        Ok(vec![])
    } else {
        Ok(vec![])
    }
}

/// Close a specific connection
#[frb]
pub async fn close_connection(_connection_id: String) -> Result<()> {
    // TODO: Implement connection closing
    Ok(())
}

/// Get logs
#[frb]
pub async fn get_logs(lines: Option<u32>) -> Result<Vec<String>> {
    let max_lines = lines.unwrap_or(100) as usize;

    // Get logs from the log buffer
    let logs = veloguard_core::logging::get_recent_logs(max_lines);

    if logs.is_empty() {
        // If no logs yet, return a status message
        Ok(vec![
            "[INFO] VeloGuard log buffer initialized. Logs will appear here.".to_string(),
        ])
    } else {
        Ok(logs)
    }
}

/// Set log level
#[frb]
pub async fn set_log_level(level: String) -> Result<()> {
    // Log level changes are applied dynamically using tracing-subscriber's reload handle
    // For now, we just validate the level and log the change
    let _valid_level = match level.to_lowercase().as_str() {
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
    // Note: Dynamic log level changes require tracing-subscriber's reload functionality
    // which should be set up in the VeloGuard core initialization
    Ok(())
}

/// Get system information
#[frb]
pub async fn get_system_info() -> Result<SystemInfo> {
    use sysinfo::System;

    // Get basic system information
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

    // Use sysinfo to get real system info
    let mut sys = System::new_all();
    sys.refresh_all();

    // Get memory information
    let memory_total = sys.total_memory();
    let memory_used = sys.used_memory();

    // Get CPU information
    // cpu_threads is the number of logical processors (what sysinfo returns)
    let cpu_threads = sys.cpus().len() as u32;

    // cpu_cores is the number of physical cores
    // sysinfo's cpus() returns logical processors (threads), so we estimate physical cores
    // On most modern CPUs, threads = cores * 2 (hyperthreading), but this varies
    let cpu_cores = sysinfo::System::physical_core_count()
        .map(|c| c as u32)
        .unwrap_or(cpu_threads);

    let cpu_name = sys
        .cpus()
        .first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());

    // Calculate average CPU usage
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

/// Get version information
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

/// Convert FFI config to core config
fn convert_ffi_config_to_core(ffi_config: VeloGuardConfig) -> Result<Config> {
    use veloguard_core::config::*;

    // Convert general config
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
        external_controller: ffi_config.general.external_controller,
        external_ui: ffi_config.general.external_ui,
        secret: ffi_config.general.secret,
    };

    // Convert DNS config
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

    // Convert inbounds
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

    // Convert outbounds
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

    // Convert rules
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

/// Test proxy latency by making an HTTP request through the local proxy
/// This tests the real end-to-end latency including DNS resolution and proxy chain
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

    // Get the proxy port from VeloGuard config if running
    let proxy_port = {
        let instance = get_veloguard_instance().await;
        match instance {
            Ok(inst) => {
                let guard = inst.read().await;
                if let Some(veloguard) = guard.as_ref() {
                    let config = veloguard.config();
                    // Find a mixed or http inbound port
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

    // Test URL - Google generate_204 is widely used for connectivity tests
    let test_url = "http://www.gstatic.com/generate_204";

    let start = Instant::now();

    // Use HTTP proxy to test connectivity
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

/// Test latency for a specific outbound by name using full HTTP request
/// This uses the outbound's protocol to send an actual HTTP request and measure RTT
#[frb]
pub async fn test_outbound_latency(
    outbound_name: String,
    timeout_ms: u32,
) -> Result<LatencyTestResult> {
    use tokio::time::Duration;

    let timeout_duration = Duration::from_millis(timeout_ms as u64);
    let test_url = "http://www.gstatic.com/generate_204";

    // Get the proxy from outbound manager
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

    // Use the outbound's test_http_latency method
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

/// Test connectivity by directly connecting to a server:port (TCP handshake)
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

    // Parse test URL
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

    // Connect to Shadowsocks server
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

    // Disable Nagle's algorithm for lower latency
    let _ = stream.set_nodelay(true);

    // Set up cipher
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

    // Generate client salt for sending
    let mut client_salt = vec![0u8; cipher_spec.salt_len];
    if let Err(e) = getrandom::getrandom(&mut client_salt) {
        return Ok(LatencyTestResult {
            proxy_name,
            latency_ms: None,
            success: false,
            error: Some(format!("Failed to generate salt: {}", e)),
        });
    }

    // Derive encryption key from client salt
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

    // Build address header (ATYP + Host + Port)
    let addr_header = ss_build_address_header(&host, url_port);

    // Build HTTP request
    let http_request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: VeloGuard/1.0\r\n\r\n",
        path, host
    );

    // Combine address header and HTTP request into one payload
    let mut first_payload = addr_header;
    first_payload.extend_from_slice(http_request.as_bytes());

    // Encrypt the combined payload
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

    // Send client_salt + encrypted length + encrypted data in one write
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

    // Read response - server sends its own salt first
    let password_clone = password.clone();
    let result = tokio::time::timeout(timeout_duration, async move {
        // Read server's salt
        let mut server_salt = vec![0u8; cipher_spec.salt_len];
        if let Err(e) = ro.read_exact(&mut server_salt).await {
            return Err(format!("Failed to read server salt: {}", e));
        }

        // Derive decryption key from server's salt
        let dec_subkey = match ss_derive_subkey(&password_clone, &server_salt, cipher_spec.key_len)
        {
            Ok(k) => k,
            Err(e) => return Err(e),
        };
        let mut dec = match SsAeadCipher::new(&dec_subkey) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        // Now read and decrypt the response
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

// Shadowsocks helper structures and functions for latency testing
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
    use sha1::Sha1;

    // First derive key from password using EVP_BytesToKey (OpenSSL-style)
    let mut key = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut data = prev.clone();
        data.extend_from_slice(password.as_bytes());
        let hash = md5::compute(&data);
        prev = hash.to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);

    // Then derive subkey using HKDF
    let hk = Hkdf::<Sha1>::new(Some(salt), &key);
    let mut subkey = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut subkey)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    Ok(subkey)
}

fn ss_build_address_header(host: &str, port: u16) -> Vec<u8> {
    let mut header = Vec::new();
    // ATYP = 0x03 (domain)
    header.push(0x03);
    // Domain length
    header.push(host.len() as u8);
    // Domain
    header.extend_from_slice(host.as_bytes());
    // Port (big endian)
    header.push((port >> 8) as u8);
    header.push((port & 0xff) as u8);
    header
}

/// AEAD cipher for Shadowsocks - supports AES-128-GCM and AES-256-GCM
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
        // Shadowsocks AEAD uses little-endian nonce counter
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
    // Read encrypted length (2 bytes + 16 byte tag)
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

    // Read encrypted data
    let mut encrypted_data = vec![0u8; data_len + 16];
    reader
        .read_exact(&mut encrypted_data)
        .await
        .map_err(|e| format!("Read data failed: {}", e))?;

    let data = cipher.decrypt(&encrypted_data)?;
    Ok(Some(data))
}

/// Test connectivity via HTTP proxy
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

/// Test multiple proxies concurrently
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

/// Select a proxy within a selector group
/// group_name: The name of the selector group (e.g., "Proxy", "Auto")
/// proxy_name: The name of the proxy to select within the group
#[frb]
pub async fn select_proxy_in_group(group_name: String, proxy_name: String) -> Result<bool> {
    let instance = get_veloguard_instance().await?;
    let veloguard_guard = instance.read().await;

    if let Some(veloguard) = veloguard_guard.as_ref() {
        let proxy_manager = veloguard.proxy_manager();

        // Get the selector group
        if let Some(proxy) = proxy_manager.outbound_manager().get_proxy(&group_name) {
            // Try to downcast to SelectorOutbound
            // Since we can't directly downcast trait objects, we use a workaround:
            // Check if the proxy is a selector by trying to set the selection
            // The SelectorOutbound::set_selected method validates the proxy name

            // For now, we'll use a different approach - store selections in a global map
            // and have the routing logic check this map
            use parking_lot::RwLock;
            use std::collections::HashMap;
            use std::sync::OnceLock;

            static PROXY_SELECTIONS: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

            let selections = PROXY_SELECTIONS.get_or_init(|| RwLock::new(HashMap::new()));
            selections
                .write()
                .insert(group_name.clone(), proxy_name.clone());

            tracing::info!("Proxy selection updated: {} -> {}", group_name, proxy_name);

            // Also try to update the actual SelectorOutbound if possible
            // This requires the proxy to expose a method for selection
            // For now, we just store the selection and log it
            let _ = proxy; // Acknowledge we have the proxy

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

/// Get the currently selected proxy in a group
#[frb]
pub async fn get_selected_proxy_in_group(group_name: String) -> Result<Option<String>> {
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::OnceLock;

    static PROXY_SELECTIONS: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

    let selections = PROXY_SELECTIONS.get_or_init(|| RwLock::new(HashMap::new()));
    let guard = selections.read();

    Ok(guard.get(&group_name).cloned())
}

// ============== Connection Tracking ==============

/// Get all active connections
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

    // On Android, also include SolidTCP connections
    #[cfg(target_os = "android")]
    {
        if let Some(processor) = crate::get_android_vpn_processor() {
            let vpn_stats = processor.get_traffic_stats();

            // Add synthetic connection entries for VPN traffic if there are active connections
            if vpn_stats.tcp_connections > 0 || vpn_stats.udp_sessions > 0 {
                // Add a summary entry for VPN connections
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
                        upload_bytes: vpn_stats.bytes_sent,
                        download_bytes: vpn_stats.bytes_received,
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

/// Close a specific connection
#[frb]
pub async fn close_active_connection(connection_id: String) -> Result<bool> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    Ok(tracker.close_connection(&connection_id))
}

/// Close all connections
#[frb]
pub async fn close_all_connections() -> Result<()> {
    let tracker = veloguard_core::connection_tracker::global_tracker();
    tracker.close_all();
    Ok(())
}

/// Get connection statistics
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

    // On Android, use VPN stats directly
    #[cfg(target_os = "android")]
    {
        if let Some(processor) = crate::get_android_vpn_processor() {
            let vpn_stats = processor.get_traffic_stats();

            // Use VPN stats directly for traffic (more accurate for VPN mode)
            total_upload = vpn_stats.bytes_sent;
            total_download = vpn_stats.bytes_received;

            // Use VPN connection count
            let vpn_connections = (vpn_stats.tcp_connections + vpn_stats.udp_sessions) as u64;
            active_count = vpn_connections;
            total_count = total_count.max(vpn_connections);
        }
    }

    Ok((total_count, total_upload, total_download, active_count))
}

// ============== TUN Mode ==============

/// Check if wintun.dll is available (Windows only)
#[frb]
pub fn is_wintun_available() -> bool {
    veloguard_netstack::check_wintun_available()
}

/// Get the path where wintun.dll should be placed
#[frb]
pub fn get_wintun_dll_path() -> Option<String> {
    veloguard_netstack::get_wintun_path().map(|p| p.to_string_lossy().to_string())
}

/// Ensure wintun.dll is available, downloading if necessary (Windows only)
#[frb]
pub async fn ensure_wintun_dll() -> Result<String> {
    let path = veloguard_netstack::ensure_wintun()
        .await
        .map_err(|e| VeloGuardError::Internal(format!("Failed to ensure wintun: {}", e)))?;
    Ok(path.to_string_lossy().to_string())
}

/// Enable TUN mode (platform-specific)
#[frb]
pub async fn enable_tun_mode() -> Result<TunStatus> {
    #[cfg(target_os = "windows")]
    {
        use veloguard_netstack::{TunConfig, TunDevice};

        tracing::info!("Enabling TUN mode on Windows");

        // First ensure wintun.dll is available
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

        // Create TUN device with default config
        let config = TunConfig {
            name: "VeloGuard".to_string(),
            address: std::net::Ipv4Addr::new(198, 18, 0, 1),
            netmask: std::net::Ipv4Addr::new(255, 255, 0, 0),
            mtu: 1500,
            gateway: None,
            dns: vec![std::net::Ipv4Addr::new(198, 18, 0, 2)],
        };

        match TunDevice::with_config(config.clone()).await {
            Ok(mut tun) => match tun.start().await {
                Ok(_) => {
                    tracing::info!("TUN device started successfully");
                    Ok(TunStatus {
                        enabled: true,
                        interface_name: Some(config.name),
                        mtu: Some(config.mtu as u32),
                        error: None,
                    })
                }
                Err(e) => Ok(TunStatus {
                    enabled: false,
                    interface_name: None,
                    mtu: None,
                    error: Some(format!(
                        "Failed to start TUN device: {}. Please run as administrator.",
                        e
                    )),
                }),
            },
            Err(e) => Ok(TunStatus {
                enabled: false,
                interface_name: None,
                mtu: None,
                error: Some(format!("Failed to create TUN device: {}", e)),
            }),
        }
    }

    #[cfg(target_os = "linux")]
    {
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
        // Android uses VpnService, handled by native layer
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
        Ok(TunStatus {
            enabled: false,
            interface_name: None,
            mtu: None,
            error: Some("TUN mode is not supported on this platform.".to_string()),
        })
    }
}

/// Disable TUN mode
#[frb]
pub async fn disable_tun_mode() -> Result<TunStatus> {
    tracing::info!("Disabling TUN mode");
    Ok(TunStatus {
        enabled: false,
        interface_name: None,
        mtu: None,
        error: None,
    })
}

/// Get TUN mode status
#[frb]
pub async fn get_tun_status() -> Result<TunStatus> {
    // Return current TUN status
    Ok(TunStatus {
        enabled: false,
        interface_name: None,
        mtu: None,
        error: None,
    })
}

// ============== UWP Loopback ==============

/// Enable UWP loopback exemption (Windows only)
#[frb]
pub async fn enable_uwp_loopback() -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        tracing::info!("Enabling UWP loopback exemption");

        // Get the path to CheckNetIsolation.exe
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
        Ok(true) // UWP loopback is only relevant on Windows
    }
}

/// Open UWP loopback exemption utility (Windows only)
#[frb]
pub async fn open_uwp_loopback_utility() -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        tracing::info!("Opening UWP loopback exemption utility");

        // Try to open the EnableLoopback utility
        // First try the Windows App SDK version
        let result = Command::new("cmd")
            .args(["/C", "start", "ms-settings:developers"])
            .spawn();

        match result {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::warn!("Failed to open developer settings: {}", e);
                // Fallback: try to open CheckNetIsolation directly
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
        Ok(false) // Not applicable on non-Windows
    }
}

// ============== Android VPN Support ==============

/// Set the Android VPN file descriptor from the native layer
/// This should be called by the Android VpnService when the VPN is established
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

/// Get the current Android VPN file descriptor
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

/// Clear the Android VPN file descriptor (called when VPN stops)
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

/// Set the Android proxy mode
/// mode: "rule", "global", or "direct"
#[frb]
pub fn set_android_proxy_mode(mode: String) {
    // Convert mode string to integer for both netstack and core routing
    let mode_int = match mode.to_lowercase().as_str() {
        "global" => 1,
        "direct" => 2,
        "rule" => 3,
        _ => 0, // use config mode
    };

    // Set the runtime proxy mode in veloguard-core routing
    // This affects how traffic is routed (global = all through proxy, direct = all direct, rule = use rules)
    veloguard_core::set_runtime_proxy_mode(mode_int);
    tracing::info!("Runtime proxy mode set to {} ({})", mode, mode_int);

    #[cfg(target_os = "android")]
    {
        // Also set in netstack for Android-specific handling
        veloguard_netstack::set_android_proxy_mode(mode_int);
        tracing::info!("Android proxy mode set to {} ({})", mode, mode_int);
    }

    #[cfg(not(target_os = "android"))]
    {
        tracing::debug!("set_android_proxy_mode: mode={} applied to routing", mode);
    }
}

/// Get the current Android proxy mode
/// Returns: "rule", "global", or "direct"
#[frb]
pub fn get_android_proxy_mode() -> String {
    // Get from veloguard-core routing which is the source of truth
    match veloguard_core::get_runtime_proxy_mode() {
        1 => "global".to_string(),
        2 => "direct".to_string(),
        3 => "rule".to_string(),
        _ => "rule".to_string(), // default to rule mode
    }
}

/// Start Android VPN packet processing
/// This should be called after the VPN fd is set
#[frb]
pub async fn start_android_vpn() -> Result<bool> {
    #[cfg(target_os = "android")]
    {
        use bytes::BytesMut;
        use std::os::unix::io::FromRawFd;
        use tokio::sync::mpsc;

        let fd = veloguard_netstack::get_android_vpn_fd();
        if fd < 0 {
            tracing::error!("Android VPN fd not set");
            return Ok(false);
        }

        tracing::info!("=== Starting Android VPN packet processing ===");
        tracing::info!("VPN fd={}", fd);

        // Clean up any existing processor first
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
            // Continue anyway, but log the warning
        }

        // Check if protect callback is set
        if veloguard_solidtcp::has_protect_callback() {
            tracing::info!("Socket protect callback is SET");
        } else {
            tracing::error!("Socket protect callback is NOT SET! This will cause routing loops.");
        }

        // CRITICAL: Check if VeloGuard proxy service is running
        let proxy_port = {
            let instance = get_veloguard_instance().await?;
            let veloguard_guard = instance.read().await;
            if let Some(ref veloguard) = *veloguard_guard {
                // Check if proxy is running
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

        // Test if proxy port is actually listening
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
                // Continue anyway, maybe it will start soon
            }
        }

        // Duplicate the file descriptor so we don't take ownership of the original
        // The original fd is owned by VpnService and must remain valid
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            tracing::error!(
                "Failed to duplicate VPN fd: {}",
                std::io::Error::last_os_error()
            );
            return Ok(false);
        }

        tracing::info!("Duplicated VPN fd: {} -> {}", fd, dup_fd);

        // Create async file from the duplicated file descriptor
        // SAFETY: dup_fd is a valid duplicated fd that we own
        let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let async_fd = match tokio::io::unix::AsyncFd::new(file) {
            Ok(fd) => std::sync::Arc::new(fd),
            Err(e) => {
                tracing::error!("Failed to create AsyncFd: {}", e);
                return Ok(false);
            }
        };

        // Create channel for sending packets back to TUN
        let (tun_tx, mut tun_rx) = mpsc::channel::<BytesMut>(4096);

        // Create the VPN processor
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
                        // Log every 100th packet or first 10 packets
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

        // Spawn write task - write packets back to TUN
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

                        // Ensure we write the complete packet
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
                                        // WouldBlock - will retry on next writable
                                    }
                                    Err(_) => {
                                        // Would block, continue to wait for writable
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

/// Stop Android VPN packet processing
#[frb]
pub async fn stop_android_vpn() -> Result<bool> {
    #[cfg(target_os = "android")]
    {
        tracing::info!("=== Stopping Android VPN packet processing ===");

        // Stop the processor first (this will stop the SolidStack)
        if let Some(processor) = crate::get_android_vpn_processor() {
            processor.stop();
            // Clear the Fake-IP pool in SolidStack
            processor.reset_fake_ip_pool();
            tracing::info!("VPN processor stopped and Fake-IP pool reset");
        }

        // Clear the global processor
        crate::clear_android_vpn_processor();

        // Clear the VPN fd
        veloguard_netstack::clear_android_vpn_fd();

        // Clear the socket protect callback
        veloguard_solidtcp::clear_protect_callback();

        tracing::info!("Android VPN packet processing stopped completely");
        Ok(true)
    }

    #[cfg(not(target_os = "android"))]
    {
        tracing::warn!("stop_android_vpn called on non-Android platform");
        Ok(false)
    }
}
