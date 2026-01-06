#![allow(unexpected_cfgs)]

mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */

use veloguard_core::VeloGuard;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod api;
mod error;
mod types;

#[cfg(target_os = "android")]
pub mod android_jni;

pub use api::*;
pub use error::*;
pub use types::*;

/// Global VeloGuard instance for FFI
static VELOGUARD_INSTANCE: once_cell::sync::Lazy<Arc<RwLock<Option<VeloGuard>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Global Android VPN processor for stats tracking
#[cfg(target_os = "android")]
static ANDROID_VPN_PROCESSOR: once_cell::sync::Lazy<Arc<parking_lot::RwLock<Option<Arc<veloguard_netstack::AndroidVpnProcessor>>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

/// Global Windows VPN processor for stats tracking
#[cfg(windows)]
static WINDOWS_VPN_PROCESSOR: once_cell::sync::Lazy<Arc<parking_lot::RwLock<Option<Arc<veloguard_netstack::WindowsVpnProcessor>>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

/// Global Windows route manager
#[cfg(windows)]
static WINDOWS_ROUTE_MANAGER: once_cell::sync::Lazy<Arc<parking_lot::RwLock<Option<veloguard_netstack::WindowsRouteManager>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

/// Global Windows TUN device
#[cfg(windows)]
static WINDOWS_TUN_DEVICE: once_cell::sync::Lazy<Arc<parking_lot::RwLock<Option<veloguard_netstack::TunDevice>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

/// Set the global Android VPN processor
#[cfg(target_os = "android")]
pub fn set_android_vpn_processor(processor: Arc<veloguard_netstack::AndroidVpnProcessor>) {
    let mut guard = ANDROID_VPN_PROCESSOR.write();
    *guard = Some(processor);
    tracing::info!("Android VPN processor stored globally for stats tracking");
}

/// Clear the global Android VPN processor
#[cfg(target_os = "android")]
pub fn clear_android_vpn_processor() {
    let mut guard = ANDROID_VPN_PROCESSOR.write();
    *guard = None;
    tracing::info!("Android VPN processor cleared");
}

/// Get the global Android VPN processor
#[cfg(target_os = "android")]
pub fn get_android_vpn_processor() -> Option<Arc<veloguard_netstack::AndroidVpnProcessor>> {
    let guard = ANDROID_VPN_PROCESSOR.read();
    guard.clone()
}

/// Set the global Windows VPN processor
#[cfg(windows)]
pub fn set_windows_vpn_processor(processor: Arc<veloguard_netstack::WindowsVpnProcessor>) {
    let mut guard = WINDOWS_VPN_PROCESSOR.write();
    *guard = Some(processor);
    tracing::info!("Windows VPN processor stored globally for stats tracking");
}

/// Clear the global Windows VPN processor
#[cfg(windows)]
pub fn clear_windows_vpn_processor() {
    let mut guard = WINDOWS_VPN_PROCESSOR.write();
    *guard = None;
    tracing::info!("Windows VPN processor cleared");
}

/// Get the global Windows VPN processor
#[cfg(windows)]
pub fn get_windows_vpn_processor() -> Option<Arc<veloguard_netstack::WindowsVpnProcessor>> {
    let guard = WINDOWS_VPN_PROCESSOR.read();
    guard.clone()
}

/// Set the global Windows route manager
#[cfg(windows)]
pub fn set_windows_route_manager(manager: veloguard_netstack::WindowsRouteManager) {
    let mut guard = WINDOWS_ROUTE_MANAGER.write();
    *guard = Some(manager);
    tracing::info!("Windows route manager stored globally");
}

/// Get the global Windows route manager
#[cfg(windows)]
pub fn get_windows_route_manager() -> Option<parking_lot::MappedRwLockReadGuard<'static, veloguard_netstack::WindowsRouteManager>> {
    let guard = WINDOWS_ROUTE_MANAGER.read();
    if guard.is_some() {
        Some(parking_lot::RwLockReadGuard::map(guard, |opt| opt.as_ref().unwrap()))
    } else {
        None
    }
}

/// Get mutable access to the global Windows route manager
#[cfg(windows)]
pub fn get_windows_route_manager_mut() -> Option<parking_lot::MappedRwLockWriteGuard<'static, veloguard_netstack::WindowsRouteManager>> {
    let guard = WINDOWS_ROUTE_MANAGER.write();
    if guard.is_some() {
        Some(parking_lot::RwLockWriteGuard::map(guard, |opt| opt.as_mut().unwrap()))
    } else {
        None
    }
}

/// Clear the global Windows route manager
#[cfg(windows)]
pub fn clear_windows_route_manager() {
    let mut guard = WINDOWS_ROUTE_MANAGER.write();
    *guard = None;
    tracing::info!("Windows route manager cleared");
}

/// Set the global Windows TUN device
#[cfg(windows)]
pub fn set_windows_tun_device(device: veloguard_netstack::TunDevice) {
    let mut guard = WINDOWS_TUN_DEVICE.write();
    *guard = Some(device);
    tracing::info!("Windows TUN device stored globally");
}

/// Clear the global Windows TUN device
#[cfg(windows)]
pub fn clear_windows_tun_device() {
    let mut guard = WINDOWS_TUN_DEVICE.write();
    *guard = None;
    tracing::info!("Windows TUN device cleared");
}

/// Take the global Windows TUN device (removes it from global state)
#[cfg(windows)]
pub fn take_windows_tun_device() -> Option<veloguard_netstack::TunDevice> {
    let mut guard = WINDOWS_TUN_DEVICE.write();
    guard.take()
}

/// Get the global VeloGuard instance
async fn get_veloguard_instance() -> Result<Arc<RwLock<Option<VeloGuard>>>> {
    Ok(Arc::clone(&VELOGUARD_INSTANCE))
}

#[cfg(test)]
mod tests {
    use super::types::*;
    use proptest::prelude::*;
    
    // Generators for DTO types
    fn arb_traffic_stats_dto() -> impl Strategy<Value = TrafficStatsDto> {
        (
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u32>(),
            any::<u64>(),
        ).prop_map(|(upload, download, total_upload, total_download, connection_count, uptime_secs)| {
            TrafficStatsDto {
                upload,
                download,
                total_upload,
                total_download,
                connection_count,
                uptime_secs,
            }
        })
    }
    
    fn arb_connection_dto() -> impl Strategy<Value = ConnectionDto> {
        (
            "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}",
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}",
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
            proptest::option::of("[a-z]{3,10}\\.[a-z]{2,3}"),
            prop_oneof!["TCP", "UDP", "HTTP", "SOCKS5"],
            "[a-z]{3,10}",
            any::<u64>(),
            any::<u64>(),
            any::<i64>(),
            proptest::option::of("[A-Z]{3,10}"),
        ).prop_map(|(id, src_addr, dst_addr, dst_domain, protocol, outbound, upload, download, start_time, rule)| {
            ConnectionDto {
                id,
                src_addr,
                dst_addr,
                dst_domain,
                protocol,
                outbound,
                upload,
                download,
                start_time,
                rule,
            }
        })
    }
    
    fn arb_proxy_info_dto() -> impl Strategy<Value = ProxyInfoDto> {
        (
            "[a-z]{3,10}",
            prop_oneof!["direct", "reject", "shadowsocks", "vmess", "trojan", "wireguard"],
            proptest::option::of("[a-z]{3,10}\\.[a-z]{2,3}"),
            proptest::option::of(1u16..65535u16),
            proptest::option::of(1u64..10000u64),
            any::<bool>(),
        ).prop_map(|(tag, protocol_type, server, port, latency_ms, alive)| {
            ProxyInfoDto {
                tag,
                protocol_type,
                server,
                port,
                latency_ms,
                alive,
            }
        })
    }
    
    fn arb_proxy_group_dto() -> impl Strategy<Value = ProxyGroupDto> {
        (
            "[a-z]{3,10}",
            prop_oneof!["selector", "url-test", "fallback", "load-balance"],
            proptest::collection::vec("[a-z]{3,10}", 1..5),
            "[a-z]{3,10}",
        ).prop_map(|(tag, group_type, proxies, selected)| {
            ProxyGroupDto {
                tag,
                group_type,
                proxies,
                selected,
            }
        })
    }
    
    fn arb_rule_dto() -> impl Strategy<Value = RuleDto> {
        (
            prop_oneof!["domain", "domain-suffix", "domain-keyword", "ip-cidr", "geoip", "match"],
            "[a-z]{3,20}",
            "[a-z]{3,10}",
            any::<u64>(),
        ).prop_map(|(rule_type, payload, outbound, matched_count)| {
            RuleDto {
                rule_type,
                payload,
                outbound,
                matched_count,
            }
        })
    }
    
    fn arb_dns_config_dto() -> impl Strategy<Value = DnsConfigDto> {
        (
            any::<bool>(),
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}",
            prop_oneof!["normal", "fake-ip"],
            proptest::collection::vec("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}", 1..3),
            proptest::collection::vec("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}", 0..2),
        ).prop_map(|(enable, listen, enhanced_mode, nameservers, fallback)| {
            DnsConfigDto {
                enable,
                listen,
                enhanced_mode,
                nameservers,
                fallback,
            }
        })
    }
    
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        /// **Feature: rust-codebase-optimization, Property 7: FFI Serialization Round-Trip**
        /// **Validates: Requirements 11.1-11.6**
        /// For any TrafficStatsDto, serializing to JSON and deserializing back produces an equivalent value
        #[test]
        fn test_traffic_stats_dto_roundtrip(dto in arb_traffic_stats_dto()) {
            let json = serde_json::to_string(&dto).expect("Failed to serialize");
            let deserialized: TrafficStatsDto = serde_json::from_str(&json).expect("Failed to deserialize");
            
            prop_assert_eq!(dto.upload, deserialized.upload);
            prop_assert_eq!(dto.download, deserialized.download);
            prop_assert_eq!(dto.total_upload, deserialized.total_upload);
            prop_assert_eq!(dto.total_download, deserialized.total_download);
            prop_assert_eq!(dto.connection_count, deserialized.connection_count);
            prop_assert_eq!(dto.uptime_secs, deserialized.uptime_secs);
        }
        
        /// **Feature: rust-codebase-optimization, Property 7: FFI Serialization Round-Trip**
        /// **Validates: Requirements 11.1-11.6**
        /// For any ConnectionDto, serializing to JSON and deserializing back produces an equivalent value
        #[test]
        fn test_connection_dto_roundtrip(dto in arb_connection_dto()) {
            let json = serde_json::to_string(&dto).expect("Failed to serialize");
            let deserialized: ConnectionDto = serde_json::from_str(&json).expect("Failed to deserialize");
            
            prop_assert_eq!(dto.id, deserialized.id);
            prop_assert_eq!(dto.src_addr, deserialized.src_addr);
            prop_assert_eq!(dto.dst_addr, deserialized.dst_addr);
            prop_assert_eq!(dto.dst_domain, deserialized.dst_domain);
            prop_assert_eq!(dto.protocol, deserialized.protocol);
            prop_assert_eq!(dto.outbound, deserialized.outbound);
            prop_assert_eq!(dto.upload, deserialized.upload);
            prop_assert_eq!(dto.download, deserialized.download);
            prop_assert_eq!(dto.start_time, deserialized.start_time);
            prop_assert_eq!(dto.rule, deserialized.rule);
        }
        
        /// **Feature: rust-codebase-optimization, Property 7: FFI Serialization Round-Trip**
        /// **Validates: Requirements 11.1-11.6**
        /// For any ProxyInfoDto, serializing to JSON and deserializing back produces an equivalent value
        #[test]
        fn test_proxy_info_dto_roundtrip(dto in arb_proxy_info_dto()) {
            let json = serde_json::to_string(&dto).expect("Failed to serialize");
            let deserialized: ProxyInfoDto = serde_json::from_str(&json).expect("Failed to deserialize");
            
            prop_assert_eq!(dto.tag, deserialized.tag);
            prop_assert_eq!(dto.protocol_type, deserialized.protocol_type);
            prop_assert_eq!(dto.server, deserialized.server);
            prop_assert_eq!(dto.port, deserialized.port);
            prop_assert_eq!(dto.latency_ms, deserialized.latency_ms);
            prop_assert_eq!(dto.alive, deserialized.alive);
        }
        
        /// **Feature: rust-codebase-optimization, Property 7: FFI Serialization Round-Trip**
        /// **Validates: Requirements 11.1-11.6**
        /// For any ProxyGroupDto, serializing to JSON and deserializing back produces an equivalent value
        #[test]
        fn test_proxy_group_dto_roundtrip(dto in arb_proxy_group_dto()) {
            let json = serde_json::to_string(&dto).expect("Failed to serialize");
            let deserialized: ProxyGroupDto = serde_json::from_str(&json).expect("Failed to deserialize");
            
            prop_assert_eq!(dto.tag, deserialized.tag);
            prop_assert_eq!(dto.group_type, deserialized.group_type);
            prop_assert_eq!(dto.proxies, deserialized.proxies);
            prop_assert_eq!(dto.selected, deserialized.selected);
        }
        
        /// **Feature: rust-codebase-optimization, Property 7: FFI Serialization Round-Trip**
        /// **Validates: Requirements 11.1-11.6**
        /// For any RuleDto, serializing to JSON and deserializing back produces an equivalent value
        #[test]
        fn test_rule_dto_roundtrip(dto in arb_rule_dto()) {
            let json = serde_json::to_string(&dto).expect("Failed to serialize");
            let deserialized: RuleDto = serde_json::from_str(&json).expect("Failed to deserialize");
            
            prop_assert_eq!(dto.rule_type, deserialized.rule_type);
            prop_assert_eq!(dto.payload, deserialized.payload);
            prop_assert_eq!(dto.outbound, deserialized.outbound);
            prop_assert_eq!(dto.matched_count, deserialized.matched_count);
        }
        
        /// **Feature: rust-codebase-optimization, Property 7: FFI Serialization Round-Trip**
        /// **Validates: Requirements 11.1-11.6**
        /// For any DnsConfigDto, serializing to JSON and deserializing back produces an equivalent value
        #[test]
        fn test_dns_config_dto_roundtrip(dto in arb_dns_config_dto()) {
            let json = serde_json::to_string(&dto).expect("Failed to serialize");
            let deserialized: DnsConfigDto = serde_json::from_str(&json).expect("Failed to deserialize");
            
            prop_assert_eq!(dto.enable, deserialized.enable);
            prop_assert_eq!(dto.listen, deserialized.listen);
            prop_assert_eq!(dto.enhanced_mode, deserialized.enhanced_mode);
            prop_assert_eq!(dto.nameservers, deserialized.nameservers);
            prop_assert_eq!(dto.fallback, deserialized.fallback);
        }
    }
}
