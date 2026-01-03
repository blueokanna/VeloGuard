#![allow(unexpected_cfgs)]

mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */

use veloguard_core::VeloGuard;
use flutter_rust_bridge::frb;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::sync::Once;

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

static TRACING_INIT: Once = Once::new();

/// Initialize the VeloGuard FFI bridge
#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
    
    // Initialize tracing for logging
    TRACING_INIT.call_once(|| {
        use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
        
        // Enable debug logging for VPN-related modules
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(
                "info,veloguard_core=debug,veloguard_lib=debug,veloguard_solidtcp=debug,veloguard_netstack=debug"
            ));
        
        #[cfg(target_os = "android")]
        {
            // On Android, use android_logger
            use tracing_subscriber::fmt::format::FmtSpan;
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_span_events(FmtSpan::CLOSE)
                    .without_time())
                .try_init()
                .ok();
        }
        
        #[cfg(not(target_os = "android"))]
        {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_target(true).with_file(true).with_line_number(true))
                .try_init()
                .ok();
        }
        
        tracing::info!("VeloGuard FFI bridge initialized");
    });
}

/// Get the global VeloGuard instance
async fn get_veloguard_instance() -> Result<Arc<RwLock<Option<VeloGuard>>>> {
    Ok(Arc::clone(&VELOGUARD_INSTANCE))
}
