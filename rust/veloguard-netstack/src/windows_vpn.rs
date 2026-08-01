//! Windows compatibility exports for the platform-neutral TUN runtime.

use std::sync::atomic::{AtomicI32, Ordering};
use tracing::info;

pub use crate::vpn::{
    TunPacketProcessor as WindowsVpnProcessor, TunTrafficStats as WindowsVpnTrafficStats,
};

static WINDOWS_PROXY_MODE: AtomicI32 = AtomicI32::new(0);

pub fn set_windows_proxy_mode(mode: i32) {
    WINDOWS_PROXY_MODE.store(mode, Ordering::SeqCst);
    info!(mode, "Windows proxy mode updated");
}

pub fn get_windows_proxy_mode() -> i32 {
    WINDOWS_PROXY_MODE.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_mode_is_accessed_through_functions() {
        set_windows_proxy_mode(2);
        assert_eq!(get_windows_proxy_mode(), 2);
        set_windows_proxy_mode(0);
    }
}
