//! Android compatibility exports for the platform-neutral TUN runtime.

pub use crate::vpn::{
    TunPacketProcessor as AndroidVpnProcessor, TunTrafficStats as VpnTrafficStats,
};
