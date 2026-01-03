//! Route management for TUN mode
//!
//! This module handles routing table modifications for TUN-based transparent proxying.
//! When TUN mode is enabled, we need to:
//! 1. Add routes to direct traffic through the TUN interface
//! 2. Exclude proxy server addresses from TUN routing
//! 3. Restore original routes when TUN is disabled

use crate::error::Result;
use std::net::{IpAddr, Ipv4Addr};
use tracing::warn;

#[cfg(windows)]
use crate::error::NetStackError;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use tracing::{debug, info};

/// Route entry for tracking added routes
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub gateway: Option<IpAddr>,
    pub interface_index: u32,
    pub metric: u32,
}

/// Route manager for TUN mode
#[allow(dead_code)]
pub struct RouteManager {
    /// TUN interface index
    tun_interface_index: Option<u32>,
    /// Original default gateway
    original_gateway: Option<IpAddr>,
    /// Original default interface index
    original_interface_index: Option<u32>,
    /// Routes we've added (for cleanup)
    added_routes: Vec<RouteEntry>,
    /// Excluded addresses (proxy servers, etc.)
    excluded_addresses: Vec<IpAddr>,
}

impl RouteManager {
    pub fn new() -> Self {
        Self {
            tun_interface_index: None,
            original_gateway: None,
            original_interface_index: None,
            added_routes: Vec::new(),
            excluded_addresses: Vec::new(),
        }
    }

    /// Set the TUN interface index
    pub fn set_tun_interface(&mut self, index: u32) {
        self.tun_interface_index = Some(index);
    }

    /// Add an address to exclude from TUN routing (e.g., proxy server)
    pub fn exclude_address(&mut self, addr: IpAddr) {
        if !self.excluded_addresses.contains(&addr) {
            self.excluded_addresses.push(addr);
        }
    }

    /// Setup routes for TUN mode
    #[cfg(windows)]
    pub fn setup_routes(&mut self, tun_gateway: Ipv4Addr) -> Result<()> {
        info!("Setting up TUN routes with gateway: {}", tun_gateway);

        // Get current default route info
        self.save_original_routes()?;

        let tun_idx = self.tun_interface_index
            .ok_or_else(|| NetStackError::RoutingError("TUN interface index not set".into()))?;

        // Add routes for excluded addresses via original gateway first
        if let (Some(orig_gw), Some(orig_idx)) = (self.original_gateway, self.original_interface_index) {
            let excluded = self.excluded_addresses.clone();
            for addr in excluded {
                self.add_host_route(addr, Some(orig_gw), orig_idx)?;
            }
        }

        // Add default route via TUN
        // We use two /1 routes instead of 0.0.0.0/0 to avoid conflicts
        self.add_route(Ipv4Addr::new(0, 0, 0, 0).into(), 1, Some(tun_gateway.into()), tun_idx, 1)?;
        self.add_route(Ipv4Addr::new(128, 0, 0, 0).into(), 1, Some(tun_gateway.into()), tun_idx, 1)?;

        info!("TUN routes configured successfully");
        Ok(())
    }

    /// Restore original routes
    #[cfg(windows)]
    pub fn restore_routes(&mut self) -> Result<()> {
        info!("Restoring original routes");

        // Remove all routes we added
        for route in self.added_routes.drain(..).collect::<Vec<_>>() {
            if let Err(e) = self.delete_route(&route) {
                warn!("Failed to delete route {:?}: {}", route, e);
            }
        }

        info!("Original routes restored");
        Ok(())
    }

    #[cfg(windows)]
    fn save_original_routes(&mut self) -> Result<()> {
        // Use route print to get default gateway
        let output = Command::new("route")
            .args(["print", "0.0.0.0"])
            .output()
            .map_err(|e| NetStackError::RoutingError(format!("Failed to run route print: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse output to find default gateway
        for line in stdout.lines() {
            if line.contains("0.0.0.0") && !line.contains("On-link") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(gw) = parts[2].parse::<Ipv4Addr>() {
                        if !gw.is_unspecified() {
                            self.original_gateway = Some(gw.into());
                            debug!("Found original gateway: {}", gw);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn add_route(&mut self, dest: IpAddr, prefix_len: u8, gateway: Option<IpAddr>, if_index: u32, metric: u32) -> Result<()> {
        let mask = prefix_to_netmask(prefix_len);
        
        let mut args = vec![
            "add".to_string(),
            dest.to_string(),
            "mask".to_string(),
            mask.to_string(),
        ];

        if let Some(gw) = gateway {
            args.push(gw.to_string());
        }

        args.push("if".to_string());
        args.push(if_index.to_string());
        args.push("metric".to_string());
        args.push(metric.to_string());

        debug!("Adding route: route {}", args.join(" "));

        let output = Command::new("route")
            .args(&args)
            .output()
            .map_err(|e| NetStackError::RoutingError(format!("Failed to add route: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "route already exists" errors
            if !stderr.contains("already exists") && !stderr.is_empty() {
                warn!("Route add warning: {}", stderr);
            }
        }

        self.added_routes.push(RouteEntry {
            destination: dest,
            prefix_len,
            gateway,
            interface_index: if_index,
            metric,
        });

        Ok(())
    }

    #[cfg(windows)]
    fn add_host_route(&mut self, dest: IpAddr, gateway: Option<IpAddr>, if_index: u32) -> Result<()> {
        self.add_route(dest, 32, gateway, if_index, 1)
    }

    #[cfg(windows)]
    fn delete_route(&self, route: &RouteEntry) -> Result<()> {
        let mask = prefix_to_netmask(route.prefix_len);

        let mut args = vec![
            "delete".to_string(),
            route.destination.to_string(),
            "mask".to_string(),
            mask.to_string(),
        ];

        if let Some(gw) = route.gateway {
            args.push(gw.to_string());
        }

        debug!("Deleting route: route {}", args.join(" "));

        let output = Command::new("route")
            .args(&args)
            .output()
            .map_err(|e| NetStackError::RoutingError(format!("Failed to delete route: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                debug!("Route delete warning: {}", stderr);
            }
        }

        Ok(())
    }

    // Unix stubs
    #[cfg(unix)]
    pub fn setup_routes(&mut self, _tun_gateway: Ipv4Addr) -> Result<()> {
        // TODO: Implement for Linux/macOS
        warn!("Route management not yet implemented for this platform");
        Ok(())
    }

    #[cfg(unix)]
    pub fn restore_routes(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Default for RouteManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        if !self.added_routes.is_empty() {
            warn!("RouteManager dropped with {} routes still active", self.added_routes.len());
            let _ = self.restore_routes();
        }
    }
}

/// Convert prefix length to netmask string
#[allow(dead_code)]
fn prefix_to_netmask(prefix: u8) -> String {
    if prefix == 0 {
        return "0.0.0.0".to_string();
    }
    if prefix >= 32 {
        return "255.255.255.255".to_string();
    }
    
    let mask: u32 = !0u32 << (32 - prefix);
    let octets = [
        ((mask >> 24) & 0xFF) as u8,
        ((mask >> 16) & 0xFF) as u8,
        ((mask >> 8) & 0xFF) as u8,
        (mask & 0xFF) as u8,
    ];
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(0), "0.0.0.0");
        assert_eq!(prefix_to_netmask(1), "128.0.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
    }
}
