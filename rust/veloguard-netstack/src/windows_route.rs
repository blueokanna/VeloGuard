//! Windows route management for TUN/VPN mode
//!
//! This module handles Windows routing table manipulation for global proxy mode.
//! It adds/removes routes to redirect traffic through the TUN interface.

use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{error, info, warn};

/// Windows route manager for TUN mode
pub struct WindowsRouteManager {
    /// TUN interface name
    interface_name: String,
    /// TUN gateway address
    gateway: Ipv4Addr,
    /// Original default gateway (saved for restoration)
    original_gateway: Option<String>,
    /// Original interface index
    original_interface: Option<u32>,
    /// Whether routes are currently active
    routes_active: bool,
    /// Routes owned by this manager, in creation order.
    added_routes: Vec<WindowsRouteEntry>,
}

struct WindowsRouteEntry {
    destination: String,
    mask: String,
    gateway: String,
    interface_index: u32,
}

impl WindowsRouteManager {
    /// Create a new route manager
    pub fn new(interface_name: &str, gateway: Ipv4Addr) -> Self {
        Self {
            interface_name: interface_name.to_string(),
            gateway,
            original_gateway: None,
            original_interface: None,
            routes_active: false,
            added_routes: Vec::new(),
        }
    }

    /// Get the interface index for the TUN adapter
    fn get_interface_index(&self) -> Option<u32> {
        let output = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "(Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue).ifIndex",
                    self.interface_name
                ),
            ])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.trim().parse().ok()
    }

    /// Save the current default gateway for later restoration
    fn save_original_gateway(&mut self) -> Result<(), String> {
        let output = match Command::new("powershell")
            .args([
                "-Command",
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 | ForEach-Object { \"$($_.NextHop)|$($_.InterfaceIndex)\" }",
            ])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                error!("Failed to get original gateway: {}", e);
                return Err(format!("Failed to get original gateway: {e}"));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = stdout.trim().split('|').collect();
        
        if parts.len() >= 2 {
            self.original_gateway = Some(parts[0].to_string());
            self.original_interface = parts[1].parse().ok();
            info!(
                "Saved original gateway: {:?}, interface: {:?}",
                self.original_gateway, self.original_interface
            );
            if self.original_gateway.as_deref().is_some_and(str::is_empty)
                || self.original_interface.is_none()
            {
                return Err("Default route contains an invalid gateway or interface".to_string());
            }
            Ok(())
        } else {
            Err(format!("Could not parse original gateway info: {stdout}"))
        }
    }

    /// Enable global mode by adding routes through TUN
    pub fn enable_global_mode(&mut self, excluded_ips: &[Ipv4Addr]) -> Result<(), String> {
        if self.routes_active {
            info!("Routes already active, skipping");
            return Ok(());
        }

        info!("Enabling global mode routes for interface: {}", self.interface_name);

        // Get TUN interface index
        let if_index = self.get_interface_index()
            .ok_or_else(|| format!("Could not find interface: {}", self.interface_name))?;
        
        info!("TUN interface index: {}", if_index);

        // Save original gateway
        self.save_original_gateway()?;
        self.routes_active = true;

        let original_gateway = self
            .original_gateway
            .clone()
            .ok_or_else(|| "Original gateway not saved".to_string())?;
        let original_interface = self
            .original_interface
            .ok_or_else(|| "Original interface not saved".to_string())?;
        for address in excluded_ips {
            if let Err(error) = self.add_managed_route(
                &address.to_string(),
                "255.255.255.255",
                &original_gateway,
                original_interface,
            ) {
                let rollback_error = self.disable_global_mode().err();
                return Err(match rollback_error {
                    Some(rollback) => format!("{error}; rollback failed: {rollback}"),
                    None => error,
                });
            }
        }

        // Add routes for 0.0.0.0/1 and 128.0.0.0/1 through TUN
        // This covers all IPv4 addresses without replacing the default route
        let routes = [
            ("0.0.0.0", "128.0.0.0"),    // 0.0.0.0/1
            ("128.0.0.0", "128.0.0.0"),  // 128.0.0.0/1
        ];

        for (dest, mask) in routes {
            if let Err(error) = self.add_managed_route(
                dest,
                mask,
                &self.gateway.to_string(),
                if_index,
            ) {
                let rollback_error = self.disable_global_mode().err();
                return Err(match rollback_error {
                    Some(rollback) => format!("{error}; rollback failed: {rollback}"),
                    None => error,
                });
            }
        }
        info!("Global mode routes enabled successfully");
        Ok(())
    }

    /// Disable global mode by removing TUN routes
    pub fn disable_global_mode(&mut self) -> Result<(), String> {
        if !self.routes_active {
            info!("Routes not active, skipping");
            return Ok(());
        }

        info!("Disabling global mode routes");

        let mut failed = Vec::new();
        for route in std::mem::take(&mut self.added_routes).into_iter().rev() {
            let output = Command::new("route")
                .args([
                    "delete",
                    &route.destination,
                    "mask",
                    &route.mask,
                    &route.gateway,
                    "if",
                    &route.interface_index.to_string(),
                ])
                .output();
            match output {
                Ok(output) if output.status.success() => {
                    info!("Removed route: {} mask {}", route.destination, route.mask);
                }
                Ok(output) => {
                    let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    warn!("Failed to remove route {}: {}", route.destination, message);
                    failed.push(route);
                }
                Err(error) => {
                    warn!("Failed to remove route {}: {}", route.destination, error);
                    failed.push(route);
                }
            }
        }
        failed.reverse();
        self.added_routes = failed;
        self.routes_active = !self.added_routes.is_empty();
        if self.routes_active {
            return Err(format!(
                "{} managed route(s) could not be removed",
                self.added_routes.len()
            ));
        }
        info!("Global mode routes disabled");
        Ok(())
    }

    /// Check if routes are currently active
    pub fn is_active(&self) -> bool {
        self.routes_active
    }

    /// Add a specific route through TUN
    pub fn add_route(&mut self, destination: &str, mask: &str) -> Result<(), String> {
        let if_index = self.get_interface_index()
            .ok_or_else(|| format!("Could not find interface: {}", self.interface_name))?;

        self.add_managed_route(destination, mask, &self.gateway.to_string(), if_index)
    }

    /// Remove a specific route
    pub fn remove_route(&self, destination: &str, mask: &str) -> Result<(), String> {
        let result = Command::new("route")
            .args(["delete", destination, "mask", mask])
            .output()
            .map_err(|e| format!("Route command failed: {}", e))?;

        if result.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&result.stderr);
            Err(format!("Failed to remove route: {}", stderr))
        }
    }

    /// Exclude a specific IP from TUN routing (for proxy server)
    pub fn exclude_ip(&mut self, ip: &str) -> Result<(), String> {
        // Get the original gateway to route excluded IPs
        let gateway = self.original_gateway.clone()
            .ok_or_else(|| "Original gateway not saved".to_string())?;
        
        let if_index = self.original_interface
            .ok_or_else(|| "Original interface not saved".to_string())?;

        self.add_managed_route(ip, "255.255.255.255", &gateway, if_index)
    }

    fn add_managed_route(
        &mut self,
        destination: &str,
        mask: &str,
        gateway: &str,
        interface_index: u32,
    ) -> Result<(), String> {
        let result = Command::new("route")
            .args([
                "add",
                destination,
                "mask",
                mask,
                gateway,
                "metric",
                "1",
                "if",
                &interface_index.to_string(),
            ])
            .output()
            .map_err(|e| format!("Route command failed: {}", e))?;

        if result.status.success() {
            self.added_routes.push(WindowsRouteEntry {
                destination: destination.to_string(),
                mask: mask.to_string(),
                gateway: gateway.to_string(),
                interface_index,
            });
            info!("Added managed route: {} mask {}", destination, mask);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();
            Err(format!(
                "Failed to add route {destination} mask {mask}: {stderr}"
            ))
        }
    }
}

impl Drop for WindowsRouteManager {
    fn drop(&mut self) {
        if self.routes_active {
            if let Err(e) = self.disable_global_mode() {
                error!("Failed to cleanup routes on drop: {}", e);
            }
        }
    }
}

/// Set Windows DNS servers for the TUN interface
pub fn set_tun_dns(interface_name: &str, dns_servers: &[Ipv4Addr]) -> Result<(), String> {
    // First, set DNS for the TUN interface
    for (i, dns) in dns_servers.iter().enumerate() {
        let action = if i == 0 { "set" } else { "add" };
        let result = Command::new("netsh")
            .args([
                "interface",
                "ip",
                action,
                "dns",
                &format!("name=\"{}\"", interface_name),
                &format!("addr={}", dns),
            ])
            .output()
            .map_err(|e| format!("netsh command failed: {}", e))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            warn!("Failed to set DNS {}: {}", dns, stderr);
        }
    }

    // Set the TUN interface metric to be lower (higher priority) than other interfaces
    // This ensures DNS queries prefer the TUN interface
    let _ = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Set-NetIPInterface -InterfaceAlias '{}' -InterfaceMetric 1",
                interface_name
            ),
        ])
        .output();

    info!("TUN DNS configured: {:?}", dns_servers);
    Ok(())
}

/// Flush DNS cache
pub fn flush_dns_cache() -> Result<(), String> {
    let result = Command::new("ipconfig")
        .args(["/flushdns"])
        .output()
        .map_err(|e| format!("ipconfig command failed: {}", e))?;

    if result.status.success() {
        info!("DNS cache flushed");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&result.stderr);
        Err(format!("Failed to flush DNS: {}", stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_manager_creation() {
        let manager = WindowsRouteManager::new("VeloGuard", Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(manager.interface_name, "VeloGuard");
        assert!(!manager.is_active());
    }
}
