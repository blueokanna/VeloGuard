//! Route management for TUN mode
//!
//! This module handles routing table modifications for TUN-based transparent proxying.
//! When TUN mode is enabled, we need to:
//! 1. Add routes to direct traffic through the TUN interface
//! 2. Exclude proxy server addresses from TUN routing
//! 3. Restore original routes when TUN is disabled

use crate::error::{NetStackError, Result};
use std::net::{IpAddr, Ipv4Addr};
use tracing::warn;

#[cfg(any(windows, target_os = "linux"))]
use std::process::Command;
#[cfg(any(windows, target_os = "linux"))]
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
    /// TUN interface name used by Unix route commands.
    tun_interface_name: Option<String>,
    /// Physical interface that owned the default route before TUN startup.
    original_interface_name: Option<String>,
}

impl RouteManager {
    pub fn new() -> Self {
        Self {
            tun_interface_index: None,
            original_gateway: None,
            original_interface_index: None,
            added_routes: Vec::new(),
            excluded_addresses: Vec::new(),
            tun_interface_name: None,
            original_interface_name: None,
        }
    }

    /// Set the TUN interface index
    pub fn set_tun_interface(&mut self, index: u32) {
        self.tun_interface_index = Some(index);
    }

    pub fn set_tun_interface_name(&mut self, name: impl Into<String>) {
        self.tun_interface_name = Some(name.into());
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

        let tun_idx = self
            .tun_interface_index
            .ok_or_else(|| NetStackError::RoutingError("TUN interface index not set".into()))?;

        // Add routes for excluded addresses via original gateway first
        if let (Some(orig_gw), Some(orig_idx)) =
            (self.original_gateway, self.original_interface_index)
        {
            let excluded = self.excluded_addresses.clone();
            for addr in excluded {
                self.add_host_route(addr, Some(orig_gw), orig_idx)?;
            }
        }

        // Add default route via TUN
        // We use two /1 routes instead of 0.0.0.0/0 to avoid conflicts
        self.add_route(
            Ipv4Addr::new(0, 0, 0, 0).into(),
            1,
            Some(tun_gateway.into()),
            tun_idx,
            1,
        )?;
        self.add_route(
            Ipv4Addr::new(128, 0, 0, 0).into(),
            1,
            Some(tun_gateway.into()),
            tun_idx,
            1,
        )?;

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
            .map_err(|e| {
                NetStackError::RoutingError(format!("Failed to run route print: {}", e))
            })?;

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
    fn add_route(
        &mut self,
        dest: IpAddr,
        prefix_len: u8,
        gateway: Option<IpAddr>,
        if_index: u32,
        metric: u32,
    ) -> Result<()> {
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
    fn add_host_route(
        &mut self,
        dest: IpAddr,
        gateway: Option<IpAddr>,
        if_index: u32,
    ) -> Result<()> {
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

    #[cfg(target_os = "linux")]
    pub fn setup_routes(&mut self, _tun_gateway: Ipv4Addr) -> Result<()> {
        let tun_name = self
            .tun_interface_name
            .clone()
            .ok_or_else(|| NetStackError::RoutingError("TUN interface name not set".into()))?;
        let (gateway, interface) = self.read_linux_default_route()?;
        self.original_gateway = gateway.map(IpAddr::V4);
        self.original_interface_name = Some(interface.clone());

        for address in self.excluded_addresses.clone() {
            let IpAddr::V4(address) = address else {
                warn!(address = %address, "IPv6 route exclusion is not supported by the IPv4 TUN stack");
                continue;
            };
            self.add_linux_route(
                IpAddr::V4(address),
                32,
                gateway.map(IpAddr::V4),
                &interface,
                true,
            )?;
        }

        self.add_linux_route(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, None, &tun_name, false)?;
        self.add_linux_route(
            IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
            1,
            None,
            &tun_name,
            false,
        )?;

        info!(interface = %tun_name, "Linux TUN routes installed");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn restore_routes(&mut self) -> Result<()> {
        let mut first_error = None;
        for route in self.added_routes.drain(..).rev() {
            let cidr = format!("{}/{}", route.destination, route.prefix_len);
            let output = Command::new("ip")
                .args(["-4", "route", "del", &cidr])
                .output()
                .map_err(|error| {
                    NetStackError::RoutingError(format!("Failed to execute ip route del: {error}"))
                })?;
            if !output.status.success() {
                let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
                warn!(route = %cidr, error = %message, "Failed to remove Linux TUN route");
                first_error.get_or_insert(NetStackError::RoutingError(message));
            }
        }
        self.original_gateway = None;
        self.original_interface_name = None;
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn read_linux_default_route(&self) -> Result<(Option<Ipv4Addr>, String)> {
        let output = Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
            .map_err(|error| {
                NetStackError::RoutingError(format!("Failed to inspect default route: {error}"))
            })?;
        if !output.status.success() {
            return Err(NetStackError::RoutingError(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        parse_linux_default_route(&String::from_utf8_lossy(&output.stdout))
    }

    #[cfg(target_os = "linux")]
    fn add_linux_route(
        &mut self,
        destination: IpAddr,
        prefix_len: u8,
        gateway: Option<IpAddr>,
        interface: &str,
        allow_existing: bool,
    ) -> Result<()> {
        let cidr = format!("{destination}/{prefix_len}");
        let mut args = vec![
            "-4".to_string(),
            "route".to_string(),
            "add".to_string(),
            cidr,
        ];
        if let Some(gateway) = gateway {
            args.extend(["via".to_string(), gateway.to_string()]);
        }
        args.extend([
            "dev".to_string(),
            interface.to_string(),
            "metric".to_string(),
            "1".to_string(),
        ]);

        let output = Command::new("ip").args(&args).output().map_err(|error| {
            NetStackError::RoutingError(format!("Failed to execute ip route add: {error}"))
        })?;
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if allow_existing && message.contains("File exists") {
                debug!(route = %args.join(" "), "Keeping existing Linux route exclusion");
                return Ok(());
            }
            return Err(NetStackError::RoutingError(format!(
                "ip {} failed: {}",
                args.join(" "),
                message
            )));
        }

        self.added_routes.push(RouteEntry {
            destination,
            prefix_len,
            gateway,
            interface_index: 0,
            metric: 1,
        });
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn setup_routes(&mut self, _tun_gateway: Ipv4Addr) -> Result<()> {
        Err(NetStackError::RoutingError(
            "Route management is not implemented for this platform".to_string(),
        ))
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn restore_routes(&mut self) -> Result<()> {
        if self.added_routes.is_empty() {
            Ok(())
        } else {
            Err(NetStackError::RoutingError(
                "Cannot restore routes on this platform".to_string(),
            ))
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_default_route(output: &str) -> Result<(Option<Ipv4Addr>, String)> {
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("default "))
        .ok_or_else(|| NetStackError::RoutingError("No IPv4 default route found".to_string()))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let interface = fields
        .windows(2)
        .find_map(|pair| (pair[0] == "dev").then_some(pair[1]))
        .ok_or_else(|| NetStackError::RoutingError("Default route has no interface".to_string()))?;
    let gateway = fields
        .windows(2)
        .find_map(|pair| (pair[0] == "via").then_some(pair[1]))
        .map(str::parse)
        .transpose()
        .map_err(|error| {
            NetStackError::RoutingError(format!("Invalid default gateway: {error}"))
        })?;
    Ok((gateway, interface.to_string()))
}

impl Default for RouteManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        if !self.added_routes.is_empty() {
            warn!(
                "RouteManager dropped with {} routes still active",
                self.added_routes.len()
            );
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

    #[test]
    fn test_parse_linux_default_route() {
        let (gateway, interface) = parse_linux_default_route(
            "default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100\n",
        )
        .unwrap();
        assert_eq!(gateway, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(interface, "eth0");

        let (gateway, interface) =
            parse_linux_default_route("default dev ppp0 scope link\n").unwrap();
        assert_eq!(gateway, None);
        assert_eq!(interface, "ppp0");
    }
}
