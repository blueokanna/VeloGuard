//! Hosts file support for static DNS mappings

use std::collections::HashMap;
use std::net::IpAddr;
use tracing::debug;

/// Hosts file for static DNS mappings
#[derive(Debug, Clone, Default)]
pub struct HostsFile {
    /// Domain to IP mappings
    entries: HashMap<String, Vec<IpAddr>>,
}

impl HostsFile {
    /// Create a new empty hosts file
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Create from a map of entries
    pub fn from_map(map: HashMap<String, IpAddr>) -> Self {
        let entries = map
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), vec![v]))
            .collect();
        Self { entries }
    }

    /// Add an entry
    pub fn add(&mut self, domain: &str, ip: IpAddr) {
        let domain = domain.to_lowercase();
        self.entries
            .entry(domain)
            .or_default()
            .push(ip);
    }

    /// Lookup a domain
    pub fn lookup(&self, domain: &str) -> Option<&[IpAddr]> {
        let domain = domain.to_lowercase();
        self.entries.get(&domain).map(|v| v.as_slice())
    }

    /// Check if a domain exists
    pub fn contains(&self, domain: &str) -> bool {
        self.entries.contains_key(&domain.to_lowercase())
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Parse hosts file content
    pub fn parse(content: &str) -> Self {
        let mut hosts = Self::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Split by whitespace
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            // First part is IP, rest are hostnames
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                for hostname in &parts[1..] {
                    // Skip comments in the middle of line
                    if hostname.starts_with('#') {
                        break;
                    }
                    hosts.add(hostname, ip);
                }
            }
        }

        debug!("Parsed {} hosts entries", hosts.len());
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_hosts_basic() {
        let mut hosts = HostsFile::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        hosts.add("localhost", ip);

        assert!(hosts.contains("localhost"));
        assert!(hosts.contains("LOCALHOST")); // Case insensitive
        assert_eq!(hosts.lookup("localhost"), Some(&[ip][..]));
    }

    #[test]
    fn test_hosts_parse() {
        let content = r#"
# This is a comment
127.0.0.1   localhost
127.0.0.1   localhost.localdomain
192.168.1.1 router gateway # inline comment

# Another comment
::1         localhost ip6-localhost
"#;

        let hosts = HostsFile::parse(content);

        assert!(hosts.contains("localhost"));
        assert!(hosts.contains("router"));
        assert!(hosts.contains("gateway"));
        assert!(hosts.contains("ip6-localhost"));
    }
}
