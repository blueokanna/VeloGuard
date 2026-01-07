use crate::error::{Error, Result};
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct GeoIpDatabase {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpDatabase {
    pub fn new() -> Self {
        Self { reader: None }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = Reader::open_readfile(path.as_ref()).map_err(|e| {
            Error::config(format!("Failed to load GeoIP database: {}", e))
        })?;
        Ok(Self {
            reader: Some(reader),
        })
    }

    pub fn load_from_bytes(data: Vec<u8>) -> Result<Self> {
        let reader = Reader::from_source(data).map_err(|e| {
            Error::config(format!("Failed to load GeoIP database from bytes: {}", e))
        })?;
        Ok(Self {
            reader: Some(reader),
        })
    }

    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let lookup_result = reader.lookup(ip).ok()?;
        let country_data: geoip2::Country = lookup_result.decode().ok()??;
        country_data.country.iso_code.map(|s| s.to_uppercase())
    }

    pub fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        if let Some(lookup_country) = self.lookup_country(ip) {
            lookup_country.eq_ignore_ascii_case(country_code)
        } else {
            self.fallback_country_match(country_code, ip)
        }
    }

    fn fallback_country_match(&self, country_code: &str, ip: IpAddr) -> bool {
        let code_upper = country_code.to_uppercase();
        
        if code_upper == "LAN" || code_upper == "PRIVATE" {
            return is_private_ip(ip);
        }
        
        false
    }
}

impl Default for GeoIpDatabase {
    fn default() -> Self {
        Self::new()
    }
}

pub struct GeoIpManager {
    database: Arc<RwLock<GeoIpDatabase>>,
}

impl GeoIpManager {
    pub fn new() -> Self {
        Self {
            database: Arc::new(RwLock::new(GeoIpDatabase::new())),
        }
    }

    pub async fn load_database<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let db = GeoIpDatabase::load_from_file(path)?;
        let mut guard = self.database.write().await;
        *guard = db;
        tracing::info!("GeoIP database loaded successfully");
        Ok(())
    }

    pub async fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        let db = GeoIpDatabase::load_from_bytes(data)?;
        let mut guard = self.database.write().await;
        *guard = db;
        tracing::info!("GeoIP database loaded from bytes successfully");
        Ok(())
    }

    pub async fn is_loaded(&self) -> bool {
        self.database.read().await.is_loaded()
    }

    pub async fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        self.database.read().await.lookup_country(ip)
    }

    pub async fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        self.database.read().await.matches_country(country_code, ip)
    }
}

impl Default for GeoIpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for GeoIpManager {
    fn clone(&self) -> Self {
        Self {
            database: Arc::clone(&self.database),
        }
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
                || ipv4.is_unspecified()
                || is_cgnat(ipv4)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || is_ipv6_private(&ipv6)
        }
    }
}

fn is_cgnat(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127)
}

fn is_ipv6_private(ip: &std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || ip.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_private_ipv4() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_private_ipv6() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_geoip_database_new() {
        let db = GeoIpDatabase::new();
        assert!(!db.is_loaded());
    }

    #[test]
    fn test_fallback_lan_match() {
        let db = GeoIpDatabase::new();
        assert!(db.matches_country("LAN", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(db.matches_country("PRIVATE", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!db.matches_country("US", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
