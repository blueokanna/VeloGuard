//! Bogon IP detection for DNS anti-spoofing
//!
//! Bogon IPs are IP addresses that should not appear on the public internet.
//! This includes private IP ranges, loopback addresses, and reserved ranges.
//! DNS responses containing bogon IPs may indicate DNS spoofing/pollution.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Check if an IPv4 address is a bogon (should not appear on public internet)
///
/// Bogon IPv4 ranges include:
/// - 0.0.0.0/8 - "This" network
/// - 10.0.0.0/8 - Private (RFC 1918)
/// - 100.64.0.0/10 - Carrier-grade NAT (RFC 6598)
/// - 127.0.0.0/8 - Loopback
/// - 169.254.0.0/16 - Link-local
/// - 172.16.0.0/12 - Private (RFC 1918)
/// - 192.0.0.0/24 - IETF Protocol Assignments
/// - 192.0.2.0/24 - TEST-NET-1
/// - 192.168.0.0/16 - Private (RFC 1918)
/// - 198.18.0.0/15 - Benchmarking (RFC 2544)
/// - 198.51.100.0/24 - TEST-NET-2
/// - 203.0.113.0/24 - TEST-NET-3
/// - 224.0.0.0/4 - Multicast
/// - 240.0.0.0/4 - Reserved for future use
/// - 255.255.255.255/32 - Broadcast
pub fn is_bogon_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 0.0.0.0/8 - "This" network
    if octets[0] == 0 {
        return true;
    }

    // 10.0.0.0/8 - Private
    if octets[0] == 10 {
        return true;
    }

    // 100.64.0.0/10 - Carrier-grade NAT
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }

    // 127.0.0.0/8 - Loopback
    if octets[0] == 127 {
        return true;
    }

    // 169.254.0.0/16 - Link-local
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }

    // 172.16.0.0/12 - Private
    if octets[0] == 172 && (octets[1] & 0xF0) == 16 {
        return true;
    }

    // 192.0.0.0/24 - IETF Protocol Assignments
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }

    // 192.0.2.0/24 - TEST-NET-1
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }

    // 192.168.0.0/16 - Private
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // 198.18.0.0/15 - Benchmarking
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return true;
    }

    // 198.51.100.0/24 - TEST-NET-2
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }

    // 203.0.113.0/24 - TEST-NET-3
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }

    // 224.0.0.0/4 - Multicast
    if (octets[0] & 0xF0) == 224 {
        return true;
    }

    // 240.0.0.0/4 - Reserved for future use (includes 255.255.255.255)
    if (octets[0] & 0xF0) == 240 {
        return true;
    }

    false
}

/// Check if an IPv6 address is a bogon (should not appear on public internet)
///
/// Bogon IPv6 ranges include:
/// - ::/128 - Unspecified
/// - ::1/128 - Loopback
/// - ::ffff:0:0/96 - IPv4-mapped
/// - 64:ff9b::/96 - IPv4/IPv6 translation
/// - 100::/64 - Discard prefix
/// - 2001::/32 - Teredo
/// - 2001:2::/48 - Benchmarking
/// - 2001:db8::/32 - Documentation
/// - 2001:10::/28 - ORCHID
/// - 2002::/16 - 6to4
/// - fc00::/7 - Unique local
/// - fe80::/10 - Link-local
/// - ff00::/8 - Multicast
pub fn is_bogon_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();

    // ::/128 - Unspecified
    if ip.is_unspecified() {
        return true;
    }

    // ::1/128 - Loopback
    if ip.is_loopback() {
        return true;
    }

    // ::ffff:0:0/96 - IPv4-mapped
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        return true;
    }

    // 64:ff9b::/96 - IPv4/IPv6 translation (NAT64)
    if segments[0] == 0x64 && segments[1] == 0xff9b {
        return true;
    }

    // 100::/64 - Discard prefix
    if segments[0] == 0x100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return true;
    }

    // 2001::/32 - Teredo
    if segments[0] == 0x2001 && segments[1] == 0 {
        return true;
    }

    // 2001:2::/48 - Benchmarking
    if segments[0] == 0x2001 && segments[1] == 0x2 && segments[2] == 0 {
        return true;
    }

    // 2001:db8::/32 - Documentation
    if segments[0] == 0x2001 && segments[1] == 0xdb8 {
        return true;
    }

    // 2001:10::/28 - ORCHID
    if segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x10 {
        return true;
    }

    // 2002::/16 - 6to4
    if segments[0] == 0x2002 {
        return true;
    }

    // fc00::/7 - Unique local (fc00::/8 and fd00::/8)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // fe80::/10 - Link-local
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // ff00::/8 - Multicast
    if (segments[0] & 0xff00) == 0xff00 {
        return true;
    }

    false
}

/// Check if an IP address is a bogon
pub fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_bogon_ipv4(v4),
        IpAddr::V6(v6) => is_bogon_ipv6(v6),
    }
}

/// Check if any IP in a list is a bogon
pub fn contains_bogon(ips: &[IpAddr]) -> bool {
    ips.iter().any(|ip| is_bogon(*ip))
}

/// Filter out bogon IPs from a list
pub fn filter_bogons(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.into_iter().filter(|ip| !is_bogon(*ip)).collect()
}

/// Check if an IP is a private address (subset of bogon)
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

/// Check if an IPv4 address is private (RFC 1918)
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] & 0xF0) == 16 {
        return true;
    }

    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    false
}

/// Check if an IPv6 address is private (Unique Local Address)
pub fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // fc00::/7 - Unique local (fc00::/8 and fd00::/8)
    (segments[0] & 0xfe00) == 0xfc00
}

/// Check if an IP is a loopback address
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 127,
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Check if an IP is a reserved address (not routable)
pub fn is_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 240.0.0.0/4 - Reserved for future use
            (octets[0] & 0xF0) == 240
        }
        IpAddr::V6(_) => false, // IPv6 doesn't have a general "reserved" range like IPv4
    }
}

/// Bogon detection result with details
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BogonType {
    /// Not a bogon - valid public IP
    NotBogon,
    /// Private IP (RFC 1918 for IPv4, ULA for IPv6)
    Private,
    /// Loopback address
    Loopback,
    /// Link-local address
    LinkLocal,
    /// Multicast address
    Multicast,
    /// Reserved/unspecified address
    Reserved,
    /// Documentation/test address
    Documentation,
    /// Other bogon type
    Other,
}

/// Classify an IP address
pub fn classify_bogon(ip: IpAddr) -> BogonType {
    match ip {
        IpAddr::V4(v4) => classify_bogon_ipv4(v4),
        IpAddr::V6(v6) => classify_bogon_ipv6(v6),
    }
}

fn classify_bogon_ipv4(ip: Ipv4Addr) -> BogonType {
    let octets = ip.octets();

    // Loopback
    if octets[0] == 127 {
        return BogonType::Loopback;
    }

    // Private
    if octets[0] == 10
        || (octets[0] == 172 && (octets[1] & 0xF0) == 16)
        || (octets[0] == 192 && octets[1] == 168)
    {
        return BogonType::Private;
    }

    // Link-local
    if octets[0] == 169 && octets[1] == 254 {
        return BogonType::LinkLocal;
    }

    // Multicast
    if (octets[0] & 0xF0) == 224 {
        return BogonType::Multicast;
    }

    // Reserved
    if octets[0] == 0 || (octets[0] & 0xF0) == 240 {
        return BogonType::Reserved;
    }

    // Documentation/Test
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return BogonType::Documentation;
    }

    // Other bogon types
    if is_bogon_ipv4(ip) {
        return BogonType::Other;
    }

    BogonType::NotBogon
}

fn classify_bogon_ipv6(ip: Ipv6Addr) -> BogonType {
    let segments = ip.segments();

    // Loopback
    if ip.is_loopback() {
        return BogonType::Loopback;
    }

    // Unspecified
    if ip.is_unspecified() {
        return BogonType::Reserved;
    }

    // Private (ULA)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return BogonType::Private;
    }

    // Link-local
    if (segments[0] & 0xffc0) == 0xfe80 {
        return BogonType::LinkLocal;
    }

    // Multicast
    if (segments[0] & 0xff00) == 0xff00 {
        return BogonType::Multicast;
    }

    // Documentation
    if segments[0] == 0x2001 && segments[1] == 0xdb8 {
        return BogonType::Documentation;
    }

    // Other bogon types
    if is_bogon_ipv6(ip) {
        return BogonType::Other;
    }

    BogonType::NotBogon
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bogon_ipv4_private() {
        assert!(is_bogon_ipv4("10.0.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("10.255.255.255".parse().unwrap()));
        assert!(is_bogon_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("172.31.255.255".parse().unwrap()));
        assert!(is_bogon_ipv4("192.168.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv4_loopback() {
        assert!(is_bogon_ipv4("127.0.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv4_link_local() {
        assert!(is_bogon_ipv4("169.254.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("169.254.255.255".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv4_multicast() {
        assert!(is_bogon_ipv4("224.0.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv4_reserved() {
        assert!(is_bogon_ipv4("0.0.0.0".parse().unwrap()));
        assert!(is_bogon_ipv4("240.0.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv4_documentation() {
        assert!(is_bogon_ipv4("192.0.2.1".parse().unwrap()));
        assert!(is_bogon_ipv4("198.51.100.1".parse().unwrap()));
        assert!(is_bogon_ipv4("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn test_not_bogon_ipv4() {
        assert!(!is_bogon_ipv4("8.8.8.8".parse().unwrap()));
        assert!(!is_bogon_ipv4("1.1.1.1".parse().unwrap()));
        assert!(!is_bogon_ipv4("142.250.185.78".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv6_loopback() {
        assert!(is_bogon_ipv6("::1".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv6_unspecified() {
        assert!(is_bogon_ipv6("::".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv6_private() {
        assert!(is_bogon_ipv6("fc00::1".parse().unwrap()));
        assert!(is_bogon_ipv6("fd00::1".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv6_link_local() {
        assert!(is_bogon_ipv6("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv6_multicast() {
        assert!(is_bogon_ipv6("ff00::1".parse().unwrap()));
        assert!(is_bogon_ipv6("ff02::1".parse().unwrap()));
    }

    #[test]
    fn test_bogon_ipv6_documentation() {
        assert!(is_bogon_ipv6("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_not_bogon_ipv6() {
        assert!(!is_bogon_ipv6("2607:f8b0:4004:800::200e".parse().unwrap())); // Google
        assert!(!is_bogon_ipv6("2606:4700:4700::1111".parse().unwrap())); // Cloudflare
    }

    #[test]
    fn test_contains_bogon() {
        let ips_with_bogon: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ];
        assert!(contains_bogon(&ips_with_bogon));

        let ips_without_bogon: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        assert!(!contains_bogon(&ips_without_bogon));
    }

    #[test]
    fn test_filter_bogons() {
        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ];
        let filtered = filter_bogons(ips);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"8.8.8.8".parse().unwrap()));
        assert!(filtered.contains(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_classify_bogon() {
        assert_eq!(
            classify_bogon("127.0.0.1".parse().unwrap()),
            BogonType::Loopback
        );
        assert_eq!(
            classify_bogon("10.0.0.1".parse().unwrap()),
            BogonType::Private
        );
        assert_eq!(
            classify_bogon("169.254.1.1".parse().unwrap()),
            BogonType::LinkLocal
        );
        assert_eq!(
            classify_bogon("224.0.0.1".parse().unwrap()),
            BogonType::Multicast
        );
        assert_eq!(
            classify_bogon("8.8.8.8".parse().unwrap()),
            BogonType::NotBogon
        );
    }
}
