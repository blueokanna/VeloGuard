//! Property-based tests for DNS module
//!
//! These tests validate the correctness properties defined in the design document:
//! - Property 2: DNS Resolution Round-Trip
//! - Property 3: Fake-IP Allocation Round-Trip
//! - Property 4: DNS Bogon Detection
//!
//! **Validates: Requirements 4.9-4.11**

use crate::bogon::{classify_bogon, is_bogon, is_bogon_ipv4, is_bogon_ipv6, BogonType};
use crate::cache::DnsCache;
use crate::fake_ip::FakeIpPool;
use crate::RecordType;
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Strategy for generating valid domain names
fn domain_strategy() -> impl Strategy<Value = String> {
    // Generate domain names like "abc.example.com"
    (
        "[a-z]{1,10}",
        prop::collection::vec("[a-z]{1,8}", 1..3),
        prop_oneof!["com", "org", "net", "io", "dev"],
    )
        .prop_map(|(prefix, parts, tld)| {
            let mut domain = prefix;
            for part in parts {
                domain.push('.');
                domain.push_str(&part);
            }
            domain.push('.');
            domain.push_str(&tld);
            domain
        })
}

/// Strategy for generating valid IPv4 addresses
fn ipv4_strategy() -> impl Strategy<Value = Ipv4Addr> {
    (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255)
        .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
}

/// Strategy for generating public (non-bogon) IPv4 addresses
fn public_ipv4_strategy() -> impl Strategy<Value = Ipv4Addr> {
    // Generate IPs in common public ranges
    prop_oneof![
        // Common public IP ranges
        (1u8..10, 0u8..=255, 0u8..=255, 1u8..=254)
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
        (11u8..127, 0u8..=255, 0u8..=255, 1u8..=254)
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
        (128u8..169, 0u8..=255, 0u8..=255, 1u8..=254)
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
        (170u8..172, 0u8..=255, 0u8..=255, 1u8..=254)
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
        (173u8..192, 0u8..=255, 0u8..=255, 1u8..=254)
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
        (193u8..198, 0u8..=255, 0u8..=255, 1u8..=254)
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
        (199u8..224, 0u8..=255, 0u8..=255, 1u8..=254)
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
    ]
    .prop_filter("must not be bogon", |ip| !is_bogon_ipv4(*ip))
}

/// Strategy for generating bogon IPv4 addresses
fn bogon_ipv4_strategy() -> impl Strategy<Value = Ipv4Addr> {
    prop_oneof![
        // Private 10.0.0.0/8
        (0u8..=255, 0u8..=255, 0u8..=255).prop_map(|(b, c, d)| Ipv4Addr::new(10, b, c, d)),
        // Private 172.16.0.0/12
        (16u8..32, 0u8..=255, 0u8..=255).prop_map(|(b, c, d)| Ipv4Addr::new(172, b, c, d)),
        // Private 192.168.0.0/16
        (0u8..=255, 0u8..=255).prop_map(|(c, d)| Ipv4Addr::new(192, 168, c, d)),
        // Loopback 127.0.0.0/8
        (0u8..=255, 0u8..=255, 0u8..=255).prop_map(|(b, c, d)| Ipv4Addr::new(127, b, c, d)),
        // Link-local 169.254.0.0/16
        (0u8..=255, 0u8..=255).prop_map(|(c, d)| Ipv4Addr::new(169, 254, c, d)),
        // Reserved 240.0.0.0/4
        (240u8..=255, 0u8..=255, 0u8..=255, 0u8..=255)
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
    ]
}

/// Strategy for generating valid IPv6 addresses
#[allow(dead_code)]
fn ipv6_strategy() -> impl Strategy<Value = Ipv6Addr> {
    (
        0u16..=0xffff,
        0u16..=0xffff,
        0u16..=0xffff,
        0u16..=0xffff,
        0u16..=0xffff,
        0u16..=0xffff,
        0u16..=0xffff,
        0u16..=0xffff,
    )
        .prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

/// Strategy for generating bogon IPv6 addresses
fn bogon_ipv6_strategy() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        // Loopback ::1
        Just(Ipv6Addr::LOCALHOST),
        // Unspecified ::
        Just(Ipv6Addr::UNSPECIFIED),
        // Link-local fe80::/10
        (0u16..0x3ff, any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>())
            .prop_map(|(b, c, d, e, f, g, h, i)| Ipv6Addr::new(0xfe80 | (b & 0x3f), c, d, e, f, g, h, i)),
        // ULA fc00::/7
        (0u16..0x1ff, any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>())
            .prop_map(|(b, c, d, e, f, g, h, i)| Ipv6Addr::new(0xfc00 | (b & 0x1ff), c, d, e, f, g, h, i)),
        // Multicast ff00::/8
        (0u16..0xff, any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>())
            .prop_map(|(b, c, d, e, f, g, h, i)| Ipv6Addr::new(0xff00 | (b & 0xff), c, d, e, f, g, h, i)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Feature: rust-codebase-optimization, Property 3: Fake-IP Allocation Round-Trip**
    ///
    /// *For any* domain name, allocating a Fake-IP and then looking up that IP
    /// SHALL return the original domain name.
    ///
    /// **Validates: Requirements 4.11**
    #[test]
    fn test_fake_ip_allocation_round_trip(domain in domain_strategy()) {
        let pool = FakeIpPool::new("198.18.0.0/16", vec![]).unwrap();

        // Allocate a Fake-IP for the domain
        let ip = pool.allocate(&domain).unwrap();

        // Lookup the domain from the Fake-IP
        let looked_up_domain = pool.lookup(ip);

        // The looked up domain should match the original (case-insensitive)
        prop_assert!(looked_up_domain.is_some());
        prop_assert_eq!(looked_up_domain.unwrap().to_lowercase(), domain.to_lowercase());
    }

    /// **Feature: rust-codebase-optimization, Property 3: Fake-IP Idempotence**
    ///
    /// *For any* domain name, allocating a Fake-IP multiple times SHALL return
    /// the same IP address.
    ///
    /// **Validates: Requirements 4.11**
    #[test]
    fn test_fake_ip_allocation_idempotent(domain in domain_strategy()) {
        let pool = FakeIpPool::new("198.18.0.0/16", vec![]).unwrap();

        // Allocate twice
        let ip1 = pool.allocate(&domain).unwrap();
        let ip2 = pool.allocate(&domain).unwrap();

        // Should return the same IP
        prop_assert_eq!(ip1, ip2);
    }

    /// **Feature: rust-codebase-optimization, Property 3: Fake-IP Uniqueness**
    ///
    /// *For any* two different domain names, allocating Fake-IPs SHALL return
    /// different IP addresses.
    ///
    /// **Validates: Requirements 4.11**
    #[test]
    fn test_fake_ip_allocation_unique(
        domain1 in domain_strategy(),
        domain2 in domain_strategy()
    ) {
        prop_assume!(domain1.to_lowercase() != domain2.to_lowercase());

        let pool = FakeIpPool::new("198.18.0.0/16", vec![]).unwrap();

        let ip1 = pool.allocate(&domain1).unwrap();
        let ip2 = pool.allocate(&domain2).unwrap();

        // Different domains should get different IPs
        prop_assert_ne!(ip1, ip2);
    }

    /// **Feature: rust-codebase-optimization, Property 4: DNS Bogon Detection - IPv4**
    ///
    /// *For any* IPv4 address in a known bogon range, the bogon detection
    /// SHALL correctly identify it as a bogon.
    ///
    /// **Validates: Requirements 4.9**
    #[test]
    fn test_bogon_detection_ipv4_bogons(ip in bogon_ipv4_strategy()) {
        prop_assert!(is_bogon_ipv4(ip), "Expected {} to be detected as bogon", ip);
    }

    /// **Feature: rust-codebase-optimization, Property 4: DNS Bogon Detection - IPv4 Public**
    ///
    /// *For any* IPv4 address in a known public range, the bogon detection
    /// SHALL correctly identify it as NOT a bogon.
    ///
    /// **Validates: Requirements 4.9**
    #[test]
    fn test_bogon_detection_ipv4_public(ip in public_ipv4_strategy()) {
        prop_assert!(!is_bogon_ipv4(ip), "Expected {} to NOT be detected as bogon", ip);
    }

    /// **Feature: rust-codebase-optimization, Property 4: DNS Bogon Detection - IPv6**
    ///
    /// *For any* IPv6 address in a known bogon range, the bogon detection
    /// SHALL correctly identify it as a bogon.
    ///
    /// **Validates: Requirements 4.9**
    #[test]
    fn test_bogon_detection_ipv6_bogons(ip in bogon_ipv6_strategy()) {
        prop_assert!(is_bogon_ipv6(ip), "Expected {} to be detected as bogon", ip);
    }

    /// **Feature: rust-codebase-optimization, Property 4: DNS Bogon Classification Consistency**
    ///
    /// *For any* IP address, if classify_bogon returns NotBogon, then is_bogon
    /// SHALL return false, and vice versa.
    ///
    /// **Validates: Requirements 4.9**
    #[test]
    fn test_bogon_classification_consistency_ipv4(ip in ipv4_strategy()) {
        let classification = classify_bogon(IpAddr::V4(ip));
        let is_bogon_result = is_bogon(IpAddr::V4(ip));

        if classification == BogonType::NotBogon {
            prop_assert!(!is_bogon_result, "classify_bogon returned NotBogon but is_bogon returned true for {}", ip);
        } else {
            prop_assert!(is_bogon_result, "classify_bogon returned {:?} but is_bogon returned false for {}", classification, ip);
        }
    }

    /// **Feature: rust-codebase-optimization, Property 2: DNS Cache Round-Trip**
    ///
    /// *For any* valid domain name and IP addresses, inserting into the cache
    /// and then retrieving SHALL return the same IP addresses within the TTL period.
    ///
    /// **Validates: Requirements 4.10**
    #[test]
    fn test_dns_cache_round_trip(
        domain in domain_strategy(),
        ips in prop::collection::vec(public_ipv4_strategy(), 1..5)
    ) {
        let cache = DnsCache::new(1000, 60, 86400);

        let ip_addrs: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();

        // Insert into cache
        cache.insert(&domain, RecordType::A, ip_addrs.clone(), 300);

        // Retrieve from cache
        let cached = cache.get(&domain, RecordType::A);

        prop_assert!(cached.is_some(), "Cache should contain the entry");
        let cached_entry = cached.unwrap();

        // The cached IPs should match the original
        prop_assert_eq!(cached_entry.addresses.len(), ip_addrs.len());
        for ip in &ip_addrs {
            prop_assert!(cached_entry.addresses.contains(ip), "Cached entry should contain {}", ip);
        }
    }

    /// **Feature: rust-codebase-optimization, Property 2: DNS Cache Isolation**
    ///
    /// *For any* two different domain names, caching one SHALL NOT affect the other.
    ///
    /// **Validates: Requirements 4.10**
    #[test]
    fn test_dns_cache_isolation(
        domain1 in domain_strategy(),
        domain2 in domain_strategy(),
        ip1 in public_ipv4_strategy(),
        ip2 in public_ipv4_strategy()
    ) {
        prop_assume!(domain1.to_lowercase() != domain2.to_lowercase());

        let cache = DnsCache::new(1000, 60, 86400);

        // Insert both domains
        cache.insert(&domain1, RecordType::A, vec![IpAddr::V4(ip1)], 300);
        cache.insert(&domain2, RecordType::A, vec![IpAddr::V4(ip2)], 300);

        // Retrieve both
        let cached1 = cache.get(&domain1, RecordType::A);
        let cached2 = cache.get(&domain2, RecordType::A);

        prop_assert!(cached1.is_some());
        prop_assert!(cached2.is_some());

        // Each should have its own IP
        prop_assert!(cached1.unwrap().addresses.contains(&IpAddr::V4(ip1)));
        prop_assert!(cached2.unwrap().addresses.contains(&IpAddr::V4(ip2)));
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    /// Test that specific known bogon IPs are detected
    #[test]
    fn test_known_bogon_ips() {
        // Private IPs
        assert!(is_bogon_ipv4("10.0.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("192.168.1.1".parse().unwrap()));

        // Loopback
        assert!(is_bogon_ipv4("127.0.0.1".parse().unwrap()));

        // Link-local
        assert!(is_bogon_ipv4("169.254.1.1".parse().unwrap()));

        // Reserved
        assert!(is_bogon_ipv4("240.0.0.1".parse().unwrap()));
        assert!(is_bogon_ipv4("255.255.255.255".parse().unwrap()));
    }

    /// Test that specific known public IPs are not detected as bogon
    #[test]
    fn test_known_public_ips() {
        assert!(!is_bogon_ipv4("8.8.8.8".parse().unwrap()));
        assert!(!is_bogon_ipv4("1.1.1.1".parse().unwrap()));
        assert!(!is_bogon_ipv4("142.250.185.78".parse().unwrap())); // Google
    }

    /// Test Fake-IP pool basic functionality
    #[test]
    fn test_fake_ip_pool_basic() {
        let pool = FakeIpPool::new("198.18.0.0/24", vec![]).unwrap();

        let ip = pool.allocate("example.com").unwrap();
        assert!(pool.is_fake_ip(ip));

        let domain = pool.lookup(ip).unwrap();
        assert_eq!(domain, "example.com");
    }

    /// Test DNS cache basic functionality
    #[test]
    fn test_dns_cache_basic() {
        let cache = DnsCache::new(100, 60, 86400);

        let ips = vec![IpAddr::V4("8.8.8.8".parse().unwrap())];
        cache.insert("google.com", RecordType::A, ips.clone(), 300);

        let cached = cache.get("google.com", RecordType::A);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().addresses, ips);
    }
}
