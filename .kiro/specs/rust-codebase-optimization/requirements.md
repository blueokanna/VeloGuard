# Requirements Document

## Introduction

本文档定义了VeloGuard Rust代码库优化重构的需求。目标是减少crate包使用、消除重复代码、完善未实现功能、使用Rust宏提高代码质量，并确保Flutter与Rust前后端一致性。参考clash-rs项目实现完整的代理功能。

## Glossary

- **VeloGuard**: 主代理系统名称
- **Crate**: Rust包/库
- **Outbound**: 出站代理连接
- **Inbound**: 入站代理监听器
- **Router**: 流量路由匹配器
- **DNS_Manager**: DNS解析和服务管理器
- **Traffic_Router**: 基于规则的流量路由系统
- **Proxy_Protocol**: 代理协议实现(Shadowsocks/Trojan/Vmess/Wireguard/Tor/Tuic/Socks5)
- **Transport**: 底层传输协议(gRPC/TLS/H2/WebSocket)
- **GeoIP**: 地理IP数据库
- **Fake_IP**: 虚拟IP分配池
- **DoH**: DNS over HTTPS
- **DoT**: DNS over TLS
- **Jaeger**: 分布式追踪系统

## Requirements

### Requirement 1: Crate依赖优化

**User Story:** As a developer, I want to minimize external crate dependencies, so that the codebase is more maintainable and has fewer potential security vulnerabilities.

#### Acceptance Criteria

1. THE VeloGuard SHALL remove all unused crate dependencies from Cargo.toml files
2. THE VeloGuard SHALL consolidate duplicate functionality into single implementations
3. WHEN multiple crates provide similar functionality, THE VeloGuard SHALL prefer standard library or well-maintained crates
4. THE VeloGuard SHALL update all remaining dependencies to their latest stable versions
5. THE VeloGuard SHALL remove the following redundant internal crates: console-subscriber, tokio-veloguard-tls (merge into veloguard-rustls), unix-udp-sock (use tokio directly)

### Requirement 2: Workspace结构优化

**User Story:** As a developer, I want a cleaner workspace structure, so that the codebase is easier to navigate and maintain.

#### Acceptance Criteria

1. THE VeloGuard SHALL consolidate workspace members to: veloguard-core, veloguard-lib, veloguard-dns, veloguard-netstack, veloguard-protocol
2. THE VeloGuard SHALL merge veloguard-quic, veloguard-rustls, veloguard-boringtun, tuic, tuic-quinn into veloguard-protocol
3. THE VeloGuard SHALL merge veloguard-solidtcp into veloguard-netstack
4. THE VeloGuard SHALL remove veloguard-sock2proc and use platform-specific code in veloguard-core
5. THE VeloGuard SHALL remove veloguard-bin as it's not used by Flutter integration

### Requirement 3: 流量路由规则系统

**User Story:** As a user, I want flexible traffic routing rules, so that I can control how my traffic is routed based on various criteria.

#### Acceptance Criteria

1. WHEN a request matches a Domain rule, THE Traffic_Router SHALL route to the specified outbound
2. WHEN a request matches a DomainSuffix rule, THE Traffic_Router SHALL route to the specified outbound
3. WHEN a request matches a DomainKeyword rule, THE Traffic_Router SHALL route to the specified outbound
4. WHEN a request matches a DomainRegex rule, THE Traffic_Router SHALL route to the specified outbound
5. WHEN a request matches an IP-CIDR rule, THE Traffic_Router SHALL route to the specified outbound
6. WHEN a request matches a GeoIP rule, THE Traffic_Router SHALL lookup the IP in the GeoIP database and route accordingly
7. WHEN a request matches a SrcPort or DstPort rule, THE Traffic_Router SHALL route based on port matching
8. WHEN a request matches a ProcessName rule, THE Traffic_Router SHALL route based on the originating process
9. WHEN a request matches a RuleSet rule, THE Traffic_Router SHALL load and evaluate the external rule set
10. WHEN no rules match, THE Traffic_Router SHALL use the MATCH rule or default outbound
11. THE Traffic_Router SHALL support rule priority ordering

### Requirement 4: DNS系统

**User Story:** As a user, I want a local anti-spoofing DNS server, so that my DNS queries are secure and can be routed through the proxy.

#### Acceptance Criteria

1. THE DNS_Manager SHALL support UDP DNS upstream servers
2. THE DNS_Manager SHALL support TCP DNS upstream servers
3. THE DNS_Manager SHALL support DoH (DNS over HTTPS) upstream servers
4. THE DNS_Manager SHALL support DoT (DNS over TLS) upstream servers
5. THE DNS_Manager SHALL expose a local UDP DNS server
6. THE DNS_Manager SHALL expose a local TCP DNS server
7. THE DNS_Manager SHALL expose a local DoH server
8. THE DNS_Manager SHALL expose a local DoT server
9. WHEN a DNS response contains bogon IPs, THE DNS_Manager SHALL fallback to alternative DNS servers
10. THE DNS_Manager SHALL cache DNS responses with TTL awareness
11. THE DNS_Manager SHALL support Fake-IP mode for transparent proxying
12. THE DNS_Manager SHALL support hosts file for local overrides

### Requirement 5: 代理协议支持

**User Story:** As a user, I want support for multiple proxy protocols, so that I can connect to various proxy servers.

#### Acceptance Criteria

1. THE Proxy_Protocol SHALL implement Shadowsocks outbound with AEAD ciphers (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) and 2022 ciphers
2. THE Proxy_Protocol SHALL implement Trojan outbound with TLS and SHA224 password hashing
3. THE Proxy_Protocol SHALL implement VMess outbound with AEAD encryption and proper header sealing
4. THE Proxy_Protocol SHALL implement VLess outbound with XTLS-Vision flow support
5. THE Proxy_Protocol SHALL implement WireGuard outbound (userspace) with Noise protocol handshake
6. THE Proxy_Protocol SHALL implement TUIC outbound with QUIC and authentication
7. THE Proxy_Protocol SHALL implement SOCKS5 outbound (TCP and UDP)
8. THE Proxy_Protocol SHALL implement HTTP/HTTPS outbound with CONNECT method
9. THE Proxy_Protocol SHALL implement Hysteria2 outbound with QUIC and bandwidth control
10. WHEN a protocol supports UDP, THE Proxy_Protocol SHALL implement UDP relay functionality

### Requirement 6: 传输层支持

**User Story:** As a user, I want support for various transport protocols, so that I can bypass network restrictions.

#### Acceptance Criteria

1. THE Transport SHALL support raw TCP connections
2. THE Transport SHALL support TLS connections with SNI customization
3. THE Transport SHALL support HTTP/2 (H2) connections
4. THE Transport SHALL support WebSocket connections
5. THE Transport SHALL support gRPC connections
6. THE Transport SHALL support QUIC connections with 0-RTT

### Requirement 7: 入站代理支持

**User Story:** As a user, I want to run VeloGuard as various proxy types, so that I can use it as a network gateway.

#### Acceptance Criteria

1. THE Inbound SHALL support HTTP proxy mode
2. THE Inbound SHALL support SOCKS5 proxy mode (TCP and UDP)
3. THE Inbound SHALL support Mixed proxy mode (HTTP + SOCKS5)
4. THE Inbound SHALL support TUN device mode for system-wide proxying
5. WHEN running as TUN device, THE Inbound SHALL handle TCP and UDP traffic transparently

### Requirement 8: 动态规则加载

**User Story:** As a user, I want to load rules and proxies dynamically, so that I can update my configuration without restarting.

#### Acceptance Criteria

1. THE VeloGuard SHALL support loading rule sets from remote URLs
2. THE VeloGuard SHALL support loading proxy providers from remote URLs
3. WHEN a remote resource is updated, THE VeloGuard SHALL reload it automatically based on interval
4. THE VeloGuard SHALL cache remote resources locally for offline use
5. THE VeloGuard SHALL support YAML and JSON format for remote resources

### Requirement 9: Jaeger追踪集成

**User Story:** As a developer, I want distributed tracing support, so that I can debug and monitor the proxy performance.

#### Acceptance Criteria

1. THE VeloGuard SHALL support OpenTelemetry tracing
2. THE VeloGuard SHALL export traces to Jaeger
3. THE VeloGuard SHALL trace DNS resolution operations
4. THE VeloGuard SHALL trace proxy connection establishment
5. THE VeloGuard SHALL trace traffic routing decisions
6. WHEN tracing is disabled, THE VeloGuard SHALL have minimal performance overhead

### Requirement 10: Rust宏优化

**User Story:** As a developer, I want to use Rust macros to reduce boilerplate, so that the code is more maintainable.

#### Acceptance Criteria

1. THE VeloGuard SHALL use declarative macros for error handling patterns
2. THE VeloGuard SHALL use declarative macros for configuration parsing
3. THE VeloGuard SHALL use derive macros for common trait implementations
4. THE VeloGuard SHALL use procedural macros for protocol message serialization
5. THE VeloGuard SHALL remove all code comments from the final implementation

### Requirement 11: Flutter-Rust一致性

**User Story:** As a developer, I want consistent API between Flutter and Rust, so that the frontend and backend work seamlessly together.

#### Acceptance Criteria

1. THE VeloGuard SHALL expose all proxy control functions through flutter_rust_bridge
2. THE VeloGuard SHALL expose traffic statistics through flutter_rust_bridge
3. THE VeloGuard SHALL expose connection tracking through flutter_rust_bridge
4. THE VeloGuard SHALL expose configuration management through flutter_rust_bridge
5. THE VeloGuard SHALL use consistent error types across the FFI boundary
6. THE VeloGuard SHALL serialize all data types correctly for FFI

### Requirement 12: 代码质量

**User Story:** As a developer, I want high-quality code, so that the project is maintainable and reliable.

#### Acceptance Criteria

1. THE VeloGuard SHALL achieve high cohesion within each module
2. THE VeloGuard SHALL achieve low coupling between modules
3. THE VeloGuard SHALL remove all unused methods and types
4. THE VeloGuard SHALL remove all duplicate implementations
5. THE VeloGuard SHALL implement all TODO items or remove them
6. THE VeloGuard SHALL have no code comments in the final implementation
