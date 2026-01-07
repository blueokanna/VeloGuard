# Design Document: VeloGuard Rust Codebase Optimization

## Overview

本设计文档描述了VeloGuard Rust代码库的全面优化重构方案。目标是将现有的15个crate合并为5个核心crate，移除未使用的依赖，完善所有代理协议实现，并使用Rust宏提高代码质量。

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Flutter UI                                │
└─────────────────────────────────────────────────────────────────┘
                              │ FFI (flutter_rust_bridge)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      veloguard-lib                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   API FFI   │  │   Types     │  │   Error     │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ veloguard-core│    │ veloguard-dns │    │veloguard-     │
│               │    │               │    │netstack       │
│ ┌───────────┐ │    │ ┌───────────┐ │    │ ┌───────────┐ │
│ │  Config   │ │    │ │  Resolver │ │    │ │    TUN    │ │
│ ├───────────┤ │    │ ├───────────┤ │    │ ├───────────┤ │
│ │  Router   │ │    │ │   Cache   │ │    │ │    TCP    │ │
│ ├───────────┤ │    │ ├───────────┤ │    │ ├───────────┤ │
│ │  Inbound  │ │    │ │  Fake-IP  │ │    │ │    UDP    │ │
│ ├───────────┤ │    │ ├───────────┤ │    │ ├───────────┤ │
│ │  Outbound │ │    │ │   Server  │ │    │ │    NAT    │ │
│ ├───────────┤ │    │ └───────────┘ │    │ └───────────┘ │
│ │  Tracing  │ │    └───────────────┘    └───────────────┘
│ └───────────┘ │              │
└───────────────┘              │
        │                      │
        └──────────┬───────────┘
                   ▼
        ┌───────────────────┐
        │ veloguard-protocol│
        │                   │
        │ ┌───────────────┐ │
        │ │  Shadowsocks  │ │
        │ ├───────────────┤ │
        │ │    Trojan     │ │
        │ ├───────────────┤ │
        │ │    VMess      │ │
        │ ├───────────────┤ │
        │ │   WireGuard   │ │
        │ ├───────────────┤ │
        │ │     TUIC      │ │
        │ ├───────────────┤ │
        │ │   Hysteria2   │ │
        │ ├───────────────┤ │
        │ │     QUIC      │ │
        │ ├───────────────┤ │
        │ │   Transport   │ │
        │ │ (TLS/WS/H2)   │ │
        │ └───────────────┘ │
        └───────────────────┘
```

## Components and Interfaces

### 1. veloguard-lib (FFI Layer)

负责Flutter与Rust之间的通信。所有API使用YAML格式配置，前后端保持一致。

```rust
#[flutter_rust_bridge::frb(sync)]
pub fn init_app();

pub async fn start_proxy_from_yaml(yaml_config: String) -> Result<(), String>;
pub async fn start_proxy_from_file(config_path: String) -> Result<(), String>;
pub async fn stop_proxy() -> Result<(), String>;
pub async fn is_proxy_running() -> Result<bool, String>;

pub async fn get_traffic_stats() -> Result<TrafficStatsDto, String>;
pub async fn get_connections() -> Result<Vec<ConnectionDto>, String>;
pub async fn close_connection(id: String) -> Result<(), String>;
pub async fn close_all_connections() -> Result<(), String>;

pub async fn test_proxy_latency(tag: String, test_url: String, timeout_ms: u64) -> Result<u64, String>;
pub async fn test_all_proxies_latency(test_url: String, timeout_ms: u64) -> Result<Vec<ProxyLatencyDto>, String>;

pub async fn reload_config_from_yaml(yaml_config: String) -> Result<(), String>;
pub async fn reload_config_from_file(config_path: String) -> Result<(), String>;

pub async fn set_proxy_mode(mode: i32) -> Result<(), String>;
pub async fn get_proxy_mode() -> Result<i32, String>;

pub async fn get_proxies() -> Result<Vec<ProxyInfoDto>, String>;
pub async fn get_proxy_groups() -> Result<Vec<ProxyGroupDto>, String>;
pub async fn select_proxy(group_tag: String, proxy_tag: String) -> Result<(), String>;

pub async fn get_rules() -> Result<Vec<RuleDto>, String>;
pub async fn get_dns_config() -> Result<DnsConfigDto, String>;

#[cfg(target_os = "android")]
pub fn set_vpn_fd(fd: i32);
#[cfg(target_os = "android")]
pub fn clear_vpn_fd();
#[cfg(target_os = "android")]
pub fn set_protect_socket_callback(callback: impl Fn(i32) -> bool + Send + Sync + 'static);

#[cfg(windows)]
pub async fn start_tun_mode(tun_name: String, tun_address: String, tun_netmask: String) -> Result<(), String>;
#[cfg(windows)]
pub async fn stop_tun_mode() -> Result<(), String>;
```

### Flutter-Rust DTO Types (前后端一致)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[flutter_rust_bridge::frb(dart_metadata=("freezed"))]
pub struct TrafficStatsDto {
    pub upload: u64,
    pub download: u64,
    pub total_upload: u64,
    pub total_download: u64,
    pub connection_count: u32,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[flutter_rust_bridge::frb(dart_metadata=("freezed"))]
pub struct ConnectionDto {
    pub id: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub dst_domain: Option<String>,
    pub protocol: String,
    pub outbound: String,
    pub upload: u64,
    pub download: u64,
    pub start_time: i64,
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[flutter_rust_bridge::frb(dart_metadata=("freezed"))]
pub struct ProxyInfoDto {
    pub tag: String,
    pub protocol_type: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub latency_ms: Option<u64>,
    pub alive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[flutter_rust_bridge::frb(dart_metadata=("freezed"))]
pub struct ProxyGroupDto {
    pub tag: String,
    pub group_type: String,
    pub proxies: Vec<String>,
    pub selected: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[flutter_rust_bridge::frb(dart_metadata=("freezed"))]
pub struct ProxyLatencyDto {
    pub tag: String,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[flutter_rust_bridge::frb(dart_metadata=("freezed"))]
pub struct RuleDto {
    pub rule_type: String,
    pub payload: String,
    pub outbound: String,
    pub matched_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[flutter_rust_bridge::frb(dart_metadata=("freezed"))]
pub struct DnsConfigDto {
    pub enable: bool,
    pub listen: String,
    pub enhanced_mode: String,
    pub nameservers: Vec<String>,
    pub fallback: Vec<String>,
}
```

### YAML Configuration Handling

```rust
pub fn parse_config_from_yaml(yaml_str: &str) -> Result<Config> {
    serde_yaml::from_str(yaml_str).map_err(|e| VeloGuardError::Config(e.to_string()))
}

pub fn parse_config_from_file(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(path)?;
    parse_config_from_yaml(&content)
}

pub fn serialize_config_to_yaml(config: &Config) -> Result<String> {
    serde_yaml::to_string(config).map_err(|e| VeloGuardError::Config(e.to_string()))
}
```

### 2. veloguard-core (Core Logic)

核心代理逻辑，包括配置、路由、入站和出站管理。

```rust
pub trait Router {
    async fn match_outbound(
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process: Option<&str>,
    ) -> String;
    
    async fn reload_rules(rules: Vec<Rule>) -> Result<()>;
}

pub trait InboundManager {
    async fn start() -> Result<()>;
    async fn stop() -> Result<()>;
    async fn reload() -> Result<()>;
}

pub trait OutboundManager {
    fn get_proxy(tag: &str) -> Option<Arc<dyn OutboundProxy>>;
    async fn test_latency(tag: &str, url: &str) -> Result<Duration>;
}
```

### 3. veloguard-dns (DNS System)

完整的DNS解析和服务系统。

```rust
pub trait DnsResolver {
    async fn resolve(domain: &str) -> Result<Vec<IpAddr>>;
    async fn resolve_with_type(domain: &str, rtype: RecordType) -> Result<DnsResponse>;
}

pub trait DnsServer {
    async fn start(listen: SocketAddr) -> Result<()>;
    async fn stop() -> Result<()>;
}

pub trait FakeIpPool {
    fn allocate(domain: &str) -> IpAddr;
    fn lookup(ip: IpAddr) -> Option<String>;
    fn release(ip: IpAddr);
}
```

### 4. veloguard-netstack (Network Stack)

用户空间TCP/IP栈，用于TUN模式。

```rust
pub trait NetStack {
    async fn create_tun(config: TunConfig) -> Result<()>;
    async fn start() -> Result<()>;
    async fn stop() -> Result<()>;
    fn tcp_listener() -> Option<TcpListener>;
    fn udp_listener() -> Option<UdpListener>;
}

pub trait TcpConnection {
    fn src_addr(&self) -> SocketAddr;
    fn dst_addr(&self) -> SocketAddr;
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    async fn write(&mut self, buf: &[u8]) -> Result<usize>;
}
```

### 5. veloguard-protocol (Protocol Implementations)

所有代理协议的实现。

```rust
pub trait ProxyProtocol: Send + Sync {
    fn name(&self) -> &str;
    async fn connect(&self, target: Address) -> Result<Box<dyn AsyncReadWrite>>;
    async fn relay(&self, inbound: Box<dyn AsyncReadWrite>, target: Address) -> Result<()>;
}

pub trait Transport: Send + Sync {
    async fn wrap(&self, stream: TcpStream) -> Result<Box<dyn AsyncReadWrite>>;
}
```

## Data Models

### Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub dns: DnsConfig,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub rules: Vec<RuleConfig>,
    pub proxy_providers: Vec<ProxyProviderConfig>,
    pub rule_providers: Vec<RuleProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    #[serde(rename = "type")]
    pub protocol: ProtocolType,
    pub tag: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub transport: Option<TransportConfig>,
    #[serde(flatten)]
    pub protocol_options: ProtocolOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(rename = "type")]
    pub transport_type: TransportType,
    pub host: Option<String>,
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub tls: Option<TlsConfig>,
}
```

### Protocol Types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolType {
    Direct,
    Reject,
    Shadowsocks,
    Trojan,
    Vmess,
    Vless,
    Wireguard,
    Tuic,
    Hysteria2,
    Socks5,
    Http,
    #[serde(alias = "select")]
    Selector,
    #[serde(alias = "url-test")]
    Urltest,
    Fallback,
    #[serde(alias = "load-balance")]
    Loadbalance,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Tcp,
    Tls,
    Websocket,
    Http2,
    Grpc,
    Quic,
}
```

### Traffic Statistics

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub upload: u64,
    pub download: u64,
    pub connections: u32,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub src: SocketAddr,
    pub dst: String,
    pub protocol: String,
    pub outbound: String,
    pub upload: u64,
    pub download: u64,
    pub start_time: DateTime<Utc>,
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Routing Rule Matching

*For any* request with domain, IP, port, and process information, the router SHALL match rules in priority order and return the correct outbound tag. If no rule matches, the router SHALL return the default outbound.

**Validates: Requirements 3.1-3.11**

### Property 2: DNS Resolution Round-Trip

*For any* valid domain name, resolving through the DNS resolver and then looking up the cached result SHALL return the same IP addresses within the TTL period.

**Validates: Requirements 4.10**

### Property 3: Fake-IP Allocation Round-Trip

*For any* domain name, allocating a Fake-IP and then looking up that IP SHALL return the original domain name.

**Validates: Requirements 4.11**

### Property 4: DNS Bogon Detection

*For any* DNS response containing bogon IP addresses (private, loopback, or reserved ranges), the DNS resolver SHALL detect and fallback to alternative DNS servers.

**Validates: Requirements 4.9**

### Property 5: DNS Protocol Consistency

*For any* valid DNS query, resolving through UDP, TCP, DoH, and DoT upstreams SHALL return equivalent results (same IP addresses).

**Validates: Requirements 4.1-4.4**

### Property 6: Remote Resource Loading

*For any* valid remote rule or proxy provider URL, loading and parsing SHALL succeed and produce valid configuration objects. Reloading after the update interval SHALL fetch fresh data.

**Validates: Requirements 8.1-8.5**

### Property 7: FFI Serialization Round-Trip

*For any* data type exposed through FFI, serializing to Flutter and deserializing back SHALL produce an equivalent value.

**Validates: Requirements 11.1-11.6**

### Property 8: Hosts File Override

*For any* domain configured in the hosts file, DNS resolution SHALL return the configured IP address, bypassing upstream DNS servers.

**Validates: Requirements 4.12**

## Error Handling

### Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum VeloGuardError {
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("DNS error: {0}")]
    Dns(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Timeout")]
    Timeout,
    
    #[error("Connection refused")]
    ConnectionRefused,
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}
```

### Error Handling Strategy

1. 使用`thiserror`定义错误类型
2. 使用`anyhow`在应用层处理错误
3. FFI边界使用`Result<T, String>`简化错误传递
4. 所有网络操作使用超时保护
5. 使用宏简化错误处理模式

```rust
macro_rules! try_network {
    ($expr:expr, $msg:expr) => {
        $expr.map_err(|e| VeloGuardError::Network(format!("{}: {}", $msg, e)))?
    };
}
```

## Testing Strategy

### Unit Tests

- 配置解析和验证
- 路由规则匹配
- DNS缓存逻辑
- Fake-IP分配
- 协议消息编解码

### Property-Based Tests

使用`proptest`或`quickcheck`进行属性测试：

1. **路由匹配属性测试**: 生成随机请求，验证路由匹配正确性
2. **DNS缓存属性测试**: 生成随机DNS响应，验证缓存行为
3. **Fake-IP属性测试**: 生成随机域名，验证分配和查找一致性
4. **FFI序列化属性测试**: 生成随机数据类型，验证序列化往返

### Integration Tests

- 代理协议端到端测试（需要测试服务器）
- TUN模式网络栈测试
- DNS服务器测试

### Test Configuration

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn test_routing_property(
            domain in "[a-z]{1,10}\\.[a-z]{2,3}",
            port in 1u16..65535u16,
        ) {
            // Property test implementation
        }
    }
}
```

## Dependency Optimization

### Removed Dependencies

以下依赖将被移除或合并：

- `console-subscriber` - 合并到tracing配置
- `tokio-veloguard-tls` - 合并到veloguard-protocol
- `unix-udp-sock` - 使用tokio原生UDP
- `veloguard-sock2proc` - 合并到veloguard-core
- `md5` - 使用`md-5` crate统一
- `webpki` - 使用`rustls`内置

### Updated Dependencies

所有依赖更新到最新稳定版本，主要更新：

- `tokio` 1.x (最新)
- `rustls` 0.23.x
- `quinn` 0.11.x
- `hickory-dns` 0.25.x
- `smoltcp` 0.12.x

### Workspace Dependencies

```toml
[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
anyhow = "1"
thiserror = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
bytes = "1"
futures = "0.3"
async-trait = "0.1"
dashmap = "6"
parking_lot = "0.12"
rustls = { version = "0.23", default-features = false, features = ["std", "ring"] }
quinn = { version = "0.11", default-features = false, features = ["runtime-tokio", "rustls"] }
hickory-resolver = { version = "0.25", default-features = false, features = ["tokio"] }
smoltcp = { version = "0.12", default-features = false, features = ["std", "medium-ip", "proto-ipv4", "proto-ipv6", "socket-tcp", "socket-udp"] }
```

## Macro Definitions

### Error Handling Macros

```rust
#[macro_export]
macro_rules! bail_config {
    ($($arg:tt)*) => {
        return Err($crate::error::VeloGuardError::Config(format!($($arg)*)))
    };
}

#[macro_export]
macro_rules! bail_network {
    ($($arg:tt)*) => {
        return Err($crate::error::VeloGuardError::Network(format!($($arg)*)))
    };
}

#[macro_export]
macro_rules! bail_protocol {
    ($($arg:tt)*) => {
        return Err($crate::error::VeloGuardError::Protocol(format!($($arg)*)))
    };
}
```

### Protocol Implementation Macros

```rust
#[macro_export]
macro_rules! impl_outbound_proxy {
    ($name:ident, $tag_field:ident) => {
        #[async_trait::async_trait]
        impl OutboundProxy for $name {
            fn tag(&self) -> &str {
                &self.$tag_field
            }
            
            async fn disconnect(&self) -> Result<()> {
                Ok(())
            }
        }
    };
}
```

### Configuration Parsing Macros

```rust
#[macro_export]
macro_rules! get_option {
    ($options:expr, $key:expr, String) => {
        $options.get($key).and_then(|v| match v {
            serde_yaml::Value::String(s) => Some(s.clone()),
            serde_yaml::Value::Number(n) => Some(n.to_string()),
            serde_yaml::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        })
    };
    ($options:expr, $key:expr, u16) => {
        $options.get($key).and_then(|v| v.as_i64()).map(|n| n as u16)
    };
    ($options:expr, $key:expr, bool) => {
        $options.get($key).and_then(|v| v.as_bool())
    };
}

#[macro_export]
macro_rules! require_option {
    ($options:expr, $key:expr, $type:ident, $error_msg:expr) => {
        get_option!($options, $key, $type).ok_or_else(|| VeloGuardError::Config($error_msg.to_string()))?
    };
}
```

## Protocol Implementation Details

### Shadowsocks Protocol (完善现有实现)

现有实现已支持AEAD加密，需要补充：

```rust
pub struct ShadowsocksConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: ShadowsocksCipher,
    pub udp: bool,
    pub plugin: Option<PluginConfig>,
}

#[derive(Debug, Clone, Copy)]
pub enum ShadowsocksCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
    Aes128Gcm2022,
    Aes256Gcm2022,
    Chacha20Poly13052022,
}

impl ShadowsocksOutbound {
    pub async fn relay_udp(&self, packet: UdpPacket, target: Address) -> Result<()>;
}
```

### Trojan Protocol (需要完整实现)

```rust
pub struct TrojanConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub udp: bool,
    pub transport: Option<TransportConfig>,
}

impl TrojanOutbound {
    fn password_hash(&self) -> [u8; 56] {
        use sha2::{Sha224, Digest};
        let mut hasher = Sha224::new();
        hasher.update(self.password.as_bytes());
        let result = hasher.finalize();
        let hex = hex::encode(result);
        let mut hash = [0u8; 56];
        hash.copy_from_slice(hex.as_bytes());
        hash
    }
    
    async fn handshake(&self, stream: &mut TlsStream, target: &Address, cmd: TrojanCommand) -> Result<()> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.password_hash());
        buf.extend_from_slice(b"\r\n");
        buf.push(cmd as u8);
        target.write_to(&mut buf)?;
        buf.extend_from_slice(b"\r\n");
        stream.write_all(&buf).await?;
        Ok(())
    }
    
    pub async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: Address) -> Result<()>;
    pub async fn relay_udp(&self, packet: UdpPacket, target: Address) -> Result<()>;
}

#[repr(u8)]
pub enum TrojanCommand {
    Connect = 0x01,
    UdpAssociate = 0x03,
}
```

### VMess Protocol (需要完整实现)

```rust
pub struct VmessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub alter_id: u16,
    pub cipher: VmessCipher,
    pub udp: bool,
    pub transport: Option<TransportConfig>,
}

#[derive(Debug, Clone, Copy)]
pub enum VmessCipher {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

pub struct VmessHeader {
    pub version: u8,
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_header: u8,
    pub option: VmessOption,
    pub padding_length: u8,
    pub security: VmessCipher,
    pub reserved: u8,
    pub command: VmessCommand,
    pub port: u16,
    pub address_type: AddressType,
    pub address: Address,
}

impl VmessOutbound {
    fn generate_auth_id(&self, timestamp: i64) -> [u8; 16];
    fn generate_request_key(&self) -> [u8; 16];
    fn generate_request_iv(&self) -> [u8; 16];
    fn seal_header(&self, header: &VmessHeader) -> Result<Vec<u8>>;
    fn open_response_header(&self, data: &[u8]) -> Result<VmessResponseHeader>;
    
    pub async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: Address) -> Result<()>;
    pub async fn relay_udp(&self, packet: UdpPacket, target: Address) -> Result<()>;
}
```

### VLess Protocol (新增实现)

```rust
pub struct VlessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub flow: Option<VlessFlow>,
    pub udp: bool,
    pub transport: Option<TransportConfig>,
}

#[derive(Debug, Clone, Copy)]
pub enum VlessFlow {
    None,
    XtlsRprxVision,
    XtlsRprxVisionUdp443,
}

pub struct VlessRequest {
    pub version: u8,
    pub uuid: [u8; 16],
    pub addons_len: u8,
    pub addons: Vec<u8>,
    pub command: VlessCommand,
    pub port: u16,
    pub address_type: AddressType,
    pub address: Address,
}

pub struct VlessResponse {
    pub version: u8,
    pub addons_len: u8,
    pub addons: Vec<u8>,
}

impl VlessOutbound {
    pub fn new(config: VlessConfig) -> Result<Self>;
    
    async fn handshake(&self, stream: &mut impl AsyncReadWrite, target: &Address, cmd: VlessCommand) -> Result<()> {
        let mut buf = Vec::with_capacity(128);
        buf.push(0x00);
        buf.extend_from_slice(self.uuid.as_bytes());
        buf.push(0x00);
        buf.push(cmd as u8);
        buf.extend_from_slice(&target.port().to_be_bytes());
        target.write_address_to(&mut buf)?;
        stream.write_all(&buf).await?;
        
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != 0x00 {
            bail_protocol!("Invalid VLESS response version");
        }
        let addons_len = response[1] as usize;
        if addons_len > 0 {
            let mut addons = vec![0u8; addons_len];
            stream.read_exact(&mut addons).await?;
        }
        Ok(())
    }
    
    pub async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: Address) -> Result<()>;
    pub async fn relay_udp(&self, packet: UdpPacket, target: Address) -> Result<()>;
}

#[repr(u8)]
pub enum VlessCommand {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
}
```

### WireGuard Protocol (需要完整实现)

```rust
pub struct WireguardConfig {
    pub private_key: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub port: u16,
    pub local_address: Vec<IpNet>,
    pub mtu: u16,
    pub reserved: Option<[u8; 3]>,
    pub dns: Vec<IpAddr>,
}

pub struct WireguardTunnel {
    session: NoiseSession,
    local_index: u32,
    remote_index: u32,
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_nonce: u64,
    rx_nonce: u64,
}

impl WireguardOutbound {
    pub fn new(config: WireguardConfig) -> Result<Self>;
    
    async fn handshake(&self) -> Result<WireguardTunnel>;
    async fn keepalive(&self, tunnel: &mut WireguardTunnel) -> Result<()>;
    fn encrypt_packet(&self, tunnel: &mut WireguardTunnel, packet: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_packet(&self, tunnel: &mut WireguardTunnel, packet: &[u8]) -> Result<Vec<u8>>;
    
    pub async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: Address) -> Result<()>;
    pub async fn relay_udp(&self, packet: UdpPacket, target: Address) -> Result<()>;
}
```

### TUIC Protocol (需要完整实现)

```rust
pub struct TuicConfig {
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub congestion_control: CongestionControl,
    pub alpn: Vec<String>,
    pub disable_sni: bool,
    pub reduce_rtt: bool,
    pub udp_relay_mode: UdpRelayMode,
    pub heartbeat: Duration,
}

#[derive(Debug, Clone, Copy)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Debug, Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

pub struct TuicConnection {
    connection: quinn::Connection,
    uuid: Uuid,
    password: String,
    authenticated: bool,
}

impl TuicOutbound {
    pub fn new(config: TuicConfig) -> Result<Self>;
    
    async fn connect(&self) -> Result<TuicConnection>;
    async fn authenticate(&self, conn: &mut TuicConnection) -> Result<()>;
    async fn open_tcp_stream(&self, conn: &TuicConnection, target: &Address) -> Result<QuicStream>;
    async fn send_udp_packet(&self, conn: &TuicConnection, packet: &UdpPacket, target: &Address) -> Result<()>;
    
    pub async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: Address) -> Result<()>;
    pub async fn relay_udp(&self, packet: UdpPacket, target: Address) -> Result<()>;
}
```

### Hysteria2 Protocol (需要完整实现)

```rust
pub struct Hysteria2Config {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub obfs: Option<Hysteria2Obfs>,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub up_mbps: u32,
    pub down_mbps: u32,
}

#[derive(Debug, Clone)]
pub struct Hysteria2Obfs {
    pub obfs_type: String,
    pub password: String,
}

impl Hysteria2Outbound {
    pub fn new(config: Hysteria2Config) -> Result<Self>;
    
    async fn connect(&self) -> Result<quinn::Connection>;
    async fn authenticate(&self, conn: &quinn::Connection) -> Result<()>;
    
    pub async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: Address) -> Result<()>;
    pub async fn relay_udp(&self, packet: UdpPacket, target: Address) -> Result<()>;
}
```

## Transport Layer Implementation

### TLS Transport

```rust
pub struct TlsTransport {
    pub sni: String,
    pub alpn: Vec<String>,
    pub skip_cert_verify: bool,
    pub fingerprint: Option<TlsFingerprint>,
    pub client_config: Arc<rustls::ClientConfig>,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Random,
}

impl TlsTransport {
    pub fn new(config: TlsConfig) -> Result<Self>;
    pub async fn wrap(&self, stream: TcpStream) -> Result<TlsStream>;
}
```

### WebSocket Transport

```rust
pub struct WebSocketTransport {
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub max_early_data: usize,
    pub early_data_header: Option<String>,
}

impl WebSocketTransport {
    pub fn new(config: WebSocketConfig) -> Result<Self>;
    pub async fn wrap(&self, stream: impl AsyncReadWrite) -> Result<WebSocketStream>;
}
```

### HTTP/2 Transport

```rust
pub struct H2Transport {
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
}

impl H2Transport {
    pub fn new(config: H2Config) -> Result<Self>;
    pub async fn wrap(&self, stream: impl AsyncReadWrite) -> Result<H2Stream>;
}
```

### gRPC Transport

```rust
pub struct GrpcTransport {
    pub host: String,
    pub service_name: String,
    pub mode: GrpcMode,
}

#[derive(Debug, Clone, Copy)]
pub enum GrpcMode {
    Gun,
    Multi,
}

impl GrpcTransport {
    pub fn new(config: GrpcConfig) -> Result<Self>;
    pub async fn wrap(&self, stream: impl AsyncReadWrite) -> Result<GrpcStream>;
}
```

## Address Type

```rust
#[derive(Debug, Clone)]
pub enum Address {
    Domain(String, u16),
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
}

impl Address {
    pub fn port(&self) -> u16;
    pub fn host(&self) -> String;
    
    pub fn write_to(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Address::Ipv4(ip, port) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Domain(domain, port) => {
                buf.push(0x03);
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Ipv6(ip, port) => {
                buf.push(0x04);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(())
    }
    
    pub fn read_from(buf: &[u8]) -> Result<(Self, usize)>;
    pub async fn read_from_async(reader: &mut impl AsyncRead) -> Result<Self>;
}
```

## Dynamic Rule/Proxy Provider

### Rule Provider

```rust
pub struct RuleProvider {
    pub name: String,
    pub provider_type: RuleProviderType,
    pub behavior: RuleBehavior,
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Duration,
    pub rules: RwLock<Vec<Rule>>,
    pub last_update: RwLock<Option<Instant>>,
}

#[derive(Debug, Clone, Copy)]
pub enum RuleProviderType {
    Http,
    File,
}

#[derive(Debug, Clone, Copy)]
pub enum RuleBehavior {
    Domain,
    Ipcidr,
    Classical,
}

impl RuleProvider {
    pub async fn load(&self) -> Result<()>;
    pub async fn update(&self) -> Result<bool>;
    pub fn matches(&self, domain: Option<&str>, ip: Option<IpAddr>) -> bool;
}
```

### Proxy Provider

```rust
pub struct ProxyProvider {
    pub name: String,
    pub provider_type: ProxyProviderType,
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Duration,
    pub health_check: HealthCheckConfig,
    pub proxies: RwLock<Vec<Arc<dyn OutboundProxy>>>,
    pub last_update: RwLock<Option<Instant>>,
}

#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub enable: bool,
    pub url: String,
    pub interval: Duration,
    pub lazy: bool,
    pub expected_status: Option<u16>,
}

impl ProxyProvider {
    pub async fn load(&self) -> Result<()>;
    pub async fn update(&self) -> Result<bool>;
    pub async fn health_check(&self) -> Result<()>;
    pub fn get_proxies(&self) -> Vec<Arc<dyn OutboundProxy>>;
}
```

## Tracing Integration

### OpenTelemetry Configuration

```rust
pub fn init_tracing(config: &TracingConfig) -> Result<()> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;
    use tracing_subscriber::layer::SubscriberExt;
    
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(&config.jaeger_endpoint)
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;
    
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
    
    tracing_subscriber::registry()
        .with(telemetry)
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    Ok(())
}
```

### Span Instrumentation

```rust
#[tracing::instrument(skip(self, target), fields(outbound = %self.tag()))]
async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: TargetAddr) -> Result<()> {
    tracing::info!(target = %target, "Starting relay");
    // Implementation
}

#[tracing::instrument(skip(self), fields(domain = %domain))]
async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
    tracing::debug!("Resolving domain");
    // Implementation
}
```
