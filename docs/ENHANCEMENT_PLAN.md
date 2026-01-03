# VeloGuard 功能增强计划

## 当前已实现功�?

### �?出站协议 (Outbound)
- Direct / Reject
- SOCKS5 (TCP)
- HTTP Proxy
- Shadowsocks (AEAD-2022, Stream Cipher)
- VMess
- Trojan
- WireGuard (userspace via boringtun)
- TUIC
- Hysteria2

### �?入站协议 (Inbound)
- HTTP Proxy
- SOCKS5 Proxy
- Mixed (HTTP + SOCKS5)

### �?路由规则
- Domain / DomainSuffix / DomainKeyword / DomainRegex
- IP-CIDR / SRC-IP-CIDR
- GeoIP (需要数据库)
- SRC-PORT / DST-PORT
- Process Name
- MATCH (默认规则)

### �?代理�?
- Selector (手动选择)
- URLTest (自动测�?
- Fallback (故障转移)
- LoadBalance (负载均衡)
- Relay (链式代理)

### �?平台支持
- Windows (TUN via Wintun)
- macOS (TUN via tun-rs)
- Linux (TUN via tun-rs)
- Android (VPN Service + SolidTCP)
- OHOS (鸿蒙)

---

## 🚀 待增强功�?

### 1. DNS 增强 (高优先级)

#### 1.1 创建 `VeloGuard-dns` crate
```
rust/VeloGuard-dns/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── server.rs          # DNS 服务�?(UDP/TCP/DoH/DoT)
    ├── client.rs          # DNS 客户�?
    ├── resolver.rs        # DNS 解析�?
    ├── cache.rs           # DNS 缓存
    ├── fake_ip.rs         # Fake-IP �?
    ├── hosts.rs           # Hosts 文件支持
    └── anti_spoofing.rs   # �?DNS 污染
```

#### 1.2 DNS 功能清单
- [ ] UDP DNS 服务�?
- [ ] TCP DNS 服务�?
- [ ] DoH (DNS over HTTPS) 服务�?
- [ ] DoT (DNS over TLS) 服务�?
- [ ] 上游 DNS 支持: UDP/TCP/DoH/DoT
- [ ] DNS 缓存 (TTL 感知)
- [ ] Fake-IP 模式
- [ ] 域名分流 (国内/国外 DNS)
- [ ] �?DNS 污染/劫持
- [ ] EDNS Client Subnet 支持

### 2. 传输层增�?(高优先级)

#### 2.1 WebSocket 传输
```rust
// rust/VeloGuard-core/src/transport/websocket.rs
- [ ] WS 传输 (VMess/Trojan)
- [ ] WSS (WebSocket over TLS)
- [ ] 自定�?Path/Headers
- [ ] Early Data 支持
```

#### 2.2 gRPC 传输
```rust
// rust/VeloGuard-core/src/transport/grpc.rs
- [ ] gRPC 传输 (VMess/Trojan)
- [ ] gRPC over TLS
- [ ] 多路复用
```

#### 2.3 HTTP/2 传输
```rust
// rust/VeloGuard-core/src/transport/h2.rs
- [ ] H2 传输
- [ ] H2C (HTTP/2 Cleartext)
```

#### 2.4 QUIC 传输
```rust
// 已有 VeloGuard-quic crate
- [ ] QUIC 传输�?
- [ ] 0-RTT 支持
- [ ] 连接迁移
```

### 3. 协议增强 (中优先级)

#### 3.1 SOCKS5 UDP 支持
```rust
// rust/VeloGuard-core/src/outbound/socks5.rs
- [ ] UDP ASSOCIATE
- [ ] UDP 转发
```

#### 3.2 Tor 支持
```rust
// 已有 arti-client 依赖
// rust/VeloGuard-core/src/outbound/tor.rs
- [ ] Tor 出站代理
- [ ] 电路管理
- [ ] .onion 域名支持
```

#### 3.3 SSH 隧道
```rust
// 已有 russh 依赖
// rust/VeloGuard-core/src/outbound/ssh.rs
- [ ] SSH 动态端口转�?
- [ ] SSH 本地端口转发
- [ ] 密钥认证
```

### 4. 规则增强 (中优先级)

#### 4.1 Rule Provider (远程规则)
```rust
// rust/VeloGuard-core/src/rule_provider.rs
- [ ] HTTP 规则�?
- [ ] 自动更新
- [ ] 规则缓存
- [ ] 支持格式: YAML, Text, Domain List
```

#### 4.2 Proxy Provider (远程代理)
```rust
// rust/VeloGuard-core/src/proxy_provider.rs
- [ ] HTTP 代理�?
- [ ] 订阅解析 (Base64, YAML)
- [ ] 自动更新
- [ ] 健康检�?
```

#### 4.3 GeoIP/GeoSite 增强
```rust
// rust/VeloGuard-core/src/geo/
- [ ] MaxMind GeoIP2 数据�?
- [ ] GeoSite 数据�?(v2ray-rules-dat)
- [ ] 自动更新
- [ ] 内存映射加载
```

### 5. 可观测性增�?(低优先级)

#### 5.1 Jaeger 追踪
```rust
// 已有 opentelemetry 依赖
- [ ] 请求追踪
- [ ] Span 上下文传�?
- [ ] Jaeger 导出
```

#### 5.2 Prometheus 指标
```rust
// rust/VeloGuard-core/src/metrics.rs
- [ ] 连接数指�?
- [ ] 流量指标
- [ ] 延迟直方�?
- [ ] Prometheus 端点
```

### 6. 安全增强 (中优先级)

#### 6.1 TLS 指纹
```rust
// rust/VeloGuard-core/src/tls.rs
- [ ] uTLS 指纹模拟
- [ ] Chrome/Firefox/Safari 指纹
- [ ] 随机指纹
```

#### 6.2 流量混淆
```rust
// rust/VeloGuard-core/src/obfs/
- [ ] simple-obfs
- [ ] v2ray-plugin
- [ ] 自定义混�?
```

---

## 📋 实施优先�?

### Phase 1: DNS 系统 (2-3 �?
1. 创建 VeloGuard-dns crate
2. 实现基础 DNS 服务�?(UDP/TCP)
3. 实现 DoH/DoT 客户�?
4. 集成�?VeloGuard-core

### Phase 2: 传输�?(2-3 �?
1. WebSocket 传输
2. gRPC 传输
3. 完善 QUIC 传输

### Phase 3: 协议扩展 (2-3 �?
1. SOCKS5 UDP
2. Tor 出站
3. SSH 隧道

### Phase 4: 规则系统 (1-2 �?
1. Rule Provider
2. Proxy Provider
3. GeoIP/GeoSite 增强

### Phase 5: 可观测�?(1 �?
1. Jaeger 集成
2. Prometheus 指标

---

## 🔧 代码结构建议

```
rust/
├── VeloGuard-core/          # 核心代理逻辑
�?  ├── src/
�?  �?  ├── inbound/        # 入站处理
�?  �?  ├── outbound/       # 出站代理
�?  �?  ├── transport/      # 传输�?(新增)
�?  �?  �?  ├── mod.rs
�?  �?  �?  ├── tcp.rs
�?  �?  �?  ├── websocket.rs
�?  �?  �?  ├── grpc.rs
�?  �?  �?  └── h2.rs
�?  �?  ├── rule_provider/  # 规则提供�?(新增)
�?  �?  ├── proxy_provider/ # 代理提供�?(新增)
�?  �?  └── ...
├── VeloGuard-dns/           # DNS 系统 (新增)
├── VeloGuard-geo/           # GeoIP/GeoSite (新增)
├── VeloGuard-obfs/          # 流量混淆 (新增)
└── ...
```

---

## 📝 下一步行�?

请告诉我你想先实现哪个功能，我会为你�?
1. 创建详细的技术设�?
2. 编写生产级代�?
3. 添加测试用例
4. 集成到现有系�?

建议�?**DNS 系统** 开始，因为它是很多高级功能的基础�?
