# VeloGuard

<p align="center">
  <img src="assets/icon.png" width="128" height="128" alt="VeloGuard Logo">
</p>

<p align="center">
  <strong>🛡️ 现代化跨平台网络代理客户端</strong>
</p>

<p align="center">
  <em>基于 Flutter + Rust 构建的高性能、安全、易用的网络代理解决方案</em>
</p>

<p align="center">
  <a href="#-项目简介">项目简介</a> •
  <a href="#-核心特性">核心特性</a> •
  <a href="#-支持平台">支持平台</a> •
  <a href="#-系统架构">系统架构</a> •
  <a href="#-零基础使用指南">零基础使用指南</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#-开发指南">开发指南</a> •
  <a href="#-常见问题与排错">常见问题与排错</a>
</p>

---

## 📖 项目简介

**VeloGuard** 是一款采用 Flutter + Rust 混合架构开发的跨平台网络代理客户端。项目利用 Rust 的高性能和内存安全特性构建核心代理引擎，通过 Flutter Rust Bridge (FRB) 实现与 Flutter UI 层的高效通信，为用户提供流畅的操作体验和稳定的代理服务。

VeloGuard 支持主流代理协议（Shadowsocks、VMess、VLESS、Trojan、TUIC、Hysteria2、WireGuard 等），提供灵活的路由规则配置，并在 Android 平台通过 VPN Service + TUN 模式实现全局透明代理，在 Windows/macOS/Linux 平台通过 Wintun/tun-rs 实现系统级流量接管。

---

## ✨ 核心特性

### 🚀 高性能 Rust 核心引擎
- **全异步架构**：基于 Tokio 运行时，支持高并发连接处理
- **零拷贝优化**：最小化内存分配，提升数据转发效率
- **智能连接池**：复用连接资源，降低延迟
- **自研 TLS 栈**：基于 rustls 的定制化 TLS 实现

### 🌐 多协议支持

| 协议类型 | 支持协议 |
|---------|---------|
| **代理协议** | HTTP, SOCKS5, Shadowsocks (AEAD-2022), VMess, VLESS, Trojan |
| **隧道协议** | WireGuard, TUIC (QUIC), Hysteria2 |
| **入站协议** | HTTP Proxy, SOCKS5 Proxy, Mixed (HTTP + SOCKS5) |

### 🔧 智能路由系统
- **域名规则**：Domain / DomainSuffix / DomainKeyword / DomainRegex
- **IP 规则**：IP-CIDR / SRC-IP-CIDR / GeoIP
- **端口规则**：SRC-PORT / DST-PORT
- **进程规则**：Process Name 匹配
- **代理组**：Selector / URLTest / Fallback / LoadBalance / Relay

### 🎨 Material Design 3 界面
- Motion-physics 物理动画系统
- 动态颜色主题 (Dynamic Color)
- 响应式布局，适配多种屏幕尺寸
- 支持 11 种语言国际化

### 📊 实时监控与管理
- 流量统计与可视化图表
- 活跃连接管理
- 实时日志查看
- IP 地址检测

---

## 📱 支持平台

| 平台 | 状态 | 最低版本 | 代理模式 |
|------|------|----------|----------|
| Android | ✅ 已支持 | Android 7.0+ | VPN Service + TUN |
| Windows | ✅ 已支持 | Windows 10+ | Wintun TUN / 系统代理 |
| macOS | ✅ 已支持 | macOS 10.15+ | tun-rs TUN / 系统代理 |
| Linux | ✅ 已支持 | Ubuntu 20.04+ | tun-rs TUN / 系统代理 |
| iOS | 🚧 开发中 | iOS 12.0+ | Network Extension |
| HarmonyOS NEXT | 🚧 开发中 | API 12+ | VPN Extension |

---

## 🏗️ 系统架构

VeloGuard 采用分层架构设计，通过 Flutter Rust Bridge 实现 Dart 与 Rust 的高效跨语言通信。

### 整体架构图

```mermaid
graph TB
    subgraph Flutter["Flutter UI Layer"]
        UI[Screens & Widgets]
        State[State Management<br/>Provider]
        L10n[Localization<br/>11 Languages]
        Theme[Material Design 3<br/>Dynamic Color]
    end

    subgraph Bridge["Flutter Rust Bridge"]
        FRB[FFI Bindings<br/>flutter_rust_bridge]
    end

    subgraph Rust["Rust Core Layer"]
        subgraph Lib["veloguard-lib"]
            API[Public API]
            JNI[Android JNI]
        end
        
        subgraph Core["veloguard-core"]
            Inbound[Inbound Handler]
            Outbound[Outbound Proxy]
            Router[Rule Router]
            Dispatcher[Traffic Dispatcher]
        end
        
        subgraph Network["Network Stack"]
            DNS[veloguard-dns]
            TUN[veloguard-netstack]
            TCP[veloguard-solidtcp]
            QUIC[veloguard-quic]
        end
        
        subgraph Crypto["Crypto & TLS"]
            TLS[veloguard-rustls]
            WG[veloguard-boringtun]
        end
    end

    subgraph Platform["Platform Layer"]
        Android[Android VPN Service]
        Windows[Wintun Driver]
        Unix[tun-rs]
    end

    UI --> State
    State --> FRB
    FRB --> API
    API --> Core
    Core --> Network
    Core --> Crypto
    Network --> Platform
    Crypto --> Platform
```

### 数据流转流程

```mermaid
sequenceDiagram
    participant App as 应用程序
    participant TUN as TUN 设备
    participant Stack as TCP/IP 栈
    participant Router as 路由引擎
    participant Proxy as 代理出站
    participant Remote as 远程服务器

    App->>TUN: 发送网络请求
    TUN->>Stack: 原始 IP 包
    Stack->>Stack: TCP/UDP 重组
    Stack->>Router: 连接请求
    Router->>Router: 规则匹配
    Router->>Proxy: 选择出站
    Proxy->>Remote: 代理连接
    Remote-->>Proxy: 响应数据
    Proxy-->>Stack: 解密数据
    Stack-->>TUN: IP 包封装
    TUN-->>App: 返回响应
```

### 代理协议处理流程

```mermaid
flowchart LR
    subgraph Inbound["入站处理"]
        HTTP_IN[HTTP Proxy]
        SOCKS_IN[SOCKS5 Proxy]
        MIXED[Mixed Proxy]
        TUN_IN[TUN Device]
    end

    subgraph Router["路由决策"]
        RULES[规则匹配引擎]
        GEOIP[GeoIP 数据库]
        DOMAIN[域名规则]
    end

    subgraph Outbound["出站代理"]
        DIRECT[Direct]
        REJECT[Reject]
        SS[Shadowsocks]
        VMESS[VMess/VLESS]
        TROJAN[Trojan]
        TUIC[TUIC]
        WG[WireGuard]
        HY2[Hysteria2]
    end

    HTTP_IN --> RULES
    SOCKS_IN --> RULES
    MIXED --> RULES
    TUN_IN --> RULES
    
    RULES --> GEOIP
    RULES --> DOMAIN
    
    GEOIP --> DIRECT
    GEOIP --> SS
    DOMAIN --> VMESS
    DOMAIN --> TROJAN
    RULES --> TUIC
    RULES --> WG
    RULES --> HY2
    RULES --> REJECT
```

---

## 📁 项目结构

```
veloguard/
├── lib/                          # Flutter 应用代码
│   └── src/
│       ├── screens/              # 页面组件
│       ├── widgets/              # 可复用组件
│       ├── providers/            # 状态管理
│       ├── services/             # 平台服务
│       ├── l10n/                 # 国际化
│       └── rust/                 # FRB 生成代码
│
├── android/                      # Android 平台代码
│   └── app/src/main/kotlin/
│       └── com/blueokanna/veloguard/
│           ├── MainActivity.kt
│           ├── VeloGuardVpnService.kt
│           └── ...
│
├── rust/                         # Rust 工作空间
│   ├── veloguard-lib/            # Flutter FFI 绑定层
│   ├── veloguard-core/           # 核心代理逻辑
│   ├── veloguard-dns/            # DNS 解析器
│   ├── veloguard-netstack/       # 网络栈 (smoltcp)
│   ├── veloguard-solidtcp/       # TCP/IP 栈
│   ├── veloguard-quic/           # QUIC 协议实现
│   ├── veloguard-rustls/         # 自定义 TLS 实现
│   ├── veloguard-boringtun/      # WireGuard 实现
│   ├── tokio-veloguard-tls/      # Tokio TLS 适配器
│   ├── tuic/                     # TUIC 协议
│   ├── tuic-quinn/               # TUIC QUIC 实现
│   ├── veloguard-sock2proc/      # 进程名查询
│   ├── unix-udp-sock/            # Unix UDP Socket
│   ├── console-subscriber/       # 调试订阅器
│   └── veloguard-bin/            # CLI 程序
│
├── ios/                          # iOS 平台代码
├── macos/                        # macOS 平台代码
├── windows/                      # Windows 平台代码
├── linux/                        # Linux 平台代码
└── ohos/                         # HarmonyOS 平台代码
```

---

## 🚀 快速开始

### 环境要求

#### Flutter 开发环境
- Flutter SDK 3.24+
- Dart SDK 3.5+
- Android Studio / VS Code
- Xcode 15+ (macOS/iOS 开发)

#### Rust 开发环境
- Rust 1.75+ (推荐使用 rustup)
- Cargo
- Android NDK r25+ (Android 开发)
- LLVM/Clang (Windows 开发)

### 构建步骤

```bash
# 1. 克隆项目
git clone https://github.com/aspect-build/veloguard.git
cd veloguard

# 2. 安装 Flutter 依赖
flutter pub get

# 3. 安装 Rust 依赖
cd rust && cargo fetch && cd ..

# 4. 生成 FFI 绑定代码
flutter_rust_bridge_codegen generate

# 5. 构建 Android (需要 Android NDK)
cd rust
cargo ndk -t arm64-v8a -t armeabi-v7a -o ../android/app/src/main/jniLibs build --release
cd ..

# 6. 运行应用
flutter run
```

### 构建发布版本

```bash
# Android APK
flutter build apk --release

# Android App Bundle
flutter build appbundle --release

# Windows
flutter build windows --release

# macOS
flutter build macos --release

# Linux
flutter build linux --release
```

---

## 🔧 开发指南

### Rust 核心开发

```bash
# 进入 Rust 工作空间
cd rust

# 运行测试
cargo test --workspace

# 代码检查
cargo clippy --workspace

# 格式化代码
cargo fmt --all

# 构建 CLI 工具
cargo build -p veloguard-bin --release
```

### Flutter UI 开发

```bash
# 代码分析
flutter analyze

# 运行测试
flutter test

# 生成国际化文件
flutter gen-l10n
```

### 调试技巧

```bash
# 启用 Rust 日志
RUST_LOG=debug flutter run

# Android 日志查看
adb logcat | grep -E "(VeloGuard|rust)"

# 性能分析
flutter run --profile
```

---

## 📄 配置文件格式

VeloGuard 兼容 Clash 配置格式，支持以下配置项：

```yaml
# 基础配置
mixed-port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info

# DNS 配置
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

# 代理节点
proxies:
  - name: "proxy-1"
    type: ss
    server: server.example.com
    port: 443
    cipher: aes-256-gcm
    password: "password"

# 代理组
proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - proxy-1
      - DIRECT

# 路由规则
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
```

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

---

## 📜 许可证

本项目采用 [AGPL-3.0](LICENSE) 许可证开源。

---

## 💖 致谢与捐赠

如果 VeloGuard 对你有帮助，欢迎通过以下方式支持项目发展：

| ![Tether](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/tether.png "Tether (USDT)") **USDT** : Arbitrum One Network: **0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed** | ![USD Coin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/usd-coin.png "USD Coin (USDC)") **USDC**: Arbitrum One Network: **0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed** | ![Dash Coin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/dash.png "Dash Coin (Dash)") **Dash**: Dash Network: **XuJwtHWdsYzfLawymR3B3nDdS2W8dHnxyR** |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|

| ![0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed](https://github.com/user-attachments/assets/608c5e0d-edfc-4dee-be6f-63d40b53a65f) | ![0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed (1)](https://github.com/user-attachments/assets/87205826-1f76-4724-9734-3ecbfbfb729f) | ![XuJwtHWdsYzfLawymR3B3nDdS2W8dHnxyR](https://github.com/user-attachments/assets/71915604-cc14-426f-a8b9-9b7f023da084) |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/aspect-build">Blueokanna</a>
</p>

<p align="center">
  <sub>🛡️ Secure • 🚀 Fast • 🎨 Beautiful</sub>
</p>

---

# 📘 零基础使用指南

> 目标：把你当作从零开始的用户，**一步一步教你从“下载 → 配置 → 运行 → 检查是否生效”**。本节强调“能看懂、能照做、能成功”。

## 1. 你需要先知道的概念（简明但完整）

1. **客户端**：VeloGuard 就是客户端，它负责把你的网络请求转发到代理服务器。
2. **配置文件**：你从服务提供商拿到的“节点信息”，通常是一个 YAML 文件。VeloGuard 读取它才能工作。
3. **代理模式**：
  - **Direct**（直连）：不代理，直接访问网络。
  - **Global**（全局）：所有流量都走代理。
  - **Rule**（规则）：符合规则的走代理，其它直连。
4. **验证是否成功**：打开“IP 检测”或访问国外网站是否变成代理出口 IP。

> 记住：**配置文件决定一切**。没有配置文件，应用不会知道要连接谁。

---

## 2. “小白”最稳妥的使用流程（适用于所有平台）

下面是最稳妥、最不容易出错的顺序：

1. **准备配置文件**
  - 找服务提供商获取 `YAML` 配置。
  - 确认里面至少有：`proxies`、`proxy-groups`、`rules`。

2. **启动 VeloGuard 应用**
  - 首次启动会要求一些权限（Android 上需要 VPN 权限）。

3. **导入配置文件**
  - 在应用界面找到“配置/Profiles/Config”。
  - 选择“导入文件”或“粘贴文本”。

4. **选择代理模式**
  - 推荐新手：先用 **Global** 测试是否能连上。
  - 如果 OK，再切换到 **Rule**。

5. **开启系统代理 / VPN**
  - Android：会出现系统授权提示，点击“允许”。
  - Windows/macOS/Linux：会开启系统代理或 TUN 模式。

6. **验证是否成功**
  - 打开“IP 检测”或访问 `https://ipinfo.io`。
  - 看 IP 是否变成代理服务器所在地。

---

# 🧭 手把手：手机端（Android）

> **目标**：你只需照做，不需要理解原理，也能成功。

## 步骤 A：安装与权限
1. 安装 APK 并打开 VeloGuard。
2. 系统会提示“建立 VPN 连接”，点击**允许**。
3. 如果出现“忽略电池优化/后台限制”的提示，建议允许，否则后台可能断连。

## 步骤 B：导入配置
1. 打开“配置/Profiles”。
2. 选择“从文件导入”或“粘贴配置”。
3. 导入后点击“使用此配置”。

## 步骤 C：启动代理
1. 选择模式：**Global**（新手推荐）。
2. 点击“启动”。状态栏出现 VPN 图标。

## 步骤 D：验证
1. 打开浏览器访问 `https://ipinfo.io`。
2. 显示的 IP 应该是代理所在地。

---

# 🧭 手把手：电脑端（Windows/macOS/Linux）

## 步骤 A：安装与启动
1. 安装并启动 VeloGuard。
2. 应用会要求系统代理或 TUN 权限，允许即可。

## 步骤 B：导入配置
1. 点击“配置/Profiles”。
2. 选择 YAML 文件导入。
3. 设置为当前配置。

## 步骤 C：选择模式
1. 新手先用 **Global**。
2. 连接成功后，再切换 **Rule**。

## 步骤 D：验证
1. 打开浏览器访问 `https://ipinfo.io`。
2. IP 变成节点所在地即成功。

---

# 🖥️📱 网页与应用显示说明（手机/电脑都正常显示）

为保证 README 在 **GitHub 网页**、**手机浏览器** 和 **App 内置浏览器**都能正常显示：

1. **分层结构清晰**：每一段都有标题，手机上滚动阅读不会迷路。
2. **短句 + 列表**：避免长段落压缩成一坨文字。
3. **图示清晰可替代**：本 README 已用流程图/列表保证阅读体验。
4. **重点信息可直接复制**：所有链接均可点击。

如果你需要“更像论文的完整文档版”，建议把本 README 作为“摘要/概览”，再另建 `docs/使用手册.md` 做扩展正文。

---

# 🧪 配置文件示例与解释（小白版）

下面是一个典型配置结构，你只需要记住“每一块做什么”。

```yaml
mixed-port: 7890          # 本地混合端口（同时支持 HTTP/SOCKS）
mode: rule                # rule / global / direct
log-level: info           # 日志等级

dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip

proxies:                  # 代理节点
  - name: "proxy-1"
   type: ss
   server: server.example.com
   port: 443
   cipher: aes-256-gcm
   password: "password"

proxy-groups:             # 代理组（选择器）
  - name: "Proxy"
   type: select
   proxies:
    - proxy-1
    - DIRECT

rules:                    # 路由规则（谁走代理）
  - DOMAIN-SUFFIX,google.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
```

**你需要理解的只有三点：**
1. `proxies`：这里就是你能用的节点。
2. `proxy-groups`：把节点放到一个组里，方便切换。
3. `rules`：决定哪些网站走代理。

---

# ✅ 使用成功的判断标准（最可靠的几条）

1. **IP 地址已变化**
2. **访问被墙网站正常打开**
3. **应用日志无错误（或只有少量重试）**
4. **连接状态显示“已连接”**

---

# 🧯 常见问题与排错

## 问题 1：启动后无法上网
- 检查模式是否为 **Global/Rule**
- 配置文件是否正确导入
- 节点是否过期

## 问题 2：IP 没变化
- 可能是 **Direct 模式**
- 或规则未命中（建议先切到 Global）

## 问题 3：连接很慢
- 试试更换节点
- 检查 DNS 配置

## 问题 4：Android 后台掉线
- 关闭电池优化
- 锁定后台运行

---

# 📚 附录：给真正的新手的简短解释

**一句话总结：**
> VeloGuard 就是一个“把网络请求转发到你指定服务器”的工具。

只要你有配置文件，导入后点击“连接”，它就会帮你把流量转发出去。

