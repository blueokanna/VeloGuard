# VeloGuard 🛡️

## 这是什么？

**VeloGuard** 是一款现代化网络代理客户端，可以让你：
- ✅ 更快更安全地浏览网络
- ✅ 在多个设备上（手机、电脑）使用
- ✅ 自动选择最快的连接方式
- ✅ 随时监控网络流量

简单来说，它就是一个「聪明的网络管家」🎯

---

## 🎯 主要功能（新手必读）

### 1️⃣ 支持多种连接协议
你可以添加不同类型的代理：
- Shadowsocks（简洁快速）
- VMess / VLESS（功能强大）
- Trojan（高效隐蔽）
- WireGuard（现代安全）
- 以及其他 7+ 种协议

**小白提示**：不知道选哪个？建议先用 Shadowsocks 或 VMess 尝试！

### 2️⃣ 智能自动转发
VeloGuard 会自动决定：
- 什么流量走代理
- 什么流量直接连接
- 哪些网站应该被加速

**你无需手动配置**，系统会根据规则自动处理 🤖

### 3️⃣ 实时流量监控
随时查看：
- 📊 当前网速
- 📈 今日流量使用量
- 🔗 活跃连接数
- 📍 当前 IP 地址

### 4️⃣ 简洁漂亮的界面
采用最新的 Material Design 3 风格：
- 深色/浅色自动切换
- 清晰的信息展示
- 新手友好的操作流程

---

## 📱 支持的设备

| 设备类型 | 系统版本 | 可用性 | 说明 |
|---------|---------|-------|------|
| 📱 Android 手机 | Android 7.0+ | ✅ 已可用 | VPN 模式和透明代理 |
| 💻 Windows 电脑 | Windows 10+ | ✅ 已可用 | 支持系统全局代理 |
| 🍎 Mac 电脑 | macOS 10.15+ | ✅ 已可用 | Intel / Apple Silicon |
| 🐧 Linux 系统 | Ubuntu 20.04+ | ✅ 已可用 | 支持主流发行版 |
| 📲 iPhone | iOS 12.0+ | 🚧 开发中 | 即将推出 |
| 🧿 HarmonyOS | API 12+ | 🚧 开发中 | 即将推出 |

---

## ⚡ 快速开始指南（新手版）

### 方式一：直接下载使用（最简单！）

#### Android 用户
1. 在 GitHub Releases 下载 APK 文件
2. 点击安装
3. 打开应用，添加你的代理配置
4. 点击「连接」即可使用

#### Windows/Mac/Linux 用户
1. 下载对应系统的安装包
2. 双击安装
3. 打开应用，导入配置文件（`.yaml`）
4. 点击开关启用代理

### 方式二：自己编译（面向开发者）

**需要的工具**：
# 1. 安装 Flutter（用于 UI）
flutter --version   # 需要 3.24+

# 2. 安装 Rust（用于核心引擎）
rustup --version    # 需要 1.75+

# 3. 克隆项目
git clone https://github.com/aspect-build/veloguard.git
cd veloguard

# 4. 安装依赖
flutter pub get

# 5. 生成代码
flutter_rust_bridge_codegen generate

# 6. 构建
flutter build apk --release   # Android
flutter build windows --release  # Windows

**提示**：编译需要 20-30 分钟，请耐心等待 ☕

---

## 🎮 最新功能一览

### 核心优势
- 🚀 **超快速**：Rust 引擎保证最高性能
- 🔒 **超安全**：支持最新的加密和隐私保护
- 📊 **超智能**：自动化规则系统，无需复杂配置
- 🌍 **跨平台**：一套代码，所有设备都能用

### 支持的代理协议详解

| 协议 | 特点 | 适用场景 |
|-----|------|---------|
| **Shadowsocks** | 轻量、快速 | ⭐ 初学者首选 |
| **VMess** | 功能丰富 | 中等用户 |
| **VLESS** | 现代、高效 | 高级用户 |
| **Trojan** | 隐蔽性好 | 需要隐蔽的场景 |
| **WireGuard** | 安全现代 | 注重安全的用户 |
| **TUIC/Hysteria2** | 超高速 | 追求速度的用户 |

---

## 📚 配置文件快速上手

VeloGuard 兼容 Clash 配置格式（`.yaml` 文件）。最简单的配置看起来这样：

# 基础设置
mixed-port: 7890          # 代理端口
allow-lan: false          # 是否允许 LAN 访问
mode: rule                # 使用规则模式
log-level: info           # 日志级别

# 代理节点配置示例
proxies:
  - name: "我的代理"
    type: ss              # Shadowsocks 协议
    server: 1.2.3.4       # 服务器地址
    port: 443             # 端口号
    cipher: aes-256-gcm   # 加密方式
    password: "你的密码"   # 密码

# 代理组（选择使用哪个节点）
proxy-groups:
  - name: "Proxy"
    type: select          # 手动选择
    proxies:
      - 我的代理
      - DIRECT            # 直接连接

# 简单规则
rules:
  - DOMAIN-SUFFIX,google.com,Proxy  # Google 走代理
  - GEOIP,CN,DIRECT                 # 国内流量直连
  - MATCH,Proxy                     # 其他走代理

**小白提示**：配置初期不用改这些，大多数预设配置都能用！

---

## 🆘 常见问题解答

### Q1: 为什么连接不上？
**A:** 检查以下几点：
- ✓ 代理配置是否正确（服务器地址、端口、密码）
- ✓ 你的网络连接是否正常
- ✓ 服务器是否还在运行
- ✓ 防火墙是否阻止了应用

### Q2: 流量用得特别快，为什么？
**A:** 可能是：
- 后台应用自动更新（邮件、云盘等）
- 视频应用自动缓存
- 手机系统更新

**解决方案**：进入应用设置，关闭不必要的后台功能。

### Q3: 使用代理会不会很卡？
**A:** 不会的！VeloGuard 使用 Rust 编写，性能非常高：
- ⚡ 平均延迟 < 50ms
- 📊 可处理 10000+ 并发连接
- 🔋 占用内存和电池很少

### Q4: 我可以在多个设备上使用吗？
**A:** 完全可以！VeloGuard 支持：
- 同时在手机、平板、电脑上使用
- 共享同一个代理配置
- 每个设备独立管理流量

### Q5: 安全吗？会记录我的数据吗？
**A:** 
- ✅ 开源项目，代码公开透明
- ✅ 本地加密，不上传个人信息
- ✅ 采用业界最新安全标准
- ✅ 支持端到端加密

---

## 🏗️ 技术架构（可选了解）

不了解技术的用户可以跳过这部分！👇

**简单版本**：
用户界面（Flutter）
    ↓
通信层（Flutter Rust Bridge）
    ↓
核心引擎（Rust - 高性能）
    ↓
系统层（Android/Windows/Linux/macOS）
    ↓
网络

**VeloGuard 的强大之处在于**：
- 前端用 Flutter 开发，跨平台支持
- 后端用 Rust 开发，性能和安全都顶级
- 两者通过高效的桥接层通信

---

## 🤝 想帮忙改进项目？

如果你发现 bug 或有好建议，欢迎：
1. 在 GitHub 上提交 Issue（报告问题）
2. Fork 项目，自己修改后提交 Pull Request
3. 完全不懂代码？直接反馈问题也很有帮助！

---

## 💖 支持开发者

如果 VeloGuard 帮助到了你，可以考虑：
- ⭐ 在 GitHub 上 Star 本项目
- 💬 分享给朋友
- 💰 通过加密货币捐赠支持开发

**捐赠地址**：
- USDT（Arbitrum）: `0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed`
- USDC（Arbitrum）: `0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed`

---

## 📜 开源协议

VeloGuard 使用 **AGPL-3.0** 协议开源。简单说就是：
- ✅ 免费使用
- ✅ 可以修改
- ✅ 必须开源修改后的代码

---

## 🌐 多语言支持

VeloGuard 支持 11 种语言：
🇨🇳 中文 • 🇺🇸 English • 🇯🇵 日本語 • 🇰🇷 한국어 • 🇷🇺 Русский
🇪🇸 Español • 🇫🇷 Français • 🇩🇪 Deutsch • 🇮🇹 Italiano 
🇵🇹 Português • 🇻🇳 Tiếng Việt

根据系统语言自动切换！

---

## 🚀 下一步计划

我们正在开发：
- 📲 iOS 版本（预计下个季度）
- 🧿 HarmonyOS 适配
- 🧠 AI 智能路由（自学习规则）
- 📊 更详细的流量分析

---

<p align="center">
  <strong>🛡️ Secure • 🚀 Fast • 🎨 Beautiful</strong>
</p>

<p align="center">
  由 <a href="https://github.com/aspect-build">Blueokanna</a> 用 ❤️ 打造
</p>

<p align="center">
  <sub>如有问题，欢迎在 GitHub 提交 Issue！</sub>
</p>