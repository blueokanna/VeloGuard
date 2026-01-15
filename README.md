# VeloGuard 🛡️

<p align="center">
  <img src="assets/icon.png" alt="VeloGuard Logo" width="128" height="128" />
</p>

## 我能用它做什么？

**VeloGuard** 是一款现代化网络代理客户端，帮你在手机和电脑上安全、快速、可视化地访问网络：
- ✅ 更快更安全地浏览网络
- ✅ 跨设备使用（Android / Windows / macOS / Linux）
- ✅ 智能判断何时走代理、何时直连
- ✅ 随时查看当前网速、流量和出口 IP

---

## 🎯 核心特性（精简版）

1. **多协议支持**：Shadowsocks / VMess / VLESS / Trojan / WireGuard / TUIC / Hysteria2 等。
2. **智能分流**：规则/全局/直连三种模式，自动判定流量走向。
3. **实时监控**：当前网速、今日流量、活跃连接、出口 IP 一目了然。
4. **跨平台 UI**：Material Design 3，深浅色自适应，手机与桌面端均优化。

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

## ⚡ 零基础上手（推荐顺序）

### A. 获取并安装
- **Android**：在 GitHub Releases 下载 APK → 安装 → 首次启动允许 VPN 权限。
- **Windows/macOS/Linux**：下载对应安装包 → 安装 → 首次启动允许系统代理/TUN 权限。

### B. 导入配置（必做）
1. 在应用内找到「配置 / Profiles」。
2. 选择「导入文件」或「粘贴 YAML 文本」。
3. 设置为当前配置。

### C. 选择模式
- 初次建议 **Global（全局）**，确认能连通后再切到 **Rule（规则）**。

### D. 启动
- 点击「连接/开关」。Android 弹出 VPN 授权时选择允许。

### E. 验证是否生效
- 访问 `https://ipinfo.io`，若 IP 变为节点所在地，则成功。

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

## 📚 配置文件快速上手（最小可用示例）

VeloGuard 兼容 Clash 配置（`.yaml`）。按需替换 server/密码：

```yaml
# 基础设置
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info

# 代理节点
proxies:
  - name: "我的代理"
    type: ss
    server: 1.2.3.4
    port: 443
    cipher: aes-256-gcm
    password: "你的密码"

# 代理组
proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - 我的代理
      - DIRECT

# 路由规则
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
```

**记住三件事：**
1) `proxies` 放节点；2) `proxy-groups` 选择节点；3) `rules` 决定谁走代理。

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