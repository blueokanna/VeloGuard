# VeloGuard

<p align="center">
  <img src="assets/veloguard.png" width="128" height="128" alt="VeloGuard 图标" style="border-radius: 12px;">
</p>

<p align="center">
  Flutter + Rust 跨平台代理客户端<br>
  <a href="README_EN.md">English</a>
</p>

## 当前实现

- Flutter Material Design 3 UI：明暗主题、动态颜色、Google Fonts、响应式导航和页面/组件动画。
- Rust workspace：核心代理、DNS、网络栈、协议与 Flutter Rust Bridge 分层。
- 配置转换采用失败关闭策略：未知入站、出站、规则类型和无效 options 会拒绝加载，绝不静默降级为 `DIRECT`。
- Android、Windows、Linux 共用 Rust TUN 数据包处理器，各平台独立管理设备生命周期。
- Windows、macOS、Linux、Android、iOS、HarmonyOS NEXT 的应用图标均由 `assets/veloguard.png` 统一生成。

## 协议状态

| 协议 | 当前状态 | 说明 |
| --- | --- | --- |
| HTTP / SOCKS5 | 已实现 | TCP 出站；仍需发布环境端到端测试 |
| Shadowsocks | 实验性 | 自研 TCP/UDP 加密路径和单元测试；未提供真实服务端互操作证据 |
| VMess | 实验性 | 自研协议与传输层；未提供 Xray 互操作测试 |
| VLESS | 实验性 | 自研 TCP/UDP/TLS 路径；未提供 Xray 互操作测试 |
| Trojan | 实验性 | 自研 TCP/UDP/TLS 路径；未提供标准服务端互操作测试 |
| WireGuard | 不可用于生产 | 握手/加密和 UDP 路径存在；TCP 路径缺少完整 TCP/IP 状态机、重传和拥塞控制 |
| TUIC v5 | 实验性 | 基于 Quinn 的实现；缺少真实 TUIC 服务端兼容性测试 |
| Hysteria 2 | 不可用于生产 | 当前自定义 QUIC 鉴权/帧格式未证明符合 Hysteria 2 标准 |
| Hysteria v1 | 未实现 | 不再错误映射为 Hysteria 2；配置会明确失败 |
| NaiveProxy | 未实现 | 配置会明确失败，不会绕过代理直连 |

协议进入“已支持”状态至少需要：官方/主流服务端互操作测试、TCP 与 UDP 测试、认证失败测试、断线重连测试，以及各目标平台上的集成测试。

## 平台状态

| 平台 | UI 壳 | 系统代理 | 全局 TUN/VPN | 当前结论 |
| --- | --- | --- | --- | --- |
| Android | 有 | 不适用 | `VpnService` 路径已实现 | 需要真机、ABI 和长连接回归测试 |
| Windows | 有 | 已实现 | Wintun 路径已实现 | 需要管理员权限和 Windows 10/11 实机测试 |
| Linux | 有 | GNOME 设置路径 | 已实现仅 IPv4 的 global 模式路径 | 仍需 root/实机验证；在完成 socket mark 或物理网卡绑定前，rule/direct 模式会主动拒绝 |
| macOS | 有 | `networksetup` 路径 | 未实现 Network Extension | 不能宣称全局代理支持 |
| iOS | 有 | 不适用 | 未实现 Packet Tunnel Extension | 仅应用壳 |
| HarmonyOS NEXT | 有工程骨架 | 不适用 | 明确返回 `OHOS_VPN_UNSUPPORTED` | 不可发布 |

## 架构

```text
Flutter UI / Provider
        |
Flutter Rust Bridge
        |
veloguard-lib (FFI 与平台入口)
        |
veloguard-core (配置、路由、入站、出站)
        +-- veloguard-dns
        +-- veloguard-netstack
        +-- veloguard-protocol
```

保持边界清晰比无目的地增加宏、泛型或复杂生命周期更重要。Rust 代码只在能减少重复、表达所有权或实现零成本抽象时使用这些能力。

## 环境要求

- Flutter SDK 对应 Dart `^3.10.4`
- Rust stable，支持 edition 2021 和 workspace resolver 3
- Android：Android SDK、NDK、JDK 17
- Windows：Visual Studio C++ 工具链；Wintun/管理员权限
- macOS/iOS：Xcode 与有效签名配置
- HarmonyOS NEXT：DevEco Studio、API 12 SDK、Flutter OHOS 工具链

## 构建与检查

```bash
flutter pub get
flutter analyze
flutter test

cd rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

平台构建必须在对应宿主和 SDK 上执行：

```bash
flutter build apk --release
flutter build windows --release
flutter build linux --release
flutter build macos --release
flutter build ios --release --no-codesign
```

HarmonyOS NEXT 使用 [ohos/README.md](ohos/README.md) 中的 DevEco/hvigor 流程。构建成功只证明工具链可用，不等于 VPN 数据路径已通过验证。

## 图标

唯一源文件为 `assets/veloguard.png`（正方形，至少 1024x1024）。Windows 环境执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/generate_icons.ps1
```

脚本会生成 Android、iOS、macOS、Windows、Linux、Web 和 HarmonyOS 所需资源，并校验源图尺寸。不要手工编辑生成图标。

## 自动化验证

每次 push 和 pull request 都会执行 Dart 格式检查、Flutter 分析与测试、Android Debug APK 构建、Android Release lint、Rust 格式检查、将警告视为错误的 Clippy，以及 Rust 全工作区测试。发布工作流会在生成签名 APK 时重复这些检查。

自动构建通过不等于 VPN 行为或协议互操作已经得到证明。Android VPN 真实流量、Windows/Linux 特权 TUN 路由、Apple Network Extension、HarmonyOS VPN FD 处理，以及真实服务端协议兼容性，仍必须满足下方发布门槛。

## GitHub 发布配置

手动执行发布工作流或推送发布标签前，必须配置以下仓库 Actions Secrets：

- `VELOGUARD_KEYSTORE_BASE64`
- `VELOGUARD_KEYSTORE_PASSWORD`
- `VELOGUARD_KEY_ALIAS`
- `VELOGUARD_KEY_PASSWORD`

`pubspec.yaml` 中的 `version`、变更日志顶部版本和 `vMAJOR.MINOR.PATCH` 标签必须一致。手动发布只能从默认分支执行。已经发布的 Release 及其产物不可变，工作流会明确失败，不会静默覆盖或把既有产物当作本次成功。

## 发布门槛

在标记正式版本前必须完成：

1. 用成熟、经过审计的实现替换或验证 WireGuard、Hysteria 2、TUIC；补充 Hysteria v1 与 NaiveProxy。
2. 完成 Linux global 路由接管/恢复的隔离网络测试，并补齐无路由环路的 rule/direct、IPv6、DNS 防泄漏与网络切换恢复；实现 Apple Network Extension 和 HarmonyOS VPN FD 到 Rust 的完整生命周期。
3. 为每个协议建立容器化互操作测试矩阵，并在 CI 中覆盖 TCP、UDP、IPv4、IPv6、重连和错误认证。
4. 在六个平台完成签名发布构建、安装、启停、休眠恢复、网络切换和泄漏测试。

## 许可证

[GNU Affero General Public License v3.0 or later](LICENSE)
