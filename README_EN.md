# VeloGuard

<p align="center">
  <img src="assets/veloguard.png" width="128" height="128" alt="VeloGuard Logo" style="border-radius: 12px;">
</p>

<p align="center">
  Cross-platform proxy client built with Flutter and Rust<br>
  <a href="README.md">中文</a>
</p>

> Status: pre-release. The repository does not yet meet the bar for production support across all six target platforms and all requested protocols. This document describes only capabilities supported by code and verification evidence.

## Implemented Scope

- Flutter Material Design 3 UI with light/dark themes, dynamic color, Google Fonts, responsive navigation, and component/page motion.
- A layered Rust workspace for the proxy core, DNS, network stack, protocols, and Flutter Rust Bridge API.
- Fail-closed configuration conversion: unknown inbound, outbound, and rule types, plus malformed options, are rejected instead of silently becoming `DIRECT`.
- Shared Rust TUN packet processing for Android, Windows, and Linux, with platform-owned device lifecycles.
- Generated app icons for Windows, macOS, Linux, Android, iOS, and HarmonyOS NEXT from `assets/veloguard.png`.

## Protocol Status

| Protocol | Status | Evidence and limitations |
| --- | --- | --- |
| HTTP / SOCKS5 | Implemented | TCP outbound; release-environment end-to-end tests are still required |
| Shadowsocks | Experimental | Custom TCP/UDP crypto path and unit tests; no real-server interoperability evidence |
| VMess | Experimental | Custom protocol/transports; no Xray interoperability suite |
| VLESS | Experimental | Custom TCP/UDP/TLS path; no Xray interoperability suite |
| Trojan | Experimental | Custom TCP/UDP/TLS path; no standard-server interoperability suite |
| WireGuard | Not production-ready | Handshake/crypto and UDP paths exist; TCP lacks a complete TCP/IP state machine, retransmission, and congestion control |
| TUIC v5 | Experimental | Quinn-based implementation without a real TUIC server compatibility suite |
| Hysteria 2 | Not production-ready | The custom QUIC authentication/framing is not proven compatible with the Hysteria 2 specification |
| Hysteria v1 | Not implemented | It is no longer misclassified as Hysteria 2; configuration fails explicitly |
| NaiveProxy | Not implemented | Configuration fails explicitly and never bypasses the proxy through a direct fallback |

A protocol can move to “supported” only after interoperability tests against mainstream servers, TCP and UDP coverage, authentication failure tests, reconnect tests, and target-platform integration tests.

## Platform Status

| Platform | UI shell | System proxy | Full-tunnel VPN/TUN | Current conclusion |
| --- | --- | --- | --- | --- |
| Android | Present | N/A | `VpnService` path implemented | Requires device, ABI, and long-running regression tests |
| Windows | Present | Implemented | Wintun path implemented | Requires Windows 10/11 tests with elevation |
| Linux | Present | GNOME settings path | IPv4 global-mode path implemented | Requires root/device testing; rule/direct modes fail closed until socket marking or interface binding is implemented |
| macOS | Present | `networksetup` path | No Network Extension | Full-tunnel support cannot be claimed |
| iOS | Present | N/A | No Packet Tunnel Extension | Application shell only |
| HarmonyOS NEXT | Project skeleton | N/A | Explicitly returns `OHOS_VPN_UNSUPPORTED` | Not releasable |

## Architecture

```text
Flutter UI / Provider
        |
Flutter Rust Bridge
        |
veloguard-lib (FFI and platform entry points)
        |
veloguard-core (configuration, routing, inbound, outbound)
        +-- veloguard-dns
        +-- veloguard-netstack
        +-- veloguard-protocol
```

Clear ownership boundaries matter more than adding macros, generics, or complex lifetimes without a measurable benefit. These Rust features should be used only for useful zero-cost abstractions, ownership modeling, or meaningful deduplication.

## Prerequisites

- Flutter SDK compatible with Dart `^3.10.4`
- Stable Rust with edition 2021 and workspace resolver 3 support
- Android: Android SDK, NDK, and JDK 17
- Windows: Visual Studio C++ toolchain, Wintun, and elevation
- macOS/iOS: Xcode and valid signing configuration
- HarmonyOS NEXT: DevEco Studio, API 12 SDK, and Flutter OHOS toolchain

## Build and Check

```bash
flutter pub get
flutter analyze
flutter test

cd rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Build each target on its supported host and SDK:

```bash
flutter build apk --release
flutter build windows --release
flutter build linux --release
flutter build macos --release
flutter build ios --release --no-codesign
```

Use the DevEco/hvigor workflow in [ohos/README.md](ohos/README.md) for HarmonyOS NEXT. A successful build validates the toolchain, not the unfinished VPN data path.

## Icons

The single source is `assets/veloguard.png` and must be square and at least 1024x1024. On Windows run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/generate_icons.ps1
```

The script generates and validates Android, iOS, macOS, Windows, Linux, Web, and HarmonyOS assets. Generated icons should not be edited manually.

## Automated Verification

Every push and pull request runs Dart formatting, Flutter analysis and tests, an Android debug APK build, Android release lint, Rust formatting, Clippy with warnings denied, and all workspace tests. The release workflow repeats those checks while creating a signed APK.

An automated build is not evidence of VPN behavior or protocol interoperability. Android VPN traffic, privileged Windows/Linux TUN routing, Apple Network Extension, HarmonyOS VPN FD handling, and real-server protocol compatibility remain subject to the release gates below.

## GitHub Release Configuration

Create these repository Actions secrets before manually dispatching a release or pushing a release tag:

- `VELOGUARD_KEYSTORE_BASE64`
- `VELOGUARD_KEYSTORE_PASSWORD`
- `VELOGUARD_KEY_ALIAS`
- `VELOGUARD_KEY_PASSWORD`

The `version` in `pubspec.yaml`, the top changelog section, and the `vMAJOR.MINOR.PATCH` tag must match. Manual releases can run only from the default branch. Existing releases are immutable, so the workflow fails instead of silently replacing or accepting existing assets.

## Release Gates

1. Replace or validate WireGuard, Hysteria 2, and TUIC with mature audited implementations; add Hysteria v1 and NaiveProxy.
2. Validate Linux global route takeover/restoration in an isolated network and add loop-free rule/direct modes, IPv6, DNS leak protection, and network-change recovery; implement Apple Network Extension and the complete HarmonyOS VPN FD lifecycle into Rust.
3. Add a containerized interoperability matrix for every protocol, covering TCP, UDP, IPv4, IPv6, reconnects, and authentication failures.
4. Complete signed release builds and installation, start/stop, sleep/resume, network-switch, and leak tests on all six platforms.

## License

[GNU Affero General Public License v3.0 or later](LICENSE)
