# Changelog

## 1.0.1

- Added push and pull-request CI for Flutter, Android, and the complete Rust workspace.
- Made stable release validation fail explicitly when immutable release assets already exist.
- Restored Android release lint checks and validated partial signing configuration.
- Replaced platform status placeholders with native runtime results.
- Removed unused WireGuard and VPN connection-count placeholder APIs.
- Replaced the unfinished profile editor action with a validated configuration editor.
- Enforced Android release lint, hardened certificate trust, and removed obsolete permissions.
- Removed fake OHOS VPN success paths and the unused Android TUN placeholder API.
- Preserved TLS certificate validation when checking the proxied exit IP.

## 1.0.0

- Fixed proxy-page rendering crashes caused by invalid animated shadow values.
- Added dual-stack IPv4 and IPv6 listener support across HTTP, SOCKS5, mixed, and TUN paths.
- Added an animated in-app startup logo and removed the white startup flash.
- Added persisted rule/global proxy mode selection before service startup.
- Added live VeloGuard process memory reporting with a three-second refresh interval.
- Added checksum-verified stable-release update checks using release tag, publication date, and SHA256.
- Added validated HTTP and TLS traffic sniffing settings.
- Unified the interface on Material Design 3 with the bundled Roboto font.
- Added manual stable-release dispatch with immutable versioned assets.
- Fixed Classical `PROCESS-NAME` and trailing rule modifier handling.
- Added centralized Material 3 shape tokens and removed continuous proxy-card marquees.
- Localized update status and installation prompts across all supported languages.
