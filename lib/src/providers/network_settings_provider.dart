import 'dart:io';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:veloguard/src/services/storage_service.dart';

class NetworkSettingsProvider extends ChangeNotifier {
  NetworkSettings _settings = NetworkSettings();
  bool _isLoading = false;

  NetworkSettings get settings => _settings;
  bool get isLoading => _isLoading;

  // Convenience getters
  bool get systemProxy => _settings.systemProxy;
  List<String> get bypassDomains => _settings.bypassDomains;
  bool get tunEnabled => _settings.tunEnabled;
  String get tunStack => _settings.tunStack;
  bool get uwpLoopback => _settings.uwpLoopback;

  // Check if running on Windows
  bool get isWindows => Platform.isWindows;

  NetworkSettingsProvider() {
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    _isLoading = true;
    notifyListeners();

    try {
      _settings = await StorageService.instance.getNetworkSettings();
    } catch (e) {
      debugPrint('Failed to load network settings: $e');
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> _saveSettings() async {
    try {
      await StorageService.instance.saveNetworkSettings(_settings);
    } catch (e) {
      debugPrint('Failed to save network settings: $e');
    }
  }

  Future<void> setSystemProxy(bool value) async {
    _settings = _settings.copyWith(systemProxy: value);
    await _saveSettings();

    if (value) {
      await _enableSystemProxy();
    } else {
      await _disableSystemProxy();
    }

    notifyListeners();
  }

  Future<void> setBypassDomains(List<String> domains) async {
    _settings = _settings.copyWith(bypassDomains: domains);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> addBypassDomain(String domain) async {
    if (!_settings.bypassDomains.contains(domain)) {
      final newList = List<String>.from(_settings.bypassDomains)..add(domain);
      await setBypassDomains(newList);
    }
  }

  Future<void> removeBypassDomain(String domain) async {
    final newList = List<String>.from(_settings.bypassDomains)..remove(domain);
    await setBypassDomains(newList);
  }

  Future<void> setTunEnabled(bool value) async {
    _settings = _settings.copyWith(tunEnabled: value);
    await _saveSettings();

    // TUN mode requires admin privileges
    if (value) {
      await _enableTun();
    } else {
      await _disableTun();
    }

    notifyListeners();
  }

  Future<void> setTunStack(String stack) async {
    if (!['gvisor', 'system', 'mixed'].contains(stack)) {
      debugPrint('Invalid TUN stack: $stack');
      return;
    }

    _settings = _settings.copyWith(tunStack: stack);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setUwpLoopback(bool value) async {
    if (!Platform.isWindows) return;

    _settings = _settings.copyWith(uwpLoopback: value);
    await _saveSettings();

    if (value) {
      await _enableUwpLoopback();
    }

    notifyListeners();
  }

  // Platform-specific implementations
  Future<void> _enableSystemProxy() async {
    try {
      final proxyHost = '127.0.0.1';
      final proxyPort = await _resolveProxyPort() ?? '7890';
      final httpProxy = '$proxyHost:$proxyPort';
      if (Platform.isWindows) {
        final bypass = _settings.bypassDomains.join(';');
        final overrideValue = bypass.isNotEmpty ? '$bypass;<local>' : '<local>';
        // Windows: Set system proxy via registry
        await Process.run('reg', [
          'add',
          r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
          '/v',
          'ProxyEnable',
          '/t',
          'REG_DWORD',
          '/d',
          '1',
          '/f',
        ]);
        await Process.run('reg', [
          'add',
          r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
          '/v',
          'ProxyServer',
          '/t',
          'REG_SZ',
          '/d',
          httpProxy,
          '/f',
        ]);
        await Process.run('reg', [
          'add',
          r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
          '/v',
          'ProxyOverride',
          '/t',
          'REG_SZ',
          '/d',
          overrideValue,
          '/f',
        ]);

        // Also configure WinHTTP to ensure system components use the proxy
        await Process.run('netsh', [
          'winhttp',
          'set',
          'proxy',
          httpProxy,
        ]);
      } else if (Platform.isMacOS) {
        // macOS: Use networksetup
        await Process.run('networksetup', [
          '-setwebproxy',
          'Wi-Fi',
          proxyHost,
          proxyPort,
        ]);
        await Process.run('networksetup', [
          '-setsecurewebproxy',
          'Wi-Fi',
          proxyHost,
          proxyPort,
        ]);
        await Process.run('networksetup', [
          '-setsocksfirewallproxy',
          'Wi-Fi',
          proxyHost,
          proxyPort,
        ]);
      } else if (Platform.isLinux) {
        // Linux: Set GNOME proxy settings
        await Process.run('gsettings', [
          'set',
          'org.gnome.system.proxy',
          'mode',
          'manual',
        ]);
        await Process.run('gsettings', [
          'set',
          'org.gnome.system.proxy.http',
          'host',
          proxyHost,
        ]);
        await Process.run('gsettings', [
          'set',
          'org.gnome.system.proxy.http',
          'port',
          proxyPort,
        ]);
      }
    } catch (e) {
      debugPrint('Failed to enable system proxy: $e');
    }
  }

  /// Resolve proxy port from active profile config (prefer mixed_port/http port), fallback to 7890
  Future<String?> _resolveProxyPort() async {
    try {
      final activeProfileId = await StorageService.instance.getActiveProfileId();
      if (activeProfileId == null) return null;
      final configContent = await StorageService.instance.getProfileConfig(activeProfileId);
      if (configContent == null) return null;

      // Config content is stored as YAML originally; but our conversion pipeline saves JSON for runtime use.
      // Try JSON parse first; if YAML, this will fail gracefully and return null.
      final decoded = jsonDecode(configContent);
      if (decoded is! Map) return null;
      final general = decoded['general'] as Map<dynamic, dynamic>?;
      if (general == null) return null;

      // Priority: mixed_port -> port (http) -> socks_port
      final mixed = general['mixed-port'] ?? general['mixed_port'];
      final http = general['port'];
      final socks = general['socks-port'] ?? general['socks_port'];

      final port = mixed ?? http ?? socks;
      if (port == null) return null;
      return port.toString();
    } catch (e) {
      debugPrint('Failed to resolve proxy port from profile: $e');
      return null;
    }
  }

  Future<void> _disableSystemProxy() async {
    try {
      if (Platform.isWindows) {
        await Process.run('reg', [
          'add',
          r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
          '/v',
          'ProxyEnable',
          '/t',
          'REG_DWORD',
          '/d',
          '0',
          '/f',
        ]);
        await Process.run('reg', [
          'add',
          r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
          '/v',
          'ProxyOverride',
          '/t',
          'REG_SZ',
          '/d',
          '',
          '/f',
        ]);
        await Process.run('netsh', ['winhttp', 'reset', 'proxy']);
      } else if (Platform.isMacOS) {
        await Process.run('networksetup', [
          '-setwebproxystate',
          'Wi-Fi',
          'off',
        ]);
        await Process.run('networksetup', [
          '-setsecurewebproxystate',
          'Wi-Fi',
          'off',
        ]);
        await Process.run('networksetup', [
          '-setsocksfirewallproxystate',
          'Wi-Fi',
          'off',
        ]);
      } else if (Platform.isLinux) {
        await Process.run('gsettings', [
          'set',
          'org.gnome.system.proxy',
          'mode',
          'none',
        ]);
      }
    } catch (e) {
      debugPrint('Failed to disable system proxy: $e');
    }
  }

  Future<void> _enableTun() async {
    // TUN mode is handled by the Rust backend
    debugPrint('TUN mode enabled with stack: ${_settings.tunStack}');
  }

  Future<void> _disableTun() async {
    debugPrint('TUN mode disabled');
  }

  Future<void> _enableUwpLoopback() async {
    if (!Platform.isWindows) return;

    try {
      // Enable UWP loopback exemption
      // This requires admin privileges
      final result = await Process.run('powershell', [
        '-Command',
        'CheckNetIsolation LoopbackExempt -a -n="Microsoft.MicrosoftEdge_8wekyb3d8bbwe"',
      ]);
      debugPrint('UWP Loopback result: ${result.stdout}');
    } catch (e) {
      debugPrint('Failed to enable UWP loopback: $e');
    }
  }

  /// Generate config JSON with current network settings
  Map<String, dynamic> generateNetworkConfig() {
    return {
      'tun': {
        'enable': _settings.tunEnabled,
        'stack': _settings.tunStack,
        'auto-route': true,
        'auto-detect-interface': true,
      },
      'mixed-port': 7890,
      'socks-port': 7891,
      'allow-lan': false,
    };
  }
}
