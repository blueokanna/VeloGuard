import 'dart:async';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:veloguard/src/services/config_converter.dart';
import 'package:veloguard/src/services/storage_service.dart';
import 'package:veloguard/src/rust/api.dart' as rust_api;
import 'package:veloguard/main.dart' show isRustLibInitialized;

/// Latency test result
class LatencyResult {
  final String proxyName;
  final int? latencyMs;
  final bool isSuccess;
  final String? error;

  LatencyResult({
    required this.proxyName,
    this.latencyMs,
    this.isSuccess = false,
    this.error,
  });
}

class ProxiesProvider extends ChangeNotifier {
  ParsedClashConfig? _config;
  String? _selectedGroupName;
  final Map<String, String> _selectedProxies =
      {}; // groupName -> selected proxy name
  final Map<String, LatencyResult> _latencyResults =
      {}; // proxyName -> latency result
  bool _isLoading = false;
  bool _isTesting = false;
  String? _error;

  ParsedClashConfig? get config => _config;
  String? get selectedGroupName => _selectedGroupName;
  Map<String, String> get selectedProxies => _selectedProxies;
  Map<String, LatencyResult> get latencyResults => _latencyResults;
  bool get isLoading => _isLoading;
  bool get isTesting => _isTesting;
  String? get error => _error;

  List<ParsedProxyGroup> get proxyGroups => _config?.proxyGroups ?? [];
  List<ParsedProxy> get proxies => _config?.proxies ?? [];

  /// Get the currently selected group
  ParsedProxyGroup? get selectedGroup {
    if (_selectedGroupName == null || _config == null) return null;
    try {
      return _config!.proxyGroups.firstWhere(
        (g) => g.name == _selectedGroupName,
      );
    } catch (e) {
      return _config!.proxyGroups.isNotEmpty
          ? _config!.proxyGroups.first
          : null;
    }
  }

  /// Get proxies for a specific group
  List<dynamic> getProxiesForGroup(ParsedProxyGroup group) {
    final result = <dynamic>[];
    for (final proxyName in group.proxies) {
      // Check if it's a direct/reject
      if (proxyName == 'DIRECT' || proxyName == 'REJECT') {
        result.add(proxyName);
        continue;
      }
      // Check if it's another group
      final subGroup = _config?.proxyGroups
          .where((g) => g.name == proxyName)
          .firstOrNull;
      if (subGroup != null) {
        result.add(subGroup);
        continue;
      }
      // Check if it's a proxy
      final proxy = _config?.proxies
          .where((p) => p.name == proxyName)
          .firstOrNull;
      if (proxy != null) {
        result.add(proxy);
      } else {
        // Unknown proxy, add as string
        result.add(proxyName);
      }
    }
    return result;
  }

  /// Load config from the active profile
  Future<void> loadFromActiveProfile() async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final activeProfileId = await StorageService.instance
          .getActiveProfileId();
      if (activeProfileId == null) {
        _config = null;
        _error = 'No active profile';
        return;
      }

      final configContent = await StorageService.instance.getProfileConfig(
        activeProfileId,
      );
      if (configContent == null) {
        _config = null;
        _error = 'Profile config not found';
        return;
      }

      _config = ConfigConverter.parseClashConfig(configContent);

      // Load persisted selections
      await _loadPersistedSelections();

      // Select first group by default if no persisted selection
      if (_config!.proxyGroups.isNotEmpty && _selectedGroupName == null) {
        _selectedGroupName = _config!.proxyGroups.first.name;
      }

      // Initialize selected proxies with first proxy in each group if not persisted
      for (final group in _config!.proxyGroups) {
        if (!_selectedProxies.containsKey(group.name) &&
            group.proxies.isNotEmpty) {
          _selectedProxies[group.name] = group.proxies.first;
        }
      }
    } catch (e) {
      debugPrint('Failed to load proxies: $e');
      _error = e.toString();
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Load persisted selections from SharedPreferences
  Future<void> _loadPersistedSelections() async {
    try {
      final prefs = await SharedPreferences.getInstance();

      // Load selected group
      final savedGroup = prefs.getString('selected_proxy_group');
      if (savedGroup != null &&
          _config!.proxyGroups.any((g) => g.name == savedGroup)) {
        _selectedGroupName = savedGroup;
      }

      // Load selected proxies for each group
      for (final group in _config!.proxyGroups) {
        final savedProxy = prefs.getString('selected_proxy_${group.name}');
        if (savedProxy != null && group.proxies.contains(savedProxy)) {
          _selectedProxies[group.name] = savedProxy;
        }
      }
    } catch (e) {
      debugPrint('Failed to load persisted selections: $e');
    }
  }

  /// Save selections to SharedPreferences
  Future<void> _saveSelections() async {
    try {
      final prefs = await SharedPreferences.getInstance();

      // Save selected group
      if (_selectedGroupName != null) {
        await prefs.setString('selected_proxy_group', _selectedGroupName!);
      }

      // Save selected proxies for each group
      for (final entry in _selectedProxies.entries) {
        await prefs.setString('selected_proxy_${entry.key}', entry.value);
      }
    } catch (e) {
      debugPrint('Failed to save selections: $e');
    }
  }

  /// Load config from raw YAML content
  void loadFromYaml(String yamlContent) {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      _config = ConfigConverter.parseClashConfig(yamlContent);

      // Select first group by default
      if (_config!.proxyGroups.isNotEmpty && _selectedGroupName == null) {
        _selectedGroupName = _config!.proxyGroups.first.name;
      }

      // Initialize selected proxies
      for (final group in _config!.proxyGroups) {
        if (!_selectedProxies.containsKey(group.name) &&
            group.proxies.isNotEmpty) {
          _selectedProxies[group.name] = group.proxies.first;
        }
      }
    } catch (e) {
      debugPrint('Failed to parse config: $e');
      _error = e.toString();
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Select a proxy group to display
  void selectGroup(String groupName) {
    _selectedGroupName = groupName;
    _saveSelections();
    notifyListeners();
  }

  /// Select a proxy within a group
  Future<void> selectProxyInGroup(String groupName, String proxyName) async {
    _selectedProxies[groupName] = proxyName;
    _saveSelections();
    notifyListeners();

    // Call Rust API to change proxy selection (only if RustLib is initialized)
    if (!isRustLibInitialized) {
      debugPrint('Skipping Rust API call: RustLib not initialized');
      return;
    }

    try {
      await rust_api.selectProxyInGroup(
        groupName: groupName,
        proxyName: proxyName,
      );
      debugPrint('Proxy selection updated: $groupName -> $proxyName');
    } catch (e) {
      debugPrint('Failed to update proxy selection in Rust: $e');
      // Selection is still saved locally, so UI will reflect the change
    }
  }

  /// Get the selected proxy for a group
  String? getSelectedProxyForGroup(String groupName) {
    return _selectedProxies[groupName];
  }

  /// Get latency for a proxy
  LatencyResult? getLatency(String proxyName) {
    return _latencyResults[proxyName];
  }

  /// Test latency for all proxies in the current group (concurrent)
  Future<void> testAllLatencies() async {
    if (_isTesting || selectedGroup == null) return;

    _isTesting = true;
    notifyListeners();

    try {
      final group = selectedGroup!;
      final items = getProxiesForGroup(group);

      // Collect all test futures
      final List<Future<void>> testFutures = [];

      for (final item in items) {
        ParsedProxy? proxy;
        String proxyName;

        if (item is ParsedProxy) {
          proxy = item;
          proxyName = item.name;
        } else if (item is String && item != 'DIRECT' && item != 'REJECT') {
          proxyName = item;
          // Try to find the proxy
          proxy = _config?.proxies.where((p) => p.name == item).firstOrNull;
        } else {
          continue;
        }

        if (proxy?.server != null) {
          // Add concurrent test task
          testFutures.add(_testLatencyAndUpdate(proxyName, proxy!));
        }
      }

      // Run all tests concurrently
      await Future.wait(testFutures);
    } finally {
      _isTesting = false;
      notifyListeners();
    }
  }

  /// Internal method to test latency and update result
  Future<void> _testLatencyAndUpdate(
    String proxyName,
    ParsedProxy proxy,
  ) async {
    final result = await _testLatency(proxyName, proxy);
    _latencyResults[proxyName] = result;
    notifyListeners();
  }

  /// Test latency for a single proxy
  Future<void> testLatency(String proxyName) async {
    final proxy = _config?.proxies
        .where((p) => p.name == proxyName)
        .firstOrNull;
    if (proxy?.server == null) return;

    final result = await _testLatency(proxyName, proxy!);
    _latencyResults[proxyName] = result;
    notifyListeners();
  }

  Future<LatencyResult> _testLatency(
    String proxyName,
    ParsedProxy proxy,
  ) async {
    // Check if RustLib is initialized
    if (!isRustLibInitialized) {
      return LatencyResult(
        proxyName: proxyName,
        isSuccess: false,
        error: 'Rust library not initialized',
      );
    }

    try {
      final server = proxy.server;
      if (server == null) {
        return LatencyResult(
          proxyName: proxyName,
          isSuccess: false,
          error: 'No server address',
        );
      }

      String host = server;
      int resolvedPort = proxy.port ?? 0;

      // Handle server:port format
      if (server.contains(':')) {
        final parts = server.split(':');
        host = parts[0];
        if (parts.length > 1 && resolvedPort == 0) {
          resolvedPort = int.tryParse(parts[1]) ?? 0;
        }
      }

      if (resolvedPort == 0) {
        resolvedPort = 443; // Default for most proxy protocols
      }

      // Determine test method based on proxy type
      final proxyType = proxy.type.toLowerCase();

      if (proxyType == 'ss' || proxyType == 'shadowsocks') {
        // Use full Shadowsocks protocol test
        final password = proxy.options['password'] as String? ?? '';
        // Clash 配置里有的用 cipher，有的用 method；都兜一下
        final cipher =
            (proxy.options['cipher'] as String?) ??
            (proxy.options['method'] as String?) ??
            'aes-256-gcm';

        if (password.isEmpty) {
          return LatencyResult(
            proxyName: proxyName,
            isSuccess: false,
            error: 'Missing password',
          );
        }

        try {
          final result = await rust_api.testShadowsocksLatency(
            server: host,
            port: resolvedPort,
            password: password,
            cipher: cipher,
            timeoutMs: 5000,
          );

          return LatencyResult(
            proxyName: proxyName,
            latencyMs: result.latencyMs,
            isSuccess: result.success,
            error: result.error,
          );
        } catch (e) {
          // 如果 SS 协议测试失败，回落到 TCP 连通性以避免全红
          final result = await rust_api.testTcpConnectivity(
            server: host,
            port: resolvedPort,
            timeoutMs: 5000,
          );

          return LatencyResult(
            proxyName: proxyName,
            latencyMs: result.latencyMs,
            isSuccess: result.success,
            error: result.success ? null : e.toString(),
          );
        }
      }

      // For other proxy types, fallback to TCP connectivity test
      final result = await rust_api.testTcpConnectivity(
        server: host,
        port: resolvedPort,
        timeoutMs: 5000,
      );

      return LatencyResult(
        proxyName: proxyName,
        latencyMs: result.latencyMs,
        isSuccess: result.success,
        error: result.error,
      );
    } catch (e) {
      return LatencyResult(
        proxyName: proxyName,
        isSuccess: false,
        error: e.toString(),
      );
    }
  }

  /// Clear latency results
  void clearLatencies() {
    _latencyResults.clear();
    notifyListeners();
  }

  /// Clear all data
  void clear() {
    _config = null;
    _selectedGroupName = null;
    _selectedProxies.clear();
    _latencyResults.clear();
    _error = null;
    notifyListeners();
  }
}
