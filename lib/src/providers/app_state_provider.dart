import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:veloguard/src/rust/api.dart';
import 'package:veloguard/src/rust/types.dart';
import 'package:veloguard/src/services/storage_service.dart';
import 'package:veloguard/src/services/config_converter.dart';
import 'package:veloguard/src/services/platform_proxy_service.dart';

class AppStateProvider extends ChangeNotifier {
  // App state
  ThemeMode _themeMode = ThemeMode.system;
  bool _isServiceRunning = false;
  bool _isInitialized = false;
  ProxyStatus? _proxyStatus;
  TrafficStats? _trafficStats;
  List<ConnectionInfo> _connections = [];
  List<ActiveConnection> _activeConnections = [];
  SystemInfo? _systemInfo;
  String _logLevel = 'info';
  bool _isLoading = false;
  String _version = '';
  String _buildInfo = '';

  // Auto proxy settings
  bool _autoSystemProxy = true;
  bool _autoVpnClose = true;
  bool _systemProxyEnabledByUs = false;

  // Connection stats from tracker
  BigInt _totalConnections = BigInt.zero;
  BigInt _activeConnectionCount = BigInt.zero;
  BigInt _totalUploadBytes = BigInt.zero;
  BigInt _totalDownloadBytes = BigInt.zero;

  // Timer for system info refresh
  Timer? _systemInfoTimer;
  // Timer for periodic status/traffic/connection refresh
  Timer? _statusTimer;

  // Current speed values (from Rust tracker)
  BigInt _currentUploadSpeed = BigInt.zero;
  BigInt _currentDownloadSpeed = BigInt.zero;

  // Getters
  ThemeMode get themeMode => _themeMode;
  bool get isServiceRunning => _isServiceRunning;
  bool get isInitialized => _isInitialized;
  ProxyStatus? get proxyStatus => _proxyStatus;
  TrafficStats? get trafficStats => _trafficStats;
  BigInt get currentUploadSpeed => _currentUploadSpeed;
  BigInt get currentDownloadSpeed => _currentDownloadSpeed;
  List<ConnectionInfo> get connections => _connections;
  List<ActiveConnection> get activeConnections => _activeConnections;
  BigInt get totalConnections => _totalConnections;
  BigInt get activeConnectionCount => _activeConnectionCount;
  BigInt get totalUploadBytes => _totalUploadBytes;
  BigInt get totalDownloadBytes => _totalDownloadBytes;
  SystemInfo? get systemInfo => _systemInfo;
  String get logLevel => _logLevel;
  bool get isLoading => _isLoading;
  bool get autoSystemProxy => _autoSystemProxy;
  bool get autoVpnClose => _autoVpnClose;

  // Version info
  String get version => _version;
  String get buildInfo => _buildInfo;

  AppStateProvider() {
    _loadSettings();
    _loadSystemInfo();
    _loadVersionInfo();
    _initializeFromActiveProfile();
    _startSystemInfoTimer();
    _initializePlatformProxyService();
  }

  void _initializePlatformProxyService() {
    debugPrint('=== AppStateProvider: Initializing PlatformProxyService ===');
    final service = PlatformProxyService.instance;
    debugPrint(
      'AppStateProvider: PlatformProxyService initialized, vpnFd=${service.vpnFd}',
    );
  }

  @override
  void dispose() {
    _systemInfoTimer?.cancel();
    _statusTimer?.cancel();
    super.dispose();
  }

  // Start 3-second timer for system info refresh
  void _startSystemInfoTimer() {
    _systemInfoTimer?.cancel();
    _systemInfoTimer = Timer.periodic(const Duration(seconds: 3), (_) {
      _loadSystemInfo();
    });
  }

  // Start 1-second timer for live status/traffic/connection refresh
  void _startStatusTimer() {
    _statusTimer?.cancel();
    _statusTimer = Timer.periodic(const Duration(seconds: 1), (_) async {
      await _refreshStatus();
    });
  }

  void _stopStatusTimer() {
    _statusTimer?.cancel();
    _statusTimer = null;
  }

  // Initialize VeloGuard from active profile on startup
  Future<void> _initializeFromActiveProfile() async {
    try {
      final activeProfileId = await StorageService.instance
          .getActiveProfileId();
      if (activeProfileId == null) {
        debugPrint('No active profile found');
        _isInitialized = false;
        return;
      }

      debugPrint('Loading config for profile: $activeProfileId');
      final configContent = await StorageService.instance.getProfileConfig(
        activeProfileId,
      );
      if (configContent == null) {
        debugPrint('Active profile config not found');
        _isInitialized = false;
        return;
      }

      debugPrint('Config content length: ${configContent.length}');

      // Load general settings to override port configurations
      final generalSettings = await StorageService.instance
          .getGeneralSettings();

      debugPrint(
        'General settings loaded: mixedPort=${generalSettings.mixedPort}, socksPort=${generalSettings.socksPort}',
      );

      // Convert Clash YAML to VeloGuard JSON format with user settings
      final jsonConfig = ConfigConverter.convertClashYamlToJson(
        configContent,
        generalSettings: generalSettings,
      );

      debugPrint('JSON config generated, length: ${jsonConfig.length}');

      // Initialize VeloGuard with the converted config
      debugPrint('Calling initializeVeloguard...');
      await initializeVeloguard(configJson: jsonConfig);
      _isInitialized = true;
      debugPrint('VeloGuard initialized from active profile: $activeProfileId');
      notifyListeners();
    } catch (e, stackTrace) {
      debugPrint('Failed to initialize from active profile: $e');
      debugPrint('Stack trace: $stackTrace');
      _isInitialized = false;
    }
  }

  /// Set initialized state (called from ProfilesProvider when profile is selected)
  void setInitialized(bool value) {
    _isInitialized = value;
    notifyListeners();
  }

  // Load version information
  Future<void> _loadVersionInfo() async {
    try {
      _version = await getVersion();
      _buildInfo = await getBuildInfo();
      notifyListeners();
    } catch (e) {
      debugPrint('Failed to load version info: $e');
    }
  }

  // Load settings from SharedPreferences
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final themeModeString = prefs.getString('themeMode') ?? 'system';
    _themeMode = ThemeMode.values.firstWhere(
      (mode) => mode.name == themeModeString,
      orElse: () => ThemeMode.system,
    );
    _logLevel = prefs.getString('logLevel') ?? 'info';
    _autoSystemProxy = prefs.getBool('autoSystemProxy') ?? true;
    _autoVpnClose = prefs.getBool('autoVpnClose') ?? true;
    notifyListeners();
  }

  // Save settings to SharedPreferences
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('themeMode', _themeMode.name);
    await prefs.setString('logLevel', _logLevel);
    await prefs.setBool('autoSystemProxy', _autoSystemProxy);
    await prefs.setBool('autoVpnClose', _autoVpnClose);
  }

  // Auto proxy settings
  Future<void> setAutoSystemProxy(bool value) async {
    _autoSystemProxy = value;
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setAutoVpnClose(bool value) async {
    _autoVpnClose = value;
    await _saveSettings();
    notifyListeners();
  }

  // Load system information
  Future<void> _loadSystemInfo() async {
    try {
      _systemInfo = await getSystemInfo();
      notifyListeners();
    } catch (e) {
      debugPrint('Failed to load system info: $e');
    }
  }

  // Theme management
  Future<void> setThemeMode(ThemeMode mode) async {
    _themeMode = mode;
    await _saveSettings();
    notifyListeners();
  }

  // Service management
  Future<bool> startService() async {
    _isLoading = true;
    notifyListeners();

    try {
      // Try to initialize if not yet initialized
      if (!_isInitialized) {
        debugPrint(
          'Service not initialized, initializing from active profile...',
        );
        await _initializeFromActiveProfile();
      }

      if (!_isInitialized) {
        debugPrint('Cannot start service: No profile selected');
        _isLoading = false;
        notifyListeners();
        return false;
      }

      // First, ensure any previous instance is stopped
      try {
        debugPrint('Ensuring previous instance is stopped...');
        await stopVeloguard();
        // Wait for ports to be fully released
        await Future.delayed(const Duration(milliseconds: 1000));
      } catch (e) {
        debugPrint('Stop before start (expected if not running): $e');
      }

      // Re-initialize to get a fresh instance
      debugPrint('Re-initializing VeloGuard...');
      await _initializeFromActiveProfile();

      // Start the proxy
      debugPrint('Starting VeloGuard proxy...');
      await startVeloguard();

      // Set running state immediately after successful start
      _isServiceRunning = true;
      notifyListeners();

      // Wait a moment for the proxy to fully start
      await Future.delayed(const Duration(milliseconds: 300));

      // Verify the proxy is actually running
      try {
        final status = await getVeloguardStatus();
        debugPrint('Proxy status after start: running=${status.running}');
        if (!status.running) {
          debugPrint('WARNING: Proxy reports not running after start!');
        }
        _proxyStatus = status;
      } catch (e) {
        debugPrint('Failed to get status after start: $e');
      }

      // Start status timer for periodic updates
      _startStatusTimer();

      // Windows: Auto enable system proxy if setting is enabled
      if (Platform.isWindows && _autoSystemProxy) {
        final generalSettings = await StorageService.instance
            .getGeneralSettings();
        final port = generalSettings.mixedPort;
        debugPrint('Auto enabling system proxy on port $port...');
        final success = await PlatformProxyService.instance.enableSystemProxy(
          host: '127.0.0.1',
          httpPort: port,
          socksPort: generalSettings.socksPort,
        );
        if (success) {
          _systemProxyEnabledByUs = true;
          debugPrint('System proxy enabled automatically');
        } else {
          debugPrint('Failed to enable system proxy automatically');
        }
      }

      // Android: Auto enable VPN to route traffic through proxy
      // VPN must be enabled for apps to use the proxy on Android
      if (Platform.isAndroid) {
        debugPrint('Android detected, auto enabling VPN...');
        // Wait a bit for proxy to be fully ready
        await Future.delayed(const Duration(milliseconds: 500));

        // Try to enable VPN with retry
        bool vpnSuccess = false;
        for (int attempt = 1; attempt <= 3; attempt++) {
          debugPrint('VPN enable attempt $attempt/3...');
          vpnSuccess = await PlatformProxyService.instance.enableTunMode(
            mode: ProxyMode.rule,
          );
          if (vpnSuccess) {
            debugPrint('VPN enabled successfully on attempt $attempt');
            break;
          }
          if (attempt < 3) {
            debugPrint('VPN enable failed, retrying in 1 second...');
            await Future.delayed(const Duration(seconds: 1));
          }
        }

        if (!vpnSuccess) {
          debugPrint(
            'Failed to enable VPN after 3 attempts - VPN permission may be required',
          );
          // On Android, if VPN fails, the service is essentially not useful
          // But we keep it running in case user wants to retry VPN manually
        }
      }

      debugPrint('VeloGuard proxy started successfully');
      return true;
    } catch (e, stackTrace) {
      debugPrint('Failed to start service: $e');
      debugPrint('Stack trace: $stackTrace');
      _isServiceRunning = false;
      _isInitialized = false;
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> stopService() async {
    _isLoading = true;
    notifyListeners();

    try {
      debugPrint('Stopping VeloGuard service...');

      // Windows: Disable system proxy if we enabled it
      if (Platform.isWindows && _systemProxyEnabledByUs) {
        debugPrint('Auto disabling system proxy...');
        await PlatformProxyService.instance.disableSystemProxy();
        _systemProxyEnabledByUs = false;
        debugPrint('System proxy disabled automatically');
      }

      // Android: Always disable VPN when stopping service
      // Since we auto-enable VPN on service start, we should auto-disable on stop
      if (Platform.isAndroid) {
        debugPrint('Auto disabling VPN on Android...');
        await PlatformProxyService.instance.disableTunMode();
        debugPrint('VPN disabled automatically');
      }

      await stopVeloguard();
      _isServiceRunning = false;
      _isInitialized =
          false; // Mark as not initialized so we re-init on next start
      _proxyStatus = null;
      _trafficStats = null;
      _connections.clear();
      _currentUploadSpeed = BigInt.zero;
      _currentDownloadSpeed = BigInt.zero;
      _stopStatusTimer();
      debugPrint('VeloGuard service stopped');
    } catch (e) {
      debugPrint('Failed to stop service: $e');
      _stopStatusTimer();
      _isServiceRunning = false;
      _isInitialized = false;
      _currentUploadSpeed = BigInt.zero;
      _currentDownloadSpeed = BigInt.zero;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> restartService() async {
    debugPrint('Restarting VeloGuard service...');

    // Stop the service completely
    await stopService();

    // Wait for resources to be fully released
    await Future.delayed(const Duration(seconds: 2));

    // Re-initialize and start
    _isInitialized = false;
    await _initializeFromActiveProfile();

    if (_isInitialized) {
      await startService();
      debugPrint('VeloGuard service restarted successfully');
    } else {
      debugPrint('Failed to restart VeloGuard service: initialization failed');
    }
  }

  // Status refresh
  Future<void> _refreshStatus() async {
    try {
      _proxyStatus = await getVeloguardStatus();
      _trafficStats = await getTrafficStats();

      // Only update isServiceRunning from proxyStatus if we got a valid response
      // and the service was not just started (to avoid race conditions)
      if (_proxyStatus != null) {
        // If proxy reports running, update our state
        // If proxy reports not running but we think it's running, log a warning
        // but don't immediately change state (could be a temporary issue)
        if (_proxyStatus!.running) {
          _isServiceRunning = true;
        } else if (_isServiceRunning && !_isLoading) {
          // Proxy reports not running but we think it is
          // This could be a real stop or a temporary issue
          debugPrint(
            'WARNING: Proxy reports not running, but _isServiceRunning is true',
          );
          // Only update if we're not in the middle of starting/stopping
          _isServiceRunning = false;
        }
      }

      // Use speed values directly from Rust tracker
      if (_trafficStats != null) {
        _currentUploadSpeed = _trafficStats!.uploadSpeed;
        _currentDownloadSpeed = _trafficStats!.downloadSpeed;
      }

      if (!_isServiceRunning) {
        _currentUploadSpeed = BigInt.zero;
        _currentDownloadSpeed = BigInt.zero;
      }

      _connections = await getConnections();

      // Get active connections from connection tracker
      _activeConnections = await getActiveConnections();

      // Get connection stats from tracker
      // Returns (total_count, total_upload, total_download, active_count) - all BigInt
      final stats = await getConnectionStats();
      _totalConnections = stats.$1;
      _totalUploadBytes = stats.$2;
      _totalDownloadBytes = stats.$3;
      _activeConnectionCount = stats.$4;

      // Auto-start status timer if service is running and timer not active
      if (_isServiceRunning && _statusTimer == null) {
        _startStatusTimer();
      }

      // Stop timer if service is down
      if (!_isServiceRunning && _statusTimer != null) {
        _stopStatusTimer();
      }

      notifyListeners();
    } catch (e) {
      debugPrint('Failed to refresh status: $e');
    }
  }

  Future<void> refreshStatus() async {
    await _refreshStatus();
  }

  // Configuration management
  Future<bool> testConfiguration(String configJson) async {
    try {
      return await testConfig(configJson: configJson);
    } catch (e) {
      debugPrint('Failed to test configuration: $e');
      return false;
    }
  }

  Future<void> loadConfiguration(String configJson) async {
    _isLoading = true;
    notifyListeners();

    try {
      await initializeVeloguard(configJson: configJson);
      await _refreshStatus();
    } catch (e) {
      debugPrint('Failed to load configuration: $e');
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> reloadConfiguration(String configJson) async {
    _isLoading = true;
    notifyListeners();

    try {
      await reloadVeloguard(configJson: configJson);
      await _refreshStatus();
    } catch (e) {
      debugPrint('Failed to reload configuration: $e');
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  // Connection management
  Future<void> closeConnectionById(String connectionId) async {
    try {
      await closeConnection(connectionId: connectionId);
      await _refreshStatus();
    } catch (e) {
      debugPrint('Failed to close connection: $e');
    }
  }

  /// Close an active connection by ID (using connection tracker)
  Future<bool> closeActiveConnectionById(String connectionId) async {
    try {
      final result = await closeActiveConnection(connectionId: connectionId);
      await _refreshStatus();
      return result;
    } catch (e) {
      debugPrint('Failed to close active connection: $e');
      return false;
    }
  }

  Future<void> closeAllActiveConnections() async {
    // Use the new Rust API to close all connections at once
    try {
      await closeAllConnections();
      await _refreshStatus();
    } catch (e) {
      debugPrint('Failed to close all connections: $e');
      // Fallback to closing one by one
      for (final connection in _activeConnections) {
        try {
          await closeActiveConnectionById(connection.id);
        } catch (e) {
          debugPrint('Failed to close connection ${connection.id}: $e');
        }
      }
      await _refreshStatus();
    }
  }

  // Log level management
  Future<void> updateLogLevel(String level) async {
    try {
      await setLogLevel(level: level);
      _logLevel = level;
      await _saveSettings();
      notifyListeners();
    } catch (e) {
      debugPrint('Failed to set log level: $e');
    }
  }

  // Get formatted traffic data
  String getFormattedTraffic(BigInt bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var value = bytes.toDouble();
    var unitIndex = 0;

    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }

    // Always show 2 decimal places for better precision
    return '${value.toStringAsFixed(2)} ${units[unitIndex]}';
  }

  String getFormattedSpeed(BigInt bytesPerSecond) {
    return '${getFormattedTraffic(bytesPerSecond)}/s';
  }

  // Get connection status color
  Color getConnectionStatusColor() {
    if (_isServiceRunning) {
      return const Color(0xFF146C2E); // Success green
    } else {
      return const Color(0xFFBA1A1A); // Error red
    }
  }

  // Get connection status text
  String getConnectionStatusText() {
    if (_isLoading) {
      return 'Connecting...';
    } else if (_isServiceRunning) {
      return 'Connected';
    } else {
      return 'Disconnected';
    }
  }

  // Periodic status updates
  void startPeriodicUpdates() {
    // Update every 2 seconds when service is running
    if (_isServiceRunning) {
      Future.delayed(const Duration(seconds: 2), () {
        if (_isServiceRunning) {
          _refreshStatus();
          startPeriodicUpdates();
        }
      });
    }
  }
}
