import 'package:flutter/material.dart';
import 'package:veloguard/src/services/storage_service.dart';

class GeneralSettingsProvider extends ChangeNotifier {
  GeneralSettings _settings = GeneralSettings();
  bool _isLoading = false;

  GeneralSettings get settings => _settings;
  bool get isLoading => _isLoading;

  // Convenience getters
  int get tcpKeepAliveInterval => _settings.tcpKeepAliveInterval;
  String get speedTestUrl => _settings.speedTestUrl;
  int get httpPort => _settings.httpPort;
  int get socksPort => _settings.socksPort;
  int get mixedPort => _settings.mixedPort;
  Map<String, String> get hosts => _settings.hosts;
  bool get ipv6 => _settings.ipv6;
  bool get allowLan => _settings.allowLan;
  bool get unifiedDelay => _settings.unifiedDelay;
  bool get appendSystemDns => _settings.appendSystemDns;
  bool get findProcess => _settings.findProcess;
  bool get tcpConcurrent => _settings.tcpConcurrent;
  String get bindAddress => _settings.bindAddress;
  String get mode => _settings.mode;
  String get logLevel => _settings.logLevel;
  String? get externalController => _settings.externalController;
  String? get externalUi => _settings.externalUi;
  String? get secret => _settings.secret;

  GeneralSettingsProvider() {
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    _isLoading = true;
    notifyListeners();

    try {
      _settings = await StorageService.instance.getGeneralSettings();
    } catch (e) {
      debugPrint('Failed to load general settings: $e');
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> _saveSettings() async {
    try {
      await StorageService.instance.saveGeneralSettings(_settings);
    } catch (e) {
      debugPrint('Failed to save general settings: $e');
    }
  }

  Future<void> setTcpKeepAliveInterval(int value) async {
    _settings = _settings.copyWith(tcpKeepAliveInterval: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setSpeedTestUrl(String value) async {
    _settings = _settings.copyWith(speedTestUrl: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setHttpPort(int value) async {
    _settings = _settings.copyWith(httpPort: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setSocksPort(int value) async {
    _settings = _settings.copyWith(socksPort: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setMixedPort(int value) async {
    _settings = _settings.copyWith(mixedPort: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setHosts(Map<String, String> value) async {
    _settings = _settings.copyWith(hosts: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> addHost(String domain, String ip) async {
    final newHosts = Map<String, String>.from(_settings.hosts);
    newHosts[domain] = ip;
    await setHosts(newHosts);
  }

  Future<void> removeHost(String domain) async {
    final newHosts = Map<String, String>.from(_settings.hosts);
    newHosts.remove(domain);
    await setHosts(newHosts);
  }

  Future<void> setIpv6(bool value) async {
    // 当切换 IPv6 时，更新绑定地址
    String newBindAddress;
    if (_settings.allowLan) {
      newBindAddress = value ? '::' : '0.0.0.0';
    } else {
      newBindAddress = value ? '::1' : '127.0.0.1';
    }
    _settings = _settings.copyWith(ipv6: value, bindAddress: newBindAddress);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setAllowLan(bool value) async {
    // 当开启局域网访问时，自动设置绑定地址
    String newBindAddress = _settings.bindAddress;
    if (value) {
      // 开启局域网：绑定到所有接口
      newBindAddress = _settings.ipv6 ? '::' : '0.0.0.0';
    } else {
      // 关闭局域网：只绑定本地
      newBindAddress = _settings.ipv6 ? '::1' : '127.0.0.1';
    }
    _settings = _settings.copyWith(
      allowLan: value,
      bindAddress: newBindAddress,
    );
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setUnifiedDelay(bool value) async {
    _settings = _settings.copyWith(unifiedDelay: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setAppendSystemDns(bool value) async {
    _settings = _settings.copyWith(appendSystemDns: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setFindProcess(bool value) async {
    _settings = _settings.copyWith(findProcess: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setTcpConcurrent(bool value) async {
    _settings = _settings.copyWith(tcpConcurrent: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setBindAddress(String value) async {
    _settings = _settings.copyWith(bindAddress: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setMode(String value) async {
    _settings = _settings.copyWith(mode: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setLogLevel(String value) async {
    _settings = _settings.copyWith(logLevel: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setExternalController(String? value) async {
    _settings = _settings.copyWith(externalController: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setExternalUi(String? value) async {
    _settings = _settings.copyWith(externalUi: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setSecret(String? value) async {
    _settings = _settings.copyWith(secret: value);
    await _saveSettings();
    notifyListeners();
  }

  /// Generate general config for Rust core
  Map<String, dynamic> generateGeneralConfig() {
    return {
      'port': _settings.httpPort,
      'socks-port': _settings.socksPort,
      'mixed-port': _settings.mixedPort,
      'allow-lan': _settings.allowLan,
      'bind-address': _settings.bindAddress,
      'mode': _settings.mode,
      'log-level': _settings.logLevel,
      'ipv6': _settings.ipv6,
      'tcp-concurrent': _settings.tcpConcurrent,
      'unified-delay': _settings.unifiedDelay,
      'find-process-mode': _settings.findProcess ? 'always' : 'off',
      'keep-alive-interval': _settings.tcpKeepAliveInterval,
      'external-controller': _settings.externalController,
      'external-ui': _settings.externalUi,
      'secret': _settings.secret,
      'hosts': _settings.hosts,
    };
  }
}
