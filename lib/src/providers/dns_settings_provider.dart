import 'package:flutter/material.dart';
import 'package:veloguard/src/services/storage_service.dart';

class DnsSettingsProvider extends ChangeNotifier {
  DnsSettings _settings = DnsSettings();
  bool _isLoading = false;

  DnsSettings get settings => _settings;
  bool get isLoading => _isLoading;

  // Convenience getters
  bool get enable => _settings.enable;
  bool get overrideDns => _settings.overrideDns;
  String get listen => _settings.listen;
  bool get useHosts => _settings.useHosts;
  bool get useSystemHosts => _settings.useSystemHosts;
  bool get ipv6 => _settings.ipv6;
  bool get followRules => _settings.followRules;
  bool get preferH3 => _settings.preferH3;
  String get dnsMode => _settings.dnsMode;
  String get fakeIpRange => _settings.fakeIpRange;
  List<String> get fakeIpFilter => _settings.fakeIpFilter;
  List<String> get defaultNameservers => _settings.defaultNameservers;
  Map<String, String> get nameserverPolicy => _settings.nameserverPolicy;
  List<String> get nameservers => _settings.nameservers;
  List<String> get fallback => _settings.fallback;
  List<String> get proxyNameservers => _settings.proxyNameservers;
  DnsFallbackFilter get fallbackFilter => _settings.fallbackFilter;

  DnsSettingsProvider() {
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    _isLoading = true;
    notifyListeners();

    try {
      _settings = await StorageService.instance.getDnsSettings();
    } catch (e) {
      debugPrint('Failed to load DNS settings: $e');
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> _saveSettings() async {
    try {
      await StorageService.instance.saveDnsSettings(_settings);
    } catch (e) {
      debugPrint('Failed to save DNS settings: $e');
    }
  }

  Future<void> setEnable(bool value) async {
    _settings = _settings.copyWith(enable: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setOverrideDns(bool value) async {
    _settings = _settings.copyWith(overrideDns: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setListen(String value) async {
    _settings = _settings.copyWith(listen: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setUseHosts(bool value) async {
    _settings = _settings.copyWith(useHosts: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setUseSystemHosts(bool value) async {
    _settings = _settings.copyWith(useSystemHosts: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setIpv6(bool value) async {
    _settings = _settings.copyWith(ipv6: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setFollowRules(bool value) async {
    _settings = _settings.copyWith(followRules: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setPreferH3(bool value) async {
    _settings = _settings.copyWith(preferH3: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setDnsMode(String value) async {
    _settings = _settings.copyWith(dnsMode: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setFakeIpRange(String value) async {
    _settings = _settings.copyWith(fakeIpRange: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setFakeIpFilter(List<String> value) async {
    _settings = _settings.copyWith(fakeIpFilter: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> addFakeIpFilter(String filter) async {
    if (!_settings.fakeIpFilter.contains(filter)) {
      final newList = List<String>.from(_settings.fakeIpFilter)..add(filter);
      await setFakeIpFilter(newList);
    }
  }

  Future<void> removeFakeIpFilter(String filter) async {
    final newList = List<String>.from(_settings.fakeIpFilter)..remove(filter);
    await setFakeIpFilter(newList);
  }

  Future<void> setDefaultNameservers(List<String> value) async {
    _settings = _settings.copyWith(defaultNameservers: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> addDefaultNameserver(String ns) async {
    if (!_settings.defaultNameservers.contains(ns)) {
      final newList = List<String>.from(_settings.defaultNameservers)..add(ns);
      await setDefaultNameservers(newList);
    }
  }

  Future<void> removeDefaultNameserver(String ns) async {
    final newList = List<String>.from(_settings.defaultNameservers)..remove(ns);
    await setDefaultNameservers(newList);
  }

  Future<void> setNameserverPolicy(Map<String, String> value) async {
    _settings = _settings.copyWith(nameserverPolicy: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> addNameserverPolicy(String domain, String server) async {
    final newMap = Map<String, String>.from(_settings.nameserverPolicy);
    newMap[domain] = server;
    await setNameserverPolicy(newMap);
  }

  Future<void> removeNameserverPolicy(String domain) async {
    final newMap = Map<String, String>.from(_settings.nameserverPolicy);
    newMap.remove(domain);
    await setNameserverPolicy(newMap);
  }

  Future<void> setNameservers(List<String> value) async {
    _settings = _settings.copyWith(nameservers: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> addNameserver(String ns) async {
    if (!_settings.nameservers.contains(ns)) {
      final newList = List<String>.from(_settings.nameservers)..add(ns);
      await setNameservers(newList);
    }
  }

  Future<void> removeNameserver(String ns) async {
    final newList = List<String>.from(_settings.nameservers)..remove(ns);
    await setNameservers(newList);
  }

  Future<void> setFallback(List<String> value) async {
    _settings = _settings.copyWith(fallback: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> addFallback(String ns) async {
    if (!_settings.fallback.contains(ns)) {
      final newList = List<String>.from(_settings.fallback)..add(ns);
      await setFallback(newList);
    }
  }

  Future<void> removeFallback(String ns) async {
    final newList = List<String>.from(_settings.fallback)..remove(ns);
    await setFallback(newList);
  }

  Future<void> setProxyNameservers(List<String> value) async {
    _settings = _settings.copyWith(proxyNameservers: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> addProxyNameserver(String ns) async {
    if (!_settings.proxyNameservers.contains(ns)) {
      final newList = List<String>.from(_settings.proxyNameservers)..add(ns);
      await setProxyNameservers(newList);
    }
  }

  Future<void> removeProxyNameserver(String ns) async {
    final newList = List<String>.from(_settings.proxyNameservers)..remove(ns);
    await setProxyNameservers(newList);
  }

  Future<void> setFallbackFilter(DnsFallbackFilter value) async {
    _settings = _settings.copyWith(fallbackFilter: value);
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setFallbackFilterGeoip(bool value) async {
    final newFilter = _settings.fallbackFilter.copyWith(geoip: value);
    await setFallbackFilter(newFilter);
  }

  Future<void> setFallbackFilterGeoipCode(String value) async {
    final newFilter = _settings.fallbackFilter.copyWith(geoipCode: value);
    await setFallbackFilter(newFilter);
  }

  Future<void> setFallbackFilterGeosite(List<String> value) async {
    final newFilter = _settings.fallbackFilter.copyWith(geosite: value);
    await setFallbackFilter(newFilter);
  }

  Future<void> addFallbackFilterGeosite(String site) async {
    if (!_settings.fallbackFilter.geosite.contains(site)) {
      final newList = List<String>.from(_settings.fallbackFilter.geosite)..add(site);
      await setFallbackFilterGeosite(newList);
    }
  }

  Future<void> removeFallbackFilterGeosite(String site) async {
    final newList = List<String>.from(_settings.fallbackFilter.geosite)..remove(site);
    await setFallbackFilterGeosite(newList);
  }

  Future<void> setFallbackFilterIpCidr(List<String> value) async {
    final newFilter = _settings.fallbackFilter.copyWith(ipCidr: value);
    await setFallbackFilter(newFilter);
  }

  Future<void> addFallbackFilterIpCidr(String cidr) async {
    if (!_settings.fallbackFilter.ipCidr.contains(cidr)) {
      final newList = List<String>.from(_settings.fallbackFilter.ipCidr)..add(cidr);
      await setFallbackFilterIpCidr(newList);
    }
  }

  Future<void> removeFallbackFilterIpCidr(String cidr) async {
    final newList = List<String>.from(_settings.fallbackFilter.ipCidr)..remove(cidr);
    await setFallbackFilterIpCidr(newList);
  }

  Future<void> setFallbackFilterDomain(List<String> value) async {
    final newFilter = _settings.fallbackFilter.copyWith(domain: value);
    await setFallbackFilter(newFilter);
  }

  Future<void> addFallbackFilterDomain(String domain) async {
    if (!_settings.fallbackFilter.domain.contains(domain)) {
      final newList = List<String>.from(_settings.fallbackFilter.domain)..add(domain);
      await setFallbackFilterDomain(newList);
    }
  }

  Future<void> removeFallbackFilterDomain(String domain) async {
    final newList = List<String>.from(_settings.fallbackFilter.domain)..remove(domain);
    await setFallbackFilterDomain(newList);
  }

  /// Generate DNS config for Rust core
  Map<String, dynamic> generateDnsConfig() {
    return {
      'enable': _settings.enable,
      'listen': _settings.listen,
      'ipv6': _settings.ipv6,
      'use-hosts': _settings.useHosts,
      'use-system-hosts': _settings.useSystemHosts,
      'prefer-h3': _settings.preferH3,
      'enhanced-mode': _settings.dnsMode,
      'fake-ip-range': _settings.fakeIpRange,
      'fake-ip-filter': _settings.fakeIpFilter,
      'default-nameserver': _settings.defaultNameservers,
      'nameserver-policy': _settings.nameserverPolicy,
      'nameserver': _settings.nameservers,
      'fallback': _settings.fallback,
      'proxy-server-nameserver': _settings.proxyNameservers,
      'fallback-filter': {
        'geoip': _settings.fallbackFilter.geoip,
        'geoip-code': _settings.fallbackFilter.geoipCode,
        'geosite': _settings.fallbackFilter.geosite,
        'ipcidr': _settings.fallbackFilter.ipCidr,
        'domain': _settings.fallbackFilter.domain,
      },
    };
  }
}
