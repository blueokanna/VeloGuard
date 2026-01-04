import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// DNS settings model
class DnsSettings {
  final bool enable;
  final bool overrideDns;
  final String listen;
  final bool useHosts;
  final bool useSystemHosts;
  final bool ipv6;
  final bool followRules;
  final bool preferH3;
  final String dnsMode; // 'normal', 'fake-ip', 'redir-host'
  final String fakeIpRange;
  final List<String> fakeIpFilter;
  final List<String> defaultNameservers;
  final Map<String, String> nameserverPolicy;
  final List<String> nameservers;
  final List<String> fallback;
  final List<String> proxyNameservers;
  final DnsFallbackFilter fallbackFilter;

  DnsSettings({
    this.enable = true,
    this.overrideDns = false,
    this.listen = '0.0.0.0:53',
    this.useHosts = true,
    this.useSystemHosts = true,
    this.ipv6 = false,
    this.followRules = true,
    this.preferH3 = false,
    this.dnsMode = 'fake-ip',
    this.fakeIpRange = '198.18.0.1/16',
    this.fakeIpFilter = const [],
    this.defaultNameservers = const ['8.8.8.8', '1.1.1.1'],
    this.nameserverPolicy = const {},
    this.nameservers = const [
      'https://dns.google/dns-query',
      'https://cloudflare-dns.com/dns-query',
    ],
    this.fallback = const [],
    this.proxyNameservers = const [],
    DnsFallbackFilter? fallbackFilter,
  }) : fallbackFilter = fallbackFilter ?? DnsFallbackFilter();

  Map<String, dynamic> toJson() => {
    'enable': enable,
    'overrideDns': overrideDns,
    'listen': listen,
    'useHosts': useHosts,
    'useSystemHosts': useSystemHosts,
    'ipv6': ipv6,
    'followRules': followRules,
    'preferH3': preferH3,
    'dnsMode': dnsMode,
    'fakeIpRange': fakeIpRange,
    'fakeIpFilter': fakeIpFilter,
    'defaultNameservers': defaultNameservers,
    'nameserverPolicy': nameserverPolicy,
    'nameservers': nameservers,
    'fallback': fallback,
    'proxyNameservers': proxyNameservers,
    'fallbackFilter': fallbackFilter.toJson(),
  };

  factory DnsSettings.fromJson(Map<String, dynamic> json) => DnsSettings(
    enable: json['enable'] as bool? ?? true,
    overrideDns: json['overrideDns'] as bool? ?? false,
    listen: json['listen'] as String? ?? '0.0.0.0:53',
    useHosts: json['useHosts'] as bool? ?? true,
    useSystemHosts: json['useSystemHosts'] as bool? ?? true,
    ipv6: json['ipv6'] as bool? ?? false,
    followRules: json['followRules'] as bool? ?? true,
    preferH3: json['preferH3'] as bool? ?? false,
    dnsMode: json['dnsMode'] as String? ?? 'fake-ip',
    fakeIpRange: json['fakeIpRange'] as String? ?? '198.18.0.1/16',
    fakeIpFilter: (json['fakeIpFilter'] as List?)?.cast<String>() ?? [],
    defaultNameservers:
        (json['defaultNameservers'] as List?)?.cast<String>() ??
        ['8.8.8.8', '1.1.1.1'],
    nameserverPolicy:
        (json['nameserverPolicy'] as Map?)?.cast<String, String>() ?? {},
    nameservers: (json['nameservers'] as List?)?.cast<String>() ?? [],
    fallback: (json['fallback'] as List?)?.cast<String>() ?? [],
    proxyNameservers: (json['proxyNameservers'] as List?)?.cast<String>() ?? [],
    fallbackFilter: json['fallbackFilter'] != null
        ? DnsFallbackFilter.fromJson(
            json['fallbackFilter'] as Map<String, dynamic>,
          )
        : DnsFallbackFilter(),
  );

  DnsSettings copyWith({
    bool? enable,
    bool? overrideDns,
    String? listen,
    bool? useHosts,
    bool? useSystemHosts,
    bool? ipv6,
    bool? followRules,
    bool? preferH3,
    String? dnsMode,
    String? fakeIpRange,
    List<String>? fakeIpFilter,
    List<String>? defaultNameservers,
    Map<String, String>? nameserverPolicy,
    List<String>? nameservers,
    List<String>? fallback,
    List<String>? proxyNameservers,
    DnsFallbackFilter? fallbackFilter,
  }) {
    return DnsSettings(
      enable: enable ?? this.enable,
      overrideDns: overrideDns ?? this.overrideDns,
      listen: listen ?? this.listen,
      useHosts: useHosts ?? this.useHosts,
      useSystemHosts: useSystemHosts ?? this.useSystemHosts,
      ipv6: ipv6 ?? this.ipv6,
      followRules: followRules ?? this.followRules,
      preferH3: preferH3 ?? this.preferH3,
      dnsMode: dnsMode ?? this.dnsMode,
      fakeIpRange: fakeIpRange ?? this.fakeIpRange,
      fakeIpFilter: fakeIpFilter ?? this.fakeIpFilter,
      defaultNameservers: defaultNameservers ?? this.defaultNameservers,
      nameserverPolicy: nameserverPolicy ?? this.nameserverPolicy,
      nameservers: nameservers ?? this.nameservers,
      fallback: fallback ?? this.fallback,
      proxyNameservers: proxyNameservers ?? this.proxyNameservers,
      fallbackFilter: fallbackFilter ?? this.fallbackFilter,
    );
  }
}

/// DNS fallback filter settings
class DnsFallbackFilter {
  final bool geoip;
  final String geoipCode;
  final List<String> geosite;
  final List<String> ipCidr;
  final List<String> domain;

  DnsFallbackFilter({
    this.geoip = true,
    this.geoipCode = 'CN',
    this.geosite = const [],
    this.ipCidr = const [],
    this.domain = const [],
  });

  Map<String, dynamic> toJson() => {
    'geoip': geoip,
    'geoipCode': geoipCode,
    'geosite': geosite,
    'ipCidr': ipCidr,
    'domain': domain,
  };

  factory DnsFallbackFilter.fromJson(Map<String, dynamic> json) =>
      DnsFallbackFilter(
        geoip: json['geoip'] as bool? ?? true,
        geoipCode: json['geoipCode'] as String? ?? 'CN',
        geosite: (json['geosite'] as List?)?.cast<String>() ?? [],
        ipCidr: (json['ipCidr'] as List?)?.cast<String>() ?? [],
        domain: (json['domain'] as List?)?.cast<String>() ?? [],
      );

  DnsFallbackFilter copyWith({
    bool? geoip,
    String? geoipCode,
    List<String>? geosite,
    List<String>? ipCidr,
    List<String>? domain,
  }) {
    return DnsFallbackFilter(
      geoip: geoip ?? this.geoip,
      geoipCode: geoipCode ?? this.geoipCode,
      geosite: geosite ?? this.geosite,
      ipCidr: ipCidr ?? this.ipCidr,
      domain: domain ?? this.domain,
    );
  }
}

/// General settings model
class GeneralSettings {
  final int tcpKeepAliveInterval;
  final String speedTestUrl;
  final int httpPort;
  final int socksPort;
  final int mixedPort;
  final Map<String, String> hosts;
  final bool ipv6;
  final bool allowLan;
  final bool unifiedDelay;
  final bool appendSystemDns;
  final bool findProcess;
  final bool tcpConcurrent;
  final String bindAddress;
  final String mode; // 'rule', 'global', 'direct'
  final String logLevel;
  final String? externalController;
  final String? externalUi;
  final String? secret;
  final bool hapticFeedbackEnabled; // 震动反馈开关

  GeneralSettings({
    this.tcpKeepAliveInterval = 30,
    this.speedTestUrl = 'http://www.gstatic.com/generate_204',
    this.httpPort = 7890,
    this.socksPort = 7891,
    this.mixedPort = 7897,
    this.hosts = const {},
    this.ipv6 = false,
    this.allowLan = false,
    this.unifiedDelay = false,
    this.appendSystemDns = false,
    this.findProcess = true,
    this.tcpConcurrent = false,
    this.bindAddress = '127.0.0.1',
    this.mode = 'rule',
    this.logLevel = 'info',
    this.externalController,
    this.externalUi,
    this.secret,
    this.hapticFeedbackEnabled = false, // 默认关闭
  });

  Map<String, dynamic> toJson() => {
    'tcpKeepAliveInterval': tcpKeepAliveInterval,
    'speedTestUrl': speedTestUrl,
    'httpPort': httpPort,
    'socksPort': socksPort,
    'mixedPort': mixedPort,
    'hosts': hosts,
    'ipv6': ipv6,
    'allowLan': allowLan,
    'unifiedDelay': unifiedDelay,
    'appendSystemDns': appendSystemDns,
    'findProcess': findProcess,
    'tcpConcurrent': tcpConcurrent,
    'bindAddress': bindAddress,
    'mode': mode,
    'logLevel': logLevel,
    'externalController': externalController,
    'externalUi': externalUi,
    'secret': secret,
    'hapticFeedbackEnabled': hapticFeedbackEnabled,
  };

  factory GeneralSettings.fromJson(Map<String, dynamic> json) {
    final allowLan = json['allowLan'] as bool? ?? false;
    final ipv6 = json['ipv6'] as bool? ?? false;
    var bindAddress = json['bindAddress'] as String? ?? '127.0.0.1';

    // Convert '*' or invalid addresses to proper IP format
    if (bindAddress == '*') {
      if (allowLan) {
        bindAddress = ipv6 ? '::' : '0.0.0.0';
      } else {
        bindAddress = ipv6 ? '::1' : '127.0.0.1';
      }
    }

    return GeneralSettings(
      tcpKeepAliveInterval: json['tcpKeepAliveInterval'] as int? ?? 30,
      speedTestUrl:
          json['speedTestUrl'] as String? ??
          'http://www.gstatic.com/generate_204',
      httpPort: json['httpPort'] as int? ?? 7890,
      socksPort: json['socksPort'] as int? ?? 7891,
      mixedPort: json['mixedPort'] as int? ?? 7897,
      hosts: (json['hosts'] as Map?)?.cast<String, String>() ?? {},
      ipv6: ipv6,
      allowLan: allowLan,
      unifiedDelay: json['unifiedDelay'] as bool? ?? false,
      appendSystemDns: json['appendSystemDns'] as bool? ?? false,
      findProcess: json['findProcess'] as bool? ?? true,
      tcpConcurrent: json['tcpConcurrent'] as bool? ?? false,
      bindAddress: bindAddress,
      mode: json['mode'] as String? ?? 'rule',
      logLevel: json['logLevel'] as String? ?? 'info',
      externalController: json['externalController'] as String?,
      externalUi: json['externalUi'] as String?,
      secret: json['secret'] as String?,
      hapticFeedbackEnabled: json['hapticFeedbackEnabled'] as bool? ?? false,
    );
  }

  GeneralSettings copyWith({
    int? tcpKeepAliveInterval,
    String? speedTestUrl,
    int? httpPort,
    int? socksPort,
    int? mixedPort,
    Map<String, String>? hosts,
    bool? ipv6,
    bool? allowLan,
    bool? unifiedDelay,
    bool? appendSystemDns,
    bool? findProcess,
    bool? tcpConcurrent,
    String? bindAddress,
    String? mode,
    String? logLevel,
    String? externalController,
    String? externalUi,
    String? secret,
    bool? hapticFeedbackEnabled,
  }) {
    return GeneralSettings(
      tcpKeepAliveInterval: tcpKeepAliveInterval ?? this.tcpKeepAliveInterval,
      speedTestUrl: speedTestUrl ?? this.speedTestUrl,
      httpPort: httpPort ?? this.httpPort,
      socksPort: socksPort ?? this.socksPort,
      mixedPort: mixedPort ?? this.mixedPort,
      hosts: hosts ?? this.hosts,
      ipv6: ipv6 ?? this.ipv6,
      allowLan: allowLan ?? this.allowLan,
      unifiedDelay: unifiedDelay ?? this.unifiedDelay,
      appendSystemDns: appendSystemDns ?? this.appendSystemDns,
      findProcess: findProcess ?? this.findProcess,
      tcpConcurrent: tcpConcurrent ?? this.tcpConcurrent,
      bindAddress: bindAddress ?? this.bindAddress,
      mode: mode ?? this.mode,
      logLevel: logLevel ?? this.logLevel,
      externalController: externalController ?? this.externalController,
      externalUi: externalUi ?? this.externalUi,
      secret: secret ?? this.secret,
      hapticFeedbackEnabled:
          hapticFeedbackEnabled ?? this.hapticFeedbackEnabled,
    );
  }
}

/// Profile configuration model with JSON serialization
class ProfileConfig {
  final String id;
  final String name;
  final String type; // 'url', 'file', 'qrcode'
  final String source;
  final String? configContent;
  final DateTime? lastUpdated;
  final DateTime? expiresAt;
  final int? usedTraffic;
  final int? totalTraffic;
  final bool autoUpdate;
  final int autoUpdateInterval; // in minutes

  ProfileConfig({
    required this.id,
    required this.name,
    required this.type,
    required this.source,
    this.configContent,
    this.lastUpdated,
    this.expiresAt,
    this.usedTraffic,
    this.totalTraffic,
    this.autoUpdate = false,
    this.autoUpdateInterval = 180,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'type': type,
    'source': source,
    'configContent': configContent,
    'lastUpdated': lastUpdated?.toIso8601String(),
    'expiresAt': expiresAt?.toIso8601String(),
    'usedTraffic': usedTraffic,
    'totalTraffic': totalTraffic,
    'autoUpdate': autoUpdate,
    'autoUpdateInterval': autoUpdateInterval,
  };

  factory ProfileConfig.fromJson(Map<String, dynamic> json) => ProfileConfig(
    id: json['id'] as String,
    name: json['name'] as String,
    type: json['type'] as String,
    source: json['source'] as String,
    configContent: json['configContent'] as String?,
    lastUpdated: json['lastUpdated'] != null
        ? DateTime.parse(json['lastUpdated'] as String)
        : null,
    expiresAt: json['expiresAt'] != null
        ? DateTime.parse(json['expiresAt'] as String)
        : null,
    usedTraffic: json['usedTraffic'] as int?,
    totalTraffic: json['totalTraffic'] as int?,
    autoUpdate: json['autoUpdate'] as bool? ?? false,
    autoUpdateInterval: json['autoUpdateInterval'] as int? ?? 180,
  );

  ProfileConfig copyWith({
    String? id,
    String? name,
    String? type,
    String? source,
    String? configContent,
    DateTime? lastUpdated,
    DateTime? expiresAt,
    int? usedTraffic,
    int? totalTraffic,
    bool? autoUpdate,
    int? autoUpdateInterval,
  }) {
    return ProfileConfig(
      id: id ?? this.id,
      name: name ?? this.name,
      type: type ?? this.type,
      source: source ?? this.source,
      configContent: configContent ?? this.configContent,
      lastUpdated: lastUpdated ?? this.lastUpdated,
      expiresAt: expiresAt ?? this.expiresAt,
      usedTraffic: usedTraffic ?? this.usedTraffic,
      totalTraffic: totalTraffic ?? this.totalTraffic,
      autoUpdate: autoUpdate ?? this.autoUpdate,
      autoUpdateInterval: autoUpdateInterval ?? this.autoUpdateInterval,
    );
  }
}

/// Network settings model
class NetworkSettings {
  final bool systemProxy;
  final List<String> bypassDomains;
  final bool tunEnabled;
  final String tunStack; // 'gvisor', 'system', 'mixed'
  final bool uwpLoopback; // Windows only

  NetworkSettings({
    this.systemProxy = false,
    this.bypassDomains = const [],
    this.tunEnabled = false,
    this.tunStack = 'mixed',
    this.uwpLoopback = false,
  });

  Map<String, dynamic> toJson() => {
    'systemProxy': systemProxy,
    'bypassDomains': bypassDomains,
    'tunEnabled': tunEnabled,
    'tunStack': tunStack,
    'uwpLoopback': uwpLoopback,
  };

  factory NetworkSettings.fromJson(Map<String, dynamic> json) =>
      NetworkSettings(
        systemProxy: json['systemProxy'] as bool? ?? false,
        bypassDomains:
            (json['bypassDomains'] as List<dynamic>?)
                ?.map((e) => e as String)
                .toList() ??
            [],
        tunEnabled: json['tunEnabled'] as bool? ?? false,
        tunStack: json['tunStack'] as String? ?? 'mixed',
        uwpLoopback: json['uwpLoopback'] as bool? ?? false,
      );

  NetworkSettings copyWith({
    bool? systemProxy,
    List<String>? bypassDomains,
    bool? tunEnabled,
    String? tunStack,
    bool? uwpLoopback,
  }) {
    return NetworkSettings(
      systemProxy: systemProxy ?? this.systemProxy,
      bypassDomains: bypassDomains ?? this.bypassDomains,
      tunEnabled: tunEnabled ?? this.tunEnabled,
      tunStack: tunStack ?? this.tunStack,
      uwpLoopback: uwpLoopback ?? this.uwpLoopback,
    );
  }
}

/// Storage service for persisting app data
class StorageService {
  static StorageService? _instance;
  static StorageService get instance => _instance ??= StorageService._();

  StorageService._();

  SharedPreferences? _prefs;
  String? _dataDir;

  Future<void> init() async {
    _prefs = await SharedPreferences.getInstance();
    final appDir = await getApplicationSupportDirectory();
    _dataDir = appDir.path;

    // Ensure data directories exist
    await Directory('$_dataDir/profiles').create(recursive: true);
    await Directory('$_dataDir/config').create(recursive: true);
  }

  // ==================== Profile Management ====================

  Future<List<ProfileConfig>> getProfiles() async {
    final profilesJson = _prefs?.getString('profiles');
    if (profilesJson == null) return [];

    try {
      final List<dynamic> decoded = jsonDecode(profilesJson);
      return decoded
          .map((e) => ProfileConfig.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (e) {
      debugPrint('Failed to load profiles: $e');
      return [];
    }
  }

  Future<void> saveProfiles(List<ProfileConfig> profiles) async {
    final jsonList = profiles.map((p) => p.toJson()).toList();
    await _prefs?.setString('profiles', jsonEncode(jsonList));
  }

  Future<void> addProfile(ProfileConfig profile) async {
    final profiles = await getProfiles();
    profiles.add(profile);
    await saveProfiles(profiles);
  }

  Future<void> updateProfile(ProfileConfig profile) async {
    final profiles = await getProfiles();
    final index = profiles.indexWhere((p) => p.id == profile.id);
    if (index != -1) {
      profiles[index] = profile;
      await saveProfiles(profiles);
    }
  }

  Future<void> deleteProfile(String id) async {
    final profiles = await getProfiles();
    profiles.removeWhere((p) => p.id == id);
    await saveProfiles(profiles);

    // Also delete config file if exists
    final configFile = File('$_dataDir/profiles/$id.yaml');
    if (await configFile.exists()) {
      await configFile.delete();
    }
  }

  Future<void> saveProfileConfig(String profileId, String configContent) async {
    final configFile = File('$_dataDir/profiles/$profileId.yaml');
    await configFile.writeAsString(configContent);
  }

  Future<String?> getProfileConfig(String profileId) async {
    final configFile = File('$_dataDir/profiles/$profileId.yaml');
    if (await configFile.exists()) {
      return configFile.readAsString();
    }
    return null;
  }

  // ==================== Active Profile ====================

  Future<String?> getActiveProfileId() async {
    return _prefs?.getString('activeProfileId');
  }

  Future<void> setActiveProfileId(String? id) async {
    if (id != null) {
      await _prefs?.setString('activeProfileId', id);
    } else {
      await _prefs?.remove('activeProfileId');
    }
  }

  // ==================== Network Settings ====================

  Future<NetworkSettings> getNetworkSettings() async {
    final json = _prefs?.getString('networkSettings');
    if (json == null) return NetworkSettings();

    try {
      return NetworkSettings.fromJson(jsonDecode(json));
    } catch (e) {
      debugPrint('Failed to load network settings: $e');
      return NetworkSettings();
    }
  }

  Future<void> saveNetworkSettings(NetworkSettings settings) async {
    await _prefs?.setString('networkSettings', jsonEncode(settings.toJson()));
  }

  // ==================== Language Settings ====================

  Future<String?> getLocale() async {
    return _prefs?.getString('locale');
  }

  Future<void> setLocale(String? locale) async {
    if (locale != null) {
      await _prefs?.setString('locale', locale);
    } else {
      await _prefs?.remove('locale');
    }
  }

  // ==================== General Settings ====================

  Future<String> getLogLevel() async {
    return _prefs?.getString('logLevel') ?? 'info';
  }

  Future<void> setLogLevel(String level) async {
    await _prefs?.setString('logLevel', level);
  }

  Future<bool> getAutoStart() async {
    return _prefs?.getBool('autoStart') ?? false;
  }

  Future<void> setAutoStart(bool value) async {
    await _prefs?.setBool('autoStart', value);
  }

  // ==================== DNS Settings ====================

  Future<DnsSettings> getDnsSettings() async {
    final json = _prefs?.getString('dnsSettings');
    if (json == null) return DnsSettings();

    try {
      return DnsSettings.fromJson(jsonDecode(json));
    } catch (e) {
      debugPrint('Failed to load DNS settings: $e');
      return DnsSettings();
    }
  }

  Future<void> saveDnsSettings(DnsSettings settings) async {
    await _prefs?.setString('dnsSettings', jsonEncode(settings.toJson()));
  }

  // ==================== General Settings ====================

  Future<GeneralSettings> getGeneralSettings() async {
    final json = _prefs?.getString('generalSettings');
    if (json == null) return GeneralSettings();

    try {
      return GeneralSettings.fromJson(jsonDecode(json));
    } catch (e) {
      debugPrint('Failed to load general settings: $e');
      return GeneralSettings();
    }
  }

  Future<void> saveGeneralSettings(GeneralSettings settings) async {
    await _prefs?.setString('generalSettings', jsonEncode(settings.toJson()));
  }

  // ==================== Data Directory ====================

  String get dataDirectory => _dataDir ?? '';

  Future<String> getConfigPath() async {
    return '$_dataDir/config';
  }
}
