import 'dart:convert';
import 'package:yaml/yaml.dart';
import 'package:veloguard/src/services/storage_service.dart';

/// Parsed proxy information for UI display
class ParsedProxy {
  final String name;
  final String type;
  final String? server;
  final int? port;
  final Map<String, dynamic> options;

  ParsedProxy({
    required this.name,
    required this.type,
    this.server,
    this.port,
    this.options = const {},
  });

  String get displayType {
    switch (type.toLowerCase()) {
      case 'ss':
      case 'shadowsocks':
        return 'Shadowsocks';
      case 'vmess':
        return 'Vmess';
      case 'vless':
        return 'Vless';
      case 'trojan':
        return 'Trojan';
      case 'hysteria':
        return 'Hysteria';
      case 'hysteria2':
        return 'Hysteria2';
      case 'tuic':
        return 'TUIC';
      case 'wireguard':
        return 'WireGuard';
      case 'http':
        return 'HTTP';
      case 'socks5':
      case 'socks':
        return 'SOCKS5';
      default:
        return type;
    }
  }
}

/// Parsed proxy group for UI display
class ParsedProxyGroup {
  final String name;
  final String type;
  final List<String> proxies;
  final String? url;
  final int? interval;
  final String? icon;

  ParsedProxyGroup({
    required this.name,
    required this.type,
    required this.proxies,
    this.url,
    this.interval,
    this.icon,
  });

  String get displayType {
    switch (type.toLowerCase()) {
      case 'select':
        return '手动选择';
      case 'url-test':
        return '自动选择';
      case 'fallback':
        return '故障转移';
      case 'load-balance':
        return '负载均衡';
      case 'relay':
        return '链式代理';
      default:
        return type;
    }
  }
}

/// Parsed Clash config for UI display
class ParsedClashConfig {
  final List<ParsedProxy> proxies;
  final List<ParsedProxyGroup> proxyGroups;
  final Map<String, dynamic> general;
  final Map<String, dynamic> dns;
  final List<String> rules;

  ParsedClashConfig({
    required this.proxies,
    required this.proxyGroups,
    required this.general,
    required this.dns,
    required this.rules,
  });
}

/// Converts Clash YAML configuration to VeloGuard JSON format
class ConfigConverter {
  /// Parse Clash YAML config for UI display
  static ParsedClashConfig parseClashConfig(String yamlContent) {
    try {
      final yamlMap = loadYaml(yamlContent);
      if (yamlMap == null) {
        throw Exception('Empty YAML content');
      }

      final config = _convertToMap(yamlMap);

      // Parse proxies
      final proxies = <ParsedProxy>[];
      final proxiesList = config['proxies'] as List? ?? [];
      for (final proxy in proxiesList) {
        if (proxy is Map) {
          final proxyMap = _convertToMap(proxy) as Map<String, dynamic>;
          final options = Map<String, dynamic>.from(proxyMap);
          options.remove('name');
          options.remove('type');
          options.remove('server');
          options.remove('port');

          proxies.add(
            ParsedProxy(
              name: proxyMap['name']?.toString() ?? 'Unknown',
              type: proxyMap['type']?.toString() ?? 'unknown',
              server: proxyMap['server']?.toString(),
              port: proxyMap['port'] is int
                  ? proxyMap['port']
                  : int.tryParse(proxyMap['port']?.toString() ?? ''),
              options: options,
            ),
          );
        }
      }

      // Parse proxy groups
      final proxyGroups = <ParsedProxyGroup>[];
      final groupsList = config['proxy-groups'] as List? ?? [];
      for (final group in groupsList) {
        if (group is Map) {
          final groupMap = _convertToMap(group) as Map<String, dynamic>;
          proxyGroups.add(
            ParsedProxyGroup(
              name: groupMap['name']?.toString() ?? 'Unknown',
              type: groupMap['type']?.toString() ?? 'select',
              proxies:
                  (groupMap['proxies'] as List?)
                      ?.map((e) => e.toString())
                      .toList() ??
                  [],
              url: groupMap['url']?.toString(),
              interval: groupMap['interval'] is int
                  ? groupMap['interval']
                  : null,
              icon: groupMap['icon']?.toString(),
            ),
          );
        }
      }

      // Parse rules
      final rules = <String>[];
      final rulesList = config['rules'] as List? ?? [];
      for (final rule in rulesList) {
        if (rule is String) {
          rules.add(rule);
        }
      }

      return ParsedClashConfig(
        proxies: proxies,
        proxyGroups: proxyGroups,
        general: {
          'port': config['port'],
          'socks-port': config['socks-port'],
          'mixed-port': config['mixed-port'],
          'allow-lan': config['allow-lan'],
          'mode': config['mode'],
          'log-level': config['log-level'],
        },
        dns: config['dns'] != null
            ? Map<String, dynamic>.from(_convertToMap(config['dns']) as Map)
            : <String, dynamic>{},
        rules: rules,
      );
    } catch (e) {
      throw Exception('Failed to parse config: $e');
    }
  }

  /// Convert Clash YAML config to VeloGuard JSON config
  /// If generalSettings is provided, it will override the port settings from YAML
  static String convertClashYamlToJson(
    String yamlContent, {
    GeneralSettings? generalSettings,
  }) {
    try {
      final yamlMap = loadYaml(yamlContent);
      if (yamlMap == null) {
        throw Exception('Empty YAML content');
      }

      final config = _convertToMap(yamlMap);
      final veloguardConfig = _convertClashToVeloGuard(
        config,
        generalSettings: generalSettings,
      );

      return jsonEncode(veloguardConfig);
    } catch (e) {
      throw Exception('Failed to convert config: $e');
    }
  }

  /// Convert YamlMap to regular Map recursively
  static dynamic _convertToMap(dynamic value) {
    if (value is YamlMap) {
      return Map<String, dynamic>.fromEntries(
        value.entries.map(
          (e) => MapEntry(e.key.toString(), _convertToMap(e.value)),
        ),
      );
    } else if (value is YamlList) {
      return value.map((e) => _convertToMap(e)).toList();
    } else if (value is Map) {
      // Handle regular Map (e.g., empty map {})
      return Map<String, dynamic>.fromEntries(
        value.entries.map(
          (e) => MapEntry(e.key.toString(), _convertToMap(e.value)),
        ),
      );
    }
    return value;
  }

  /// Convert Clash config format to VeloGuard config format
  static Map<String, dynamic> _convertClashToVeloGuard(
    Map<String, dynamic> clash, {
    GeneralSettings? generalSettings,
  }) {
    return {
      'general': _extractGeneralConfig(clash, generalSettings: generalSettings),
      'dns': _extractDnsConfig(clash),
      'inbounds': _extractInbounds(clash, generalSettings: generalSettings),
      'outbounds': _extractOutbounds(clash),
      'rules': _extractRules(clash),
    };
  }

  static Map<String, dynamic> _extractGeneralConfig(
    Map<String, dynamic> clash, {
    GeneralSettings? generalSettings,
  }) {
    // Use generalSettings if provided, otherwise fall back to YAML values
    final httpPort = generalSettings?.httpPort ?? clash['port'] ?? 7890;
    final socksPort = generalSettings?.socksPort ?? clash['socks-port'];
    final mixedPort = generalSettings?.mixedPort ?? clash['mixed-port'];
    final allowLan = generalSettings?.allowLan ?? clash['allow-lan'] ?? false;
    final ipv6 = generalSettings?.ipv6 ?? clash['ipv6'] ?? false;
    final tcpConcurrent =
        generalSettings?.tcpConcurrent ?? clash['tcp-concurrent'] ?? false;
    var bindAddress =
        generalSettings?.bindAddress ?? clash['bind-address'] ?? '*';

    // Convert '*' or invalid addresses to proper IP format
    if (bindAddress == '*') {
      if (allowLan) {
        bindAddress = ipv6 ? '::' : '0.0.0.0';
      } else {
        bindAddress = ipv6 ? '::1' : '127.0.0.1';
      }
    }

    final mode = generalSettings?.mode ?? clash['mode'] ?? 'rule';
    final logLevel = generalSettings?.logLevel ?? clash['log-level'] ?? 'info';

    return {
      'port': httpPort,
      'socks_port': socksPort,
      'redir_port': clash['redir-port'],
      'tproxy_port': clash['tproxy-port'],
      'mixed_port': mixedPort,
      'authentication': clash['authentication'] != null
          ? (clash['authentication'] as List).map((auth) {
              final parts = auth.toString().split(':');
              return {
                'username': parts.isNotEmpty ? parts[0] : '',
                'password': parts.length > 1 ? parts[1] : '',
              };
            }).toList()
          : null,
      'allow_lan': allowLan,
      'bind_address': bindAddress,
      'mode': mode,
      'log_level': logLevel,
      'ipv6': ipv6,
      'tcp_concurrent': tcpConcurrent,
      'external_controller':
          generalSettings?.externalController ?? clash['external-controller'],
      'external_ui': generalSettings?.externalUi ?? clash['external-ui'],
      'secret': generalSettings?.secret ?? clash['secret'],
    };
  }

  static Map<String, dynamic> _extractDnsConfig(Map<String, dynamic> clash) {
    final dns = clash['dns'] as Map<String, dynamic>? ?? {};

    return {
      'enable': dns['enable'] ?? true,
      'listen': dns['listen'] ?? '0.0.0.0:53',
      'nameservers':
          (dns['nameserver'] as List?)?.map((e) => e.toString()).toList() ??
          ['8.8.8.8', '1.1.1.1'],
      'fallback':
          (dns['fallback'] as List?)?.map((e) => e.toString()).toList() ?? [],
      'enhanced_mode': dns['enhanced-mode'] ?? 'fake-ip',
    };
  }

  static List<Map<String, dynamic>> _extractInbounds(
    Map<String, dynamic> clash, {
    GeneralSettings? generalSettings,
  }) {
    final inbounds = <Map<String, dynamic>>[];

    // Use generalSettings if provided, otherwise fall back to YAML values
    final httpPort = generalSettings?.httpPort ?? clash['port'];
    final socksPort = generalSettings?.socksPort ?? clash['socks-port'];
    final mixedPort = generalSettings?.mixedPort ?? clash['mixed-port'];
    final allowLan = generalSettings?.allowLan ?? clash['allow-lan'] ?? false;
    final ipv6 = generalSettings?.ipv6 ?? clash['ipv6'] ?? false;
    var bindAddress =
        generalSettings?.bindAddress ?? clash['bind-address'] ?? '127.0.0.1';

    // Convert '*' or invalid addresses to proper IP format
    if (bindAddress == '*') {
      if (allowLan) {
        bindAddress = ipv6 ? '::' : '0.0.0.0';
      } else {
        bindAddress = ipv6 ? '::1' : '127.0.0.1';
      }
    }

    // HTTP inbound
    if (httpPort != null) {
      inbounds.add({
        'inbound_type': 'http',
        'tag': 'http-in',
        'listen': bindAddress,
        'port': httpPort,
        'options': '{}',
      });
    }

    // SOCKS inbound
    if (socksPort != null) {
      inbounds.add({
        'inbound_type': 'socks5',
        'tag': 'socks-in',
        'listen': bindAddress,
        'port': socksPort,
        'options': '{}',
      });
    }

    // Mixed inbound
    if (mixedPort != null) {
      inbounds.add({
        'inbound_type': 'mixed',
        'tag': 'mixed-in',
        'listen': bindAddress,
        'port': mixedPort,
        'options': '{}',
      });
    }

    // If no inbounds defined, add default mixed port
    if (inbounds.isEmpty) {
      inbounds.add({
        'inbound_type': 'mixed',
        'tag': 'mixed-in',
        'listen': '127.0.0.1',
        'port': 7897,
        'options': '{}',
      });
    }

    return inbounds;
  }

  static List<Map<String, dynamic>> _extractOutbounds(
    Map<String, dynamic> clash,
  ) {
    final outbounds = <Map<String, dynamic>>[];
    final proxies = clash['proxies'] as List? ?? [];
    final proxyGroups = clash['proxy-groups'] as List? ?? [];

    // Add DIRECT and REJECT first
    outbounds.add({
      'outbound_type': 'direct',
      'tag': 'DIRECT',
      'server': null,
      'port': null,
      'options': '{}',
    });

    outbounds.add({
      'outbound_type': 'reject',
      'tag': 'REJECT',
      'server': null,
      'port': null,
      'options': '{}',
    });

    // Convert proxies
    for (final proxy in proxies) {
      if (proxy is Map) {
        final proxyMap = _convertToMap(proxy) as Map<String, dynamic>;
        final proxyType =
            proxyMap['type']?.toString().toLowerCase() ?? 'unknown';
        final name = proxyMap['name']?.toString() ?? 'proxy';

        // Remove common fields for options
        final options = Map<String, dynamic>.from(proxyMap);
        options.remove('name');
        options.remove('type');
        options.remove('server');
        options.remove('port');

        outbounds.add({
          'outbound_type': _mapProxyType(proxyType),
          'tag': name,
          'server': proxyMap['server']?.toString(),
          'port': proxyMap['port'] is int
              ? proxyMap['port']
              : int.tryParse(proxyMap['port']?.toString() ?? ''),
          'options': jsonEncode(options),
        });
      }
    }

    // Convert proxy groups to selector outbounds
    for (final group in proxyGroups) {
      if (group is Map) {
        final groupMap = _convertToMap(group) as Map<String, dynamic>;
        final groupType =
            groupMap['type']?.toString().toLowerCase() ?? 'select';
        final name = groupMap['name']?.toString() ?? 'group';
        final groupProxies =
            (groupMap['proxies'] as List?)?.map((e) => e.toString()).toList() ??
            [];

        // Map proxy group type to outbound type
        String outboundType;
        switch (groupType) {
          case 'select':
            outboundType = 'selector';
            break;
          case 'url-test':
            outboundType = 'urltest';
            break;
          case 'fallback':
            outboundType = 'fallback';
            break;
          case 'load-balance':
            outboundType = 'loadbalance';
            break;
          case 'relay':
            outboundType = 'relay';
            break;
          default:
            outboundType = 'selector';
        }

        // Build options map for group
        final optionsMap = <String, dynamic>{'outbounds': groupProxies};
        if (groupMap['url'] != null) {
          optionsMap['url'] = groupMap['url'];
        }
        if (groupMap['interval'] != null) {
          optionsMap['interval'] = groupMap['interval'];
        }

        outbounds.add({
          'outbound_type': outboundType,
          'tag': name,
          'server': null,
          'port': null,
          'options': jsonEncode(optionsMap),
        });
      }
    }

    return outbounds;
  }

  static String _mapProxyType(String clashType) {
    switch (clashType) {
      case 'ss':
      case 'shadowsocks':
        return 'shadowsocks';
      case 'ssr':
      case 'shadowsocksr':
        return 'shadowsocksr';
      case 'vmess':
        return 'vmess';
      case 'vless':
        return 'vless';
      case 'trojan':
        return 'trojan';
      case 'http':
        return 'http';
      case 'socks5':
      case 'socks':
        return 'socks5';
      case 'hysteria':
        return 'hysteria';
      case 'hysteria2':
        return 'hysteria2';
      case 'wireguard':
        return 'wireguard';
      case 'tuic':
        return 'tuic';
      case 'quic':
      case 'shadowquic':
        return 'quic';
      default:
        return clashType;
    }
  }

  static List<Map<String, dynamic>> _extractRules(Map<String, dynamic> clash) {
    final rules = <Map<String, dynamic>>[];
    final clashRules = clash['rules'] as List? ?? [];

    for (final rule in clashRules) {
      if (rule is String) {
        final parts = rule.split(',');
        if (parts.length >= 2) {
          final ruleType = parts[0].trim();
          final payload = parts.length >= 3 ? parts[1].trim() : '';
          final outbound = parts.length >= 3
              ? parts[2].trim()
              : parts[1].trim();

          rules.add({
            'rule_type': _mapRuleType(ruleType),
            'payload': payload,
            'outbound': outbound,
            'process_name': null,
          });
        }
      }
    }

    // Add final MATCH rule if not present
    if (rules.isEmpty || rules.last['rule_type'] != 'match') {
      rules.add({
        'rule_type': 'match',
        'payload': '',
        'outbound': 'DIRECT',
        'process_name': null,
      });
    }

    return rules;
  }

  static String _mapRuleType(String clashRuleType) {
    switch (clashRuleType.toUpperCase()) {
      case 'DOMAIN':
        return 'domain';
      case 'DOMAIN-SUFFIX':
        return 'domain_suffix';
      case 'DOMAIN-KEYWORD':
        return 'domain_keyword';
      case 'GEOIP':
        return 'geoip';
      case 'IP-CIDR':
      case 'IP-CIDR6':
        return 'ip_cidr';
      case 'PROCESS-NAME':
        return 'process_name';
      case 'MATCH':
      case 'FINAL':
        return 'match';
      case 'RULE-SET':
        return 'rule_set';
      case 'DST-PORT':
        return 'dst_port';
      case 'SRC-PORT':
        return 'src_port';
      default:
        return clashRuleType.toLowerCase().replaceAll('-', '_');
    }
  }
}
