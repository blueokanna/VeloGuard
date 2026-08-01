import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:veloguard/src/services/config_converter.dart';

void main() {
  test('Clash rule providers are preserved for the Rust router', () {
    const yaml = '''
port: 7890
proxies: []
proxy-groups: []
rule-providers:
  proxy:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt
    path: ./ruleset/proxy.yaml
    interval: 86400
rules:
  - RULE-SET,proxy,PROXY
  - MATCH,DIRECT
''';

    final converted =
        jsonDecode(ConfigConverter.convertClashYamlToJson(yaml))
            as Map<String, dynamic>;
    final providers = converted['rule_providers'] as List<dynamic>;
    final rules = converted['rules'] as List<dynamic>;

    expect(providers, hasLength(1));
    expect(providers.single, {
      'name': 'proxy',
      'type': 'http',
      'behavior': 'domain',
      'url':
          'https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt',
      'path': './ruleset/proxy.yaml',
      'interval': 86400,
    });
    expect(rules.first, {
      'rule_type': 'rule_set',
      'payload': 'proxy',
      'outbound': 'PROXY',
      'process_name': null,
    });
  });

  test('Clash rule modifiers do not corrupt payload or outbound', () {
    const yaml = '''
proxies: []
proxy-groups: []
rules:
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - MATCH,DIRECT
''';

    final converted =
        jsonDecode(ConfigConverter.convertClashYamlToJson(yaml))
            as Map<String, dynamic>;
    final rules = converted['rules'] as List<dynamic>;

    expect(rules.first, {
      'rule_type': 'ip_cidr',
      'payload': '10.0.0.0/8',
      'outbound': 'DIRECT',
      'process_name': null,
    });
  });
}
