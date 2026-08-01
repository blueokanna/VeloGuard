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
  });
}
