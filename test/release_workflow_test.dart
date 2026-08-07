import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:yaml/yaml.dart';

void main() {
  test('stable release supports manual and tag triggers', () {
    final source = File('.github/workflows/release.yml').readAsStringSync();
    final workflow = loadYaml(source) as YamlMap;
    final triggers = workflow['on'] as YamlMap;

    expect(triggers.containsKey('push'), isTrue);
    expect(triggers.containsKey('workflow_dispatch'), isTrue);
    expect(source, contains(r'group: stable-release-${{ github.repository }}'));
    expect(source, isNot(contains('skip=true')));
    expect(source, contains("Release '\$tag' already exists"));
    expect(source, contains('flutter pub get --enforce-lockfile'));
    expect(
      source,
      contains('cargo test --manifest-path rust/Cargo.toml --workspace'),
    );
    expect(source, contains('run: ./gradlew lintRelease'));
    expect(source, contains(r'tag_name: ${{ steps.release.outputs.tag }}'));
    expect(source, contains('prerelease: false'));
    expect(source.toLowerCase(), isNot(contains('nightly')));
  });

  test('continuous integration covers Flutter, Android, and Rust', () {
    final source = File('.github/workflows/ci.yml').readAsStringSync();
    final workflow = loadYaml(source) as YamlMap;
    final triggers = workflow['on'] as YamlMap;

    expect(triggers.containsKey('push'), isTrue);
    expect(triggers.containsKey('pull_request'), isTrue);
    expect(triggers.containsKey('workflow_dispatch'), isTrue);
    expect(source, contains('flutter pub get --enforce-lockfile'));
    expect(source, contains('dart format --output=none --set-exit-if-changed'));
    expect(source, contains('flutter analyze'));
    expect(source, contains('flutter test'));
    expect(source, contains('flutter build apk --debug'));
    expect(source, contains('run: ./gradlew lintRelease'));
    expect(source, contains('cargo fmt --all -- --check'));
    expect(source, contains('--all-targets --all-features --locked'));
    expect(source, contains('-D warnings'));
  });
}
