import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

class UpdateAsset {
  const UpdateAsset({
    required this.name,
    required this.url,
    required this.sha256,
  });

  final String name;
  final Uri url;
  final String sha256;
}

class AvailableUpdate {
  const AvailableUpdate({
    required this.tag,
    required this.version,
    required this.publishedAt,
    required this.releasePage,
    required this.asset,
  });

  final String tag;
  final String version;
  final DateTime publishedAt;
  final Uri releasePage;
  final UpdateAsset asset;
}

class UpdateService {
  UpdateService({http.Client? client, Dio? dio})
    : _client = client ?? http.Client(),
      _dio = dio ?? Dio();

  static const _repository = 'blueokanna/VeloGuard';
  static const _latestReleaseApi =
      'https://api.github.com/repos/$_repository/releases/latest';
  static const MethodChannel _installer = MethodChannel('com.veloguard/proxy');

  final http.Client _client;
  final Dio _dio;

  Future<AvailableUpdate?> checkForUpdate() async {
    final package = await PackageInfo.fromPlatform();
    final currentVersion = _SemanticVersion.parse(package.version);
    final releaseResponse = await _client
        .get(
          Uri.parse(_latestReleaseApi),
          headers: const {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'VeloGuard-Updater',
          },
        )
        .timeout(const Duration(seconds: 15));

    if (releaseResponse.statusCode != 200) {
      throw HttpException(
        'GitHub release request failed (${releaseResponse.statusCode})',
      );
    }

    final release = jsonDecode(releaseResponse.body) as Map<String, dynamic>;
    if (release['draft'] == true || release['prerelease'] == true) return null;

    final tag = release['tag_name'] as String?;
    if (tag == null || !RegExp(r'^v\d+\.\d+\.\d+$').hasMatch(tag)) {
      return null;
    }
    final version = _SemanticVersion.parse(tag.substring(1));
    if (version.compareTo(currentVersion) <= 0) return null;

    final releaseDate = DateTime.parse(
      release['published_at'] as String,
    ).toUtc();
    final releaseAssets = (release['assets'] as List<dynamic>? ?? const [])
        .cast<Map<String, dynamic>>();
    final manifestReleaseAsset = releaseAssets
        .cast<Map<String, dynamic>?>()
        .firstWhere(
          (asset) => asset?['name'] == 'update-manifest.json',
          orElse: () => null,
        );
    if (manifestReleaseAsset == null) {
      throw const FormatException('Release has no update-manifest.json');
    }

    final manifestUri = Uri.parse(
      manifestReleaseAsset['browser_download_url'] as String,
    );
    final manifestResponse = await _client
        .get(manifestUri, headers: const {'User-Agent': 'VeloGuard-Updater'})
        .timeout(const Duration(seconds: 15));
    if (manifestResponse.statusCode != 200) {
      throw HttpException(
        'Update manifest request failed (${manifestResponse.statusCode})',
      );
    }

    final manifest = jsonDecode(manifestResponse.body) as Map<String, dynamic>;
    if (manifest['schema'] != 1 || manifest['tag'] != tag) {
      throw const FormatException('Update manifest tag or schema mismatch');
    }
    if (manifest['version'] != version.toString()) {
      throw const FormatException('Update manifest version mismatch');
    }

    final manifestDate = DateTime.parse(
      manifest['published_at'] as String,
    ).toUtc();
    if (manifestDate.difference(releaseDate).abs() >
        const Duration(minutes: 10)) {
      throw const FormatException('Update publication date mismatch');
    }

    final platform = Platform.isAndroid
        ? 'android'
        : Platform.isWindows
        ? 'windows'
        : Platform.isMacOS
        ? 'macos'
        : Platform.isLinux
        ? 'linux'
        : 'unsupported';
    final assets = (manifest['assets'] as List<dynamic>? ?? const [])
        .cast<Map<String, dynamic>>();
    final assetJson = assets.cast<Map<String, dynamic>?>().firstWhere(
      (asset) => asset?['platform'] == platform,
      orElse: () => null,
    );
    if (assetJson == null) return null;

    final name = assetJson['name'] as String;
    final url = Uri.parse(assetJson['url'] as String);
    final checksum = (assetJson['sha256'] as String).toLowerCase();
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(checksum)) {
      throw const FormatException('Invalid update SHA256');
    }

    final matchingReleaseAsset = releaseAssets
        .cast<Map<String, dynamic>?>()
        .firstWhere(
          (asset) =>
              asset?['name'] == name &&
              asset?['browser_download_url'] == url.toString(),
          orElse: () => null,
        );
    if (matchingReleaseAsset == null ||
        url.scheme != 'https' ||
        url.host != 'github.com' ||
        !url.path.startsWith('/$_repository/releases/download/$tag/')) {
      throw const FormatException('Update asset is not part of this release');
    }

    await _rejectRollback(tag, manifestDate, checksum);
    return AvailableUpdate(
      tag: tag,
      version: version.toString(),
      publishedAt: manifestDate,
      releasePage: Uri.parse(release['html_url'] as String),
      asset: UpdateAsset(name: name, url: url, sha256: checksum),
    );
  }

  Future<File> download(
    AvailableUpdate update, {
    void Function(double progress)? onProgress,
  }) async {
    final cache = await getTemporaryDirectory();
    final destination = File(
      '${cache.path}${Platform.pathSeparator}${update.asset.name}',
    );
    final partial = File('${destination.path}.part');
    if (await partial.exists()) await partial.delete();

    await _dio.download(
      update.asset.url.toString(),
      partial.path,
      deleteOnError: true,
      options: Options(
        followRedirects: true,
        receiveTimeout: const Duration(minutes: 5),
        headers: const {'User-Agent': 'VeloGuard-Updater'},
      ),
      onReceiveProgress: (received, total) {
        if (total > 0) onProgress?.call(received / total);
      },
    );

    final digest = await sha256.bind(partial.openRead()).first;
    if (digest.toString().toLowerCase() != update.asset.sha256) {
      await partial.delete();
      throw const FormatException('Downloaded update SHA256 mismatch');
    }
    if (await destination.exists()) await destination.delete();
    return partial.rename(destination.path);
  }

  Future<bool> install(File file, AvailableUpdate update) async {
    if (!Platform.isAndroid) {
      return launchUrl(
        update.releasePage,
        mode: LaunchMode.externalApplication,
      );
    }
    final result = await _installer.invokeMethod<dynamic>('installApk', {
      'path': file.path,
    });
    if (result is Map && result['requiresPermission'] == true) {
      throw StateError(
        'Allow installs from VeloGuard, then tap Check for updates again',
      );
    }
    return result == true || (result is Map && result['launched'] == true);
  }

  Future<void> _rejectRollback(
    String tag,
    DateTime publishedAt,
    String checksum,
  ) async {
    final prefs = await SharedPreferences.getInstance();
    final acceptedDate = DateTime.tryParse(
      prefs.getString('update.acceptedPublishedAt') ?? '',
    );
    final acceptedTag = prefs.getString('update.acceptedTag');
    final acceptedChecksum = prefs.getString('update.acceptedSha256');
    if (acceptedTag == tag &&
        acceptedChecksum != null &&
        acceptedChecksum != checksum) {
      throw const FormatException('Published update checksum changed');
    }
    if (acceptedDate != null &&
        publishedAt.isBefore(acceptedDate) &&
        acceptedTag != tag) {
      throw const FormatException('Older release metadata was rejected');
    }
    await prefs.setString('update.acceptedTag', tag);
    await prefs.setString(
      'update.acceptedPublishedAt',
      publishedAt.toIso8601String(),
    );
    await prefs.setString('update.acceptedSha256', checksum);
  }
}

class _SemanticVersion implements Comparable<_SemanticVersion> {
  const _SemanticVersion(this.major, this.minor, this.patch);

  final int major;
  final int minor;
  final int patch;

  factory _SemanticVersion.parse(String value) {
    final match = RegExp(r'^(\d+)\.(\d+)\.(\d+)$').firstMatch(value);
    if (match == null) {
      throw FormatException('Invalid semantic version: $value');
    }
    return _SemanticVersion(
      int.parse(match.group(1)!),
      int.parse(match.group(2)!),
      int.parse(match.group(3)!),
    );
  }

  @override
  int compareTo(_SemanticVersion other) {
    final majorResult = major.compareTo(other.major);
    if (majorResult != 0) return majorResult;
    final minorResult = minor.compareTo(other.minor);
    if (minorResult != 0) return minorResult;
    return patch.compareTo(other.patch);
  }

  @override
  String toString() => '$major.$minor.$patch';
}
