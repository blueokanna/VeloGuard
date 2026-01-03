import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:veloguard/src/services/storage_service.dart';
import 'package:veloguard/src/services/config_converter.dart';
import 'package:veloguard/src/rust/api.dart';

class ProfilesProvider extends ChangeNotifier {
  List<ProfileConfig> _profiles = [];
  String? _activeProfileId;
  bool _isLoading = false;
  String? _error;

  List<ProfileConfig> get profiles => _profiles;
  String? get activeProfileId => _activeProfileId;
  bool get isLoading => _isLoading;
  String? get error => _error;

  ProfileConfig? get activeProfile {
    if (_activeProfileId == null) return null;
    try {
      return _profiles.firstWhere((p) => p.id == _activeProfileId);
    } catch (e) {
      return null;
    }
  }

  ProfilesProvider() {
    _loadProfiles();
  }

  Future<void> _loadProfiles() async {
    _isLoading = true;
    notifyListeners();

    try {
      _profiles = await StorageService.instance.getProfiles();
      _activeProfileId = await StorageService.instance.getActiveProfileId();
    } catch (e) {
      debugPrint('Failed to load profiles: $e');
      _error = e.toString();
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> refresh() async {
    await _loadProfiles();
  }

  Future<void> loadProfiles() async {
    await _loadProfiles();
  }

  Future<bool> addProfileFromUrl(String name, String url) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      // Fetch config from URL
      final response = await http.get(Uri.parse(url));
      if (response.statusCode != 200) {
        throw Exception('Failed to fetch config: ${response.statusCode}');
      }

      final configContent = response.body;
      final id = DateTime.now().millisecondsSinceEpoch.toString();

      // Parse subscription info from headers
      DateTime? expiresAt;
      int? usedTraffic;
      int? totalTraffic;

      final userInfoHeader = response.headers['subscription-userinfo'];
      if (userInfoHeader != null) {
        final parts = userInfoHeader.split(';').map((s) => s.trim());
        int? uploadBytes;
        int? downloadBytes;
        for (final part in parts) {
          if (part.startsWith('upload=')) {
            uploadBytes = int.tryParse(part.substring(7));
          } else if (part.startsWith('download=')) {
            downloadBytes = int.tryParse(part.substring(9));
          } else if (part.startsWith('total=')) {
            totalTraffic = int.tryParse(part.substring(6));
          } else if (part.startsWith('expire=')) {
            final expireTimestamp = int.tryParse(part.substring(7));
            if (expireTimestamp != null) {
              expiresAt = DateTime.fromMillisecondsSinceEpoch(
                expireTimestamp * 1000,
              );
            }
          }
        }
        // Used traffic = upload + download
        if (uploadBytes != null || downloadBytes != null) {
          usedTraffic = (uploadBytes ?? 0) + (downloadBytes ?? 0);
        }
      }

      final profile = ProfileConfig(
        id: id,
        name: name,
        type: 'url',
        source: url,
        configContent: configContent,
        lastUpdated: DateTime.now(),
        expiresAt: expiresAt,
        usedTraffic: usedTraffic,
        totalTraffic: totalTraffic,
      );

      // Save config file
      await StorageService.instance.saveProfileConfig(id, configContent);

      // Add to profiles list
      await StorageService.instance.addProfile(profile);
      _profiles.add(profile);

      notifyListeners();
      return true;
    } catch (e) {
      debugPrint('Failed to add profile: $e');
      _error = e.toString();
      notifyListeners();
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<bool> addProfileFromFile(
    String name,
    String filePath,
    String content,
  ) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final id = DateTime.now().millisecondsSinceEpoch.toString();

      final profile = ProfileConfig(
        id: id,
        name: name,
        type: 'file',
        source: filePath,
        configContent: content,
        lastUpdated: DateTime.now(),
      );

      // Save config file
      await StorageService.instance.saveProfileConfig(id, content);

      // Add to profiles list
      await StorageService.instance.addProfile(profile);
      _profiles.add(profile);

      notifyListeners();
      return true;
    } catch (e) {
      debugPrint('Failed to add profile from file: $e');
      _error = e.toString();
      notifyListeners();
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<bool> updateProfile(String id) async {
    final profile = _profiles.firstWhere((p) => p.id == id);
    if (profile.type != 'url') {
      _error = 'Only URL profiles can be updated';
      notifyListeners();
      return false;
    }

    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final response = await http.get(Uri.parse(profile.source));
      if (response.statusCode != 200) {
        throw Exception('Failed to fetch config: ${response.statusCode}');
      }

      final configContent = response.body;

      // Parse subscription info
      DateTime? expiresAt = profile.expiresAt;
      int? usedTraffic = profile.usedTraffic;
      int? totalTraffic = profile.totalTraffic;

      final userInfoHeader = response.headers['subscription-userinfo'];
      if (userInfoHeader != null) {
        final parts = userInfoHeader.split(';').map((s) => s.trim());
        int? uploadBytes;
        int? downloadBytes;
        for (final part in parts) {
          if (part.startsWith('upload=')) {
            uploadBytes = int.tryParse(part.substring(7));
          } else if (part.startsWith('download=')) {
            downloadBytes = int.tryParse(part.substring(9));
          } else if (part.startsWith('total=')) {
            totalTraffic = int.tryParse(part.substring(6));
          } else if (part.startsWith('expire=')) {
            final expireTimestamp = int.tryParse(part.substring(7));
            if (expireTimestamp != null) {
              expiresAt = DateTime.fromMillisecondsSinceEpoch(
                expireTimestamp * 1000,
              );
            }
          }
        }
        // Used traffic = upload + download
        if (uploadBytes != null || downloadBytes != null) {
          usedTraffic = (uploadBytes ?? 0) + (downloadBytes ?? 0);
        }
      }

      final updatedProfile = profile.copyWith(
        configContent: configContent,
        lastUpdated: DateTime.now(),
        expiresAt: expiresAt,
        usedTraffic: usedTraffic,
        totalTraffic: totalTraffic,
      );

      // Save config file
      await StorageService.instance.saveProfileConfig(id, configContent);

      // Update profile
      await StorageService.instance.updateProfile(updatedProfile);

      final index = _profiles.indexWhere((p) => p.id == id);
      if (index != -1) {
        _profiles[index] = updatedProfile;
      }

      notifyListeners();
      return true;
    } catch (e) {
      debugPrint('Failed to update profile: $e');
      _error = e.toString();
      notifyListeners();
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> deleteProfile(String id) async {
    try {
      await StorageService.instance.deleteProfile(id);
      _profiles.removeWhere((p) => p.id == id);

      if (_activeProfileId == id) {
        _activeProfileId = null;
        await StorageService.instance.setActiveProfileId(null);
      }

      notifyListeners();
    } catch (e) {
      debugPrint('Failed to delete profile: $e');
      _error = e.toString();
      notifyListeners();
    }
  }

  /// Edit profile settings (name, URL, auto-update settings)
  Future<bool> editProfile({
    required String id,
    String? name,
    String? source,
    bool? autoUpdate,
    int? autoUpdateInterval,
  }) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final index = _profiles.indexWhere((p) => p.id == id);
      if (index == -1) {
        throw Exception('Profile not found');
      }

      final profile = _profiles[index];
      final updatedProfile = profile.copyWith(
        name: name,
        source: source,
        autoUpdate: autoUpdate,
        autoUpdateInterval: autoUpdateInterval,
      );

      await StorageService.instance.updateProfile(updatedProfile);
      _profiles[index] = updatedProfile;

      notifyListeners();
      return true;
    } catch (e) {
      debugPrint('Failed to edit profile: $e');
      _error = e.toString();
      notifyListeners();
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Get config file size for a profile
  Future<int?> getProfileConfigSize(String id) async {
    try {
      final content = await StorageService.instance.getProfileConfig(id);
      return content?.length;
    } catch (e) {
      return null;
    }
  }

  Future<bool> selectProfile(String id) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      // Get profile config
      final configContent = await StorageService.instance.getProfileConfig(id);
      if (configContent == null) {
        throw Exception('Profile config not found');
      }

      // Convert Clash YAML to VeloGuard JSON format
      final jsonConfig = ConfigConverter.convertClashYamlToJson(configContent);

      // Initialize VeloGuard with the converted config
      await initializeVeloguard(configJson: jsonConfig);

      _activeProfileId = id;
      await StorageService.instance.setActiveProfileId(id);

      notifyListeners();
      return true;
    } catch (e) {
      debugPrint('Failed to select profile: $e');
      _error = e.toString();
      notifyListeners();
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<String?> getActiveProfileConfig() async {
    if (_activeProfileId == null) return null;
    return StorageService.instance.getProfileConfig(_activeProfileId!);
  }
}
