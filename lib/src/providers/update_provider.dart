import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:veloguard/src/services/update_service.dart';

enum UpdateState {
  idle,
  checking,
  available,
  downloading,
  ready,
  installing,
  error,
}

class UpdateProvider extends ChangeNotifier {
  UpdateProvider({UpdateService? service})
    : _service = service ?? UpdateService() {
    Future<void>.microtask(() => check(silent: true));
  }

  final UpdateService _service;
  UpdateState _state = UpdateState.idle;
  AvailableUpdate? _availableUpdate;
  File? _downloadedFile;
  Object? _lastError;
  double _downloadProgress = 0;

  UpdateState get state => _state;
  AvailableUpdate? get availableUpdate => _availableUpdate;
  Object? get lastError => _lastError;
  double get downloadProgress => _downloadProgress;

  Future<void> check({bool silent = false}) async {
    if (_state == UpdateState.checking || _state == UpdateState.downloading) {
      return;
    }
    _state = UpdateState.checking;
    _lastError = null;
    notifyListeners();
    try {
      _availableUpdate = await _service.checkForUpdate();
      _state = _availableUpdate == null
          ? UpdateState.idle
          : UpdateState.available;
    } catch (error) {
      _lastError = error;
      _state = silent ? UpdateState.idle : UpdateState.error;
      debugPrint('Update check failed: $error');
    }
    notifyListeners();
  }

  Future<bool> downloadAndInstall() async {
    final update = _availableUpdate;
    if (update == null) return false;
    try {
      _state = UpdateState.downloading;
      _downloadProgress = 0;
      _lastError = null;
      notifyListeners();
      if (_downloadedFile == null || !await _downloadedFile!.exists()) {
        _downloadedFile = await _service.download(
          update,
          onProgress: (progress) {
            _downloadProgress = progress.clamp(0, 1);
            notifyListeners();
          },
        );
      }
      _state = UpdateState.installing;
      notifyListeners();
      final installed = await _service.install(_downloadedFile!, update);
      _state = installed ? UpdateState.ready : UpdateState.error;
      if (!installed) {
        _lastError = StateError('Update installer was not launched');
      }
      notifyListeners();
      return installed;
    } catch (error) {
      _lastError = error;
      _state = UpdateState.error;
      notifyListeners();
      return false;
    }
  }
}
