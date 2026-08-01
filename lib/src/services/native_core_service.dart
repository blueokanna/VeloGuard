import 'dart:ffi' as ffi;
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:veloguard/src/rust/frb_generated.dart';

enum NativeCoreStatus { idle, initializing, ready, failed }

/// Owns native library diagnostics and flutter_rust_bridge initialization.
class NativeCoreService extends ChangeNotifier {
  NativeCoreService._();

  static final NativeCoreService instance = NativeCoreService._();

  static const MethodChannel _androidChannel = MethodChannel(
    'com.veloguard/proxy',
  );

  NativeCoreStatus _status = NativeCoreStatus.idle;
  String? _lastError;
  Future<bool>? _pendingInitialization;

  NativeCoreStatus get status => _status;
  bool get isReady => _status == NativeCoreStatus.ready;
  bool get isInitializing => _status == NativeCoreStatus.initializing;
  String? get lastError => _lastError;

  Future<bool> initialize({int maxAttempts = 3}) {
    if (maxAttempts < 1) {
      throw ArgumentError.value(maxAttempts, 'maxAttempts', 'must be positive');
    }

    final pending = _pendingInitialization;
    if (pending != null) {
      return pending;
    }

    final initialization = _initialize(maxAttempts);
    _pendingInitialization = initialization;
    return initialization.whenComplete(() => _pendingInitialization = null);
  }

  Future<bool> _initialize(int maxAttempts) async {
    _setStatus(NativeCoreStatus.initializing);
    _lastError = null;

    final androidDiagnostic = await _readAndroidDiagnostic();
    if (androidDiagnostic != null) {
      debugPrint(androidDiagnostic);
    }

    if (Platform.isAndroid) {
      try {
        ffi.DynamicLibrary.open('librust_lib_veloguard.so');
        debugPrint('Native core dynamic library is loadable.');
      } catch (error) {
        _lastError = 'Dynamic library load failed: $error';
        debugPrint(_lastError);
      }
    }

    for (var attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await RustLib.init();
        _lastError = null;
        _setStatus(NativeCoreStatus.ready);
        debugPrint('Native core initialized on attempt $attempt.');
        return true;
      } catch (error, stackTrace) {
        _lastError = error.toString();
        debugPrint(
          'Native core initialization failed '
          '(attempt $attempt/$maxAttempts): $error',
        );
        debugPrintStack(stackTrace: stackTrace);

        if (attempt < maxAttempts) {
          await Future<void>.delayed(const Duration(milliseconds: 500));
        }
      }
    }

    if (androidDiagnostic != null && _lastError != null) {
      _lastError = '$androidDiagnostic\n$_lastError';
    }
    _setStatus(NativeCoreStatus.failed);
    return false;
  }

  Future<String?> _readAndroidDiagnostic() async {
    if (!Platform.isAndroid) {
      return null;
    }

    try {
      final result = await _androidChannel.invokeMapMethod<String, dynamic>(
        'getNativeLibraryInfo',
      );
      if (result == null || result['loaded'] == true) {
        return null;
      }

      final error = result['error']?.toString();
      return error == null || error.isEmpty
          ? 'Android could not load the native core.'
          : 'Android native loader: $error';
    } on MissingPluginException {
      return 'Android native diagnostics channel is unavailable.';
    } catch (error) {
      return 'Android native diagnostics failed: $error';
    }
  }

  void _setStatus(NativeCoreStatus value) {
    _status = value;
    notifyListeners();
  }
}
