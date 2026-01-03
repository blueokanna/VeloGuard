import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:veloguard/src/rust/api.dart' as rust_api;
import 'package:veloguard/src/utils/platform_utils.dart';

enum ProxyMode { global, rule, direct }

class PlatformProxyService {
  static final PlatformProxyService instance = PlatformProxyService._();
  PlatformProxyService._() {
    _setupMethodChannel();
  }

  static const MethodChannel _channel = MethodChannel('com.veloguard/proxy');
  static const MethodChannel _ohosChannel = MethodChannel(
    'com.veloguard/ohos_proxy',
  );

  bool _systemProxyEnabled = false;
  bool _tunModeEnabled = false;
  ProxyMode _currentProxyMode = ProxyMode.rule;
  int _vpnFd = -1;

  bool get systemProxyEnabled => _systemProxyEnabled;
  bool get tunModeEnabled => _tunModeEnabled;
  ProxyMode get currentProxyMode => _currentProxyMode;
  int get vpnFd => _vpnFd;
  int get androidVpnFd => _vpnFd;
  Function(bool isRunning)? onVpnStatusChanged;

  void _setupMethodChannel() {
    debugPrint('PlatformProxyService: Setting up MethodChannel handlers');

    _channel.setMethodCallHandler((call) async {
      debugPrint('PlatformProxyService: Received ${call.method}');

      switch (call.method) {
        case 'vpnStatusChanged':
          if (call.arguments is Map) {
            final args = call.arguments as Map;
            final isRunning = args['isRunning'] as bool? ?? false;
            final fd = (args['fd'] as num?)?.toInt() ?? -1;
            _tunModeEnabled = isRunning;
            _vpnFd = fd;
            onVpnStatusChanged?.call(isRunning);
          }
          return null;
        default:
          return null;
      }
    });

    _ohosChannel.setMethodCallHandler((call) async {
      switch (call.method) {
        case 'vpnStatusChanged':
          if (call.arguments is Map) {
            final args = call.arguments as Map;
            _tunModeEnabled = args['isRunning'] as bool? ?? false;
            _vpnFd = (args['fd'] as num?)?.toInt() ?? -1;
            onVpnStatusChanged?.call(_tunModeEnabled);
          }
          return null;
        default:
          return null;
      }
    });

    debugPrint('PlatformProxyService: MethodChannel handlers set up');
  }

  Future<bool> enableSystemProxy({
    required String host,
    required int httpPort,
    required int socksPort,
  }) async {
    try {
      if (Platform.isWindows) {
        return await _enableWindowsSystemProxy(host, httpPort);
      }
      if (Platform.isAndroid || PlatformUtils.isOHOS) {
        return false;
      }
      if (Platform.isMacOS) {
        return await _enableMacOSSystemProxy(host, httpPort);
      }
      if (Platform.isLinux) {
        return await _enableLinuxSystemProxy(host, httpPort);
      }
      return false;
    } catch (e) {
      debugPrint('Failed to enable system proxy: $e');
      return false;
    }
  }

  Future<bool> disableSystemProxy() async {
    try {
      if (Platform.isWindows) {
        return await _disableWindowsSystemProxy();
      }
      if (Platform.isAndroid || PlatformUtils.isOHOS) {
        return true;
      }
      if (Platform.isMacOS) {
        return await _disableMacOSSystemProxy();
      }
      if (Platform.isLinux) {
        return await _disableLinuxSystemProxy();
      }
      return false;
    } catch (e) {
      debugPrint('Failed to disable system proxy: $e');
      return false;
    }
  }

  Future<bool> enableTunMode({ProxyMode mode = ProxyMode.rule}) async {
    try {
      if (Platform.isWindows) {
        return await _enableWindowsTun();
      }
      if (Platform.isAndroid) {
        return await _enableAndroidVpn(mode: mode);
      }
      if (PlatformUtils.isOHOS) {
        return await _enableOhosVpn(mode: mode);
      }
      if (Platform.isMacOS || Platform.isLinux) {
        _tunModeEnabled = true;
        return true;
      }
      return false;
    } catch (e) {
      debugPrint('Failed to enable TUN mode: $e');
      return false;
    }
  }

  Future<bool> disableTunMode() async {
    try {
      if (Platform.isWindows) {
        return await _disableWindowsTun();
      }
      if (Platform.isAndroid) {
        return await _disableAndroidVpn();
      }
      if (PlatformUtils.isOHOS) {
        return await _disableOhosVpn();
      }
      if (Platform.isMacOS || Platform.isLinux) {
        _tunModeEnabled = false;
        return true;
      }
      return false;
    } catch (e) {
      debugPrint('Failed to disable TUN mode: $e');
      return false;
    }
  }

  Future<bool> _enableWindowsSystemProxy(String host, int port) async {
    try {
      final result = await Process.run('powershell', [
        '-Command',
        '\$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"; '
            'Set-ItemProperty -Path \$regPath -Name ProxyEnable -Value 1; '
            'Set-ItemProperty -Path \$regPath -Name ProxyServer -Value "$host:$port"',
      ]);
      if (result.exitCode == 0) {
        _systemProxyEnabled = true;
        return true;
      }
      return false;
    } catch (e) {
      debugPrint('Windows proxy error: $e');
      return false;
    }
  }

  Future<bool> _disableWindowsSystemProxy() async {
    try {
      final result = await Process.run('powershell', [
        '-Command',
        '\$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"; '
            'Set-ItemProperty -Path \$regPath -Name ProxyEnable -Value 0',
      ]);
      if (result.exitCode == 0) {
        _systemProxyEnabled = false;
        return true;
      }
      return false;
    } catch (e) {
      debugPrint('Windows proxy disable error: $e');
      return false;
    }
  }

  Future<bool> _enableWindowsTun() async {
    try {
      await rust_api.ensureWintunDll();
      final status = await rust_api.enableTunMode();
      _tunModeEnabled = status.enabled;
      return _tunModeEnabled;
    } catch (e) {
      debugPrint('Windows TUN error: $e');
      return false;
    }
  }

  Future<bool> _disableWindowsTun() async {
    try {
      final status = await rust_api.disableTunMode();
      _tunModeEnabled = status.enabled;
      return !_tunModeEnabled;
    } catch (e) {
      debugPrint('Windows TUN disable error: $e');
      _tunModeEnabled = false;
      return true;
    }
  }

  Future<bool> _enableAndroidVpn({ProxyMode mode = ProxyMode.rule}) async {
    try {
      debugPrint('=== _enableAndroidVpn: Starting with mode=$mode ===');

      // Check if another VPN is active - we will attempt to take over
      final otherVpnActive = await isOtherVpnActive();
      if (otherVpnActive) {
        debugPrint(
          '_enableAndroidVpn: Another VPN is active - will attempt to take over',
        );
      }

      // If already running, stop first
      if (_tunModeEnabled || _vpnFd >= 0) {
        debugPrint('_enableAndroidVpn: VPN already enabled, stopping first...');
        await _disableAndroidVpn();
        await Future.delayed(const Duration(milliseconds: 1000));
      }

      // Reset state
      _tunModeEnabled = false;
      _vpnFd = -1;

      // Try to reset VPN state (for recovery after app reinstall)
      try {
        await _channel.invokeMethod('resetVpnState');
        debugPrint('_enableAndroidVpn: VPN state reset successfully');
      } catch (e) {
        debugPrint('_enableAndroidVpn: resetVpnState not available: $e');
      }

      debugPrint('_enableAndroidVpn: Calling startVpn via MethodChannel...');

      // Call Android side to start VPN, returns fd synchronously
      final dynamic result;
      try {
        result = await _channel.invokeMethod('startVpn', {'mode': mode.name});
      } on PlatformException catch (e) {
        debugPrint(
          '_enableAndroidVpn: PlatformException during startVpn: ${e.code} - ${e.message}',
        );
        return false;
      }

      debugPrint(
        '_enableAndroidVpn: startVpn result=$result (type: ${result.runtimeType})',
      );

      int fd = -1;
      String? errorMsg;

      if (result is Map) {
        final success = result['success'] as bool? ?? false;
        fd = (result['fd'] as num?)?.toInt() ?? -1;
        errorMsg = result['error'] as String?;

        if (!success || fd < 0) {
          debugPrint(
            '_enableAndroidVpn: Android VPN start failed - success=$success, fd=$fd, error=$errorMsg',
          );
          // Return false, let caller show appropriate error message
          return false;
        }

        _vpnFd = fd;
        debugPrint('=== _enableAndroidVpn: Got VPN fd=$fd from Android ===');
      } else if (result == true) {
        // Compatible with old return format, try to get fd
        debugPrint('_enableAndroidVpn: Legacy result format, fetching fd...');
        try {
          fd = await _channel.invokeMethod('getVpnFd') as int? ?? -1;
        } catch (e) {
          debugPrint('_enableAndroidVpn: Failed to get VPN fd: $e');
          return false;
        }

        if (fd < 0) {
          debugPrint(
            '_enableAndroidVpn: startVpn returned true but fd is invalid ($fd)',
          );
          return false;
        }
        _vpnFd = fd;
        debugPrint('=== _enableAndroidVpn: Got VPN fd=$fd (via getVpnFd) ===');
      } else if (result == false) {
        debugPrint('_enableAndroidVpn: startVpn returned false');
        return false;
      } else {
        debugPrint(
          '_enableAndroidVpn: startVpn returned unexpected result type: ${result.runtimeType}',
        );
        return false;
      }

      // Set VPN fd in Rust layer and start processing
      try {
        debugPrint(
          '_enableAndroidVpn: Setting VPN fd=$_vpnFd in Rust layer...',
        );
        rust_api.setAndroidVpnFd(fd: _vpnFd);

        debugPrint('_enableAndroidVpn: Setting proxy mode to ${mode.name}...');
        rust_api.setAndroidProxyMode(mode: mode.name);

        debugPrint(
          '_enableAndroidVpn: Starting Android VPN packet processing in Rust...',
        );
        final vpnStarted = await rust_api.startAndroidVpn();
        debugPrint(
          '_enableAndroidVpn: Rust startAndroidVpn returned: $vpnStarted',
        );

        if (!vpnStarted) {
          debugPrint(
            '_enableAndroidVpn: Rust VPN packet processing failed to start',
          );
          // Cleanup Android side VPN
          try {
            await _channel.invokeMethod('stopVpn');
          } catch (e) {
            debugPrint(
              '_enableAndroidVpn: Failed to stop Android VPN after Rust failure: $e',
            );
          }
          _vpnFd = -1;
          return false;
        }
      } catch (e, stackTrace) {
        debugPrint('_enableAndroidVpn: Failed to start Rust VPN: $e');
        debugPrint('Stack trace: $stackTrace');
        // Cleanup Android side VPN
        try {
          await _channel.invokeMethod('stopVpn');
        } catch (_) {}
        _vpnFd = -1;
        return false;
      }

      _tunModeEnabled = true;
      _currentProxyMode = mode;
      debugPrint(
        '=== _enableAndroidVpn: VPN enabled successfully, fd=$_vpnFd, mode=$mode ===',
      );
      return true;
    } on PlatformException catch (e) {
      debugPrint(
        '_enableAndroidVpn: PlatformException: ${e.code} - ${e.message}',
      );
      _tunModeEnabled = false;
      _vpnFd = -1;
      return false;
    } catch (e, stackTrace) {
      debugPrint('_enableAndroidVpn: Unexpected error: $e');
      debugPrint('Stack trace: $stackTrace');
      _tunModeEnabled = false;
      _vpnFd = -1;
      return false;
    }
  }

  Future<bool> _disableAndroidVpn() async {
    try {
      // First cleanup Rust layer
      try {
        await rust_api.stopAndroidVpn();
        rust_api.clearAndroidVpnFd();
      } catch (e) {
        debugPrint('Failed to cleanup Rust VPN state: $e');
      }

      await _channel.invokeMethod('stopVpn');

      _tunModeEnabled = false;
      _vpnFd = -1;

      await Future.delayed(const Duration(milliseconds: 500));
      return true;
    } on PlatformException catch (e) {
      debugPrint('Android VPN disable error: ${e.message}');
      _tunModeEnabled = false;
      _vpnFd = -1;
      return false;
    }
  }

  Future<bool> _enableOhosVpn({ProxyMode mode = ProxyMode.rule}) async {
    try {
      debugPrint('_enableOhosVpn: Starting with mode=$mode');

      if (_tunModeEnabled || _vpnFd >= 0) {
        await _disableOhosVpn();
        await Future.delayed(const Duration(milliseconds: 1000));
      }

      _tunModeEnabled = false;
      _vpnFd = -1;

      final result = await _ohosChannel.invokeMethod('startVpn', {
        'mode': mode.name,
      });

      if (result is Map) {
        final success = result['success'] as bool? ?? false;
        final fd = (result['fd'] as num?)?.toInt() ?? -1;

        if (!success || fd < 0) {
          return false;
        }
        _vpnFd = fd;
      } else if (result != true) {
        return false;
      }

      try {
        rust_api.setAndroidVpnFd(fd: _vpnFd);
        rust_api.setAndroidProxyMode(mode: mode.name);
        final vpnStarted = await rust_api.startAndroidVpn();
        if (!vpnStarted) {
          return false;
        }
      } catch (e) {
        debugPrint('_enableOhosVpn: Failed to start Rust VPN: $e');
        return false;
      }

      _tunModeEnabled = true;
      _currentProxyMode = mode;
      return true;
    } on PlatformException catch (e) {
      debugPrint('_enableOhosVpn: PlatformException: ${e.message}');
      _tunModeEnabled = false;
      _vpnFd = -1;
      return false;
    }
  }

  Future<bool> _disableOhosVpn() async {
    try {
      await _ohosChannel.invokeMethod('stopVpn');
      _tunModeEnabled = false;
      _vpnFd = -1;
      try {
        await rust_api.stopAndroidVpn();
        rust_api.clearAndroidVpnFd();
      } catch (e) {
        debugPrint('Failed to cleanup Rust VPN state on OHOS: $e');
      }
      return true;
    } on PlatformException catch (e) {
      debugPrint('OHOS VPN disable error: ${e.message}');
      return false;
    }
  }

  Future<bool> setOhosProxyMode(ProxyMode mode) async {
    if (!PlatformUtils.isOHOS) return false;
    try {
      final result = await _ohosChannel.invokeMethod('setProxyMode', {
        'mode': mode.name,
      });
      if (result == true) {
        _currentProxyMode = mode;
        rust_api.setAndroidProxyMode(mode: mode.name);
      }
      return result == true;
    } catch (e) {
      debugPrint('Failed to set OHOS proxy mode: $e');
      return false;
    }
  }

  Future<bool> setProxyMode(ProxyMode mode) async {
    if (Platform.isAndroid) {
      return await setAndroidProxyMode(mode);
    } else if (PlatformUtils.isOHOS) {
      return await setOhosProxyMode(mode);
    }
    return false;
  }

  Future<int> getVpnConnectionCount() async {
    if (Platform.isAndroid) {
      return await getAndroidVpnConnectionCount();
    } else if (PlatformUtils.isOHOS) {
      try {
        return await _ohosChannel.invokeMethod('getVpnConnectionCount')
                as int? ??
            0;
      } catch (e) {
        return 0;
      }
    }
    return 0;
  }

  Future<bool> setAndroidProxyMode(ProxyMode mode) async {
    if (!Platform.isAndroid) return false;
    try {
      final result = await _channel.invokeMethod('setProxyMode', {
        'mode': mode.name,
      });
      if (result == true) {
        _currentProxyMode = mode;
        rust_api.setAndroidProxyMode(mode: mode.name);
      }
      return result == true;
    } catch (e) {
      debugPrint('Failed to set proxy mode: $e');
      return false;
    }
  }

  Future<int> getAndroidVpnConnectionCount() async {
    if (!Platform.isAndroid) return 0;
    try {
      return await _channel.invokeMethod('getVpnConnectionCount') as int? ?? 0;
    } catch (e) {
      return 0;
    }
  }

  Future<bool> _enableMacOSSystemProxy(String host, int port) async {
    try {
      final servicesResult = await Process.run('networksetup', [
        '-listallnetworkservices',
      ]);
      final services = servicesResult.stdout
          .toString()
          .split('\n')
          .where((s) => s.isNotEmpty && !s.startsWith('*'))
          .toList();
      for (final service in services) {
        await Process.run('networksetup', [
          '-setwebproxy',
          service,
          host,
          port.toString(),
        ]);
        await Process.run('networksetup', [
          '-setsecurewebproxy',
          service,
          host,
          port.toString(),
        ]);
        await Process.run('networksetup', ['-setwebproxystate', service, 'on']);
        await Process.run('networksetup', [
          '-setsecurewebproxystate',
          service,
          'on',
        ]);
      }
      _systemProxyEnabled = true;
      return true;
    } catch (e) {
      debugPrint('macOS proxy error: $e');
      return false;
    }
  }

  Future<bool> _disableMacOSSystemProxy() async {
    try {
      final servicesResult = await Process.run('networksetup', [
        '-listallnetworkservices',
      ]);
      final services = servicesResult.stdout
          .toString()
          .split('\n')
          .where((s) => s.isNotEmpty && !s.startsWith('*'))
          .toList();
      for (final service in services) {
        await Process.run('networksetup', [
          '-setwebproxystate',
          service,
          'off',
        ]);
        await Process.run('networksetup', [
          '-setsecurewebproxystate',
          service,
          'off',
        ]);
      }
      _systemProxyEnabled = false;
      return true;
    } catch (e) {
      debugPrint('macOS proxy disable error: $e');
      return false;
    }
  }

  Future<bool> _enableLinuxSystemProxy(String host, int port) async {
    try {
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy',
        'mode',
        'manual',
      ]);
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy.http',
        'host',
        host,
      ]);
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy.http',
        'port',
        port.toString(),
      ]);
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy.https',
        'host',
        host,
      ]);
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy.https',
        'port',
        port.toString(),
      ]);
      _systemProxyEnabled = true;
      return true;
    } catch (e) {
      debugPrint('Linux proxy error: $e');
      return false;
    }
  }

  Future<bool> _disableLinuxSystemProxy() async {
    try {
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy',
        'mode',
        'none',
      ]);
      _systemProxyEnabled = false;
      return true;
    } catch (e) {
      debugPrint('Linux proxy disable error: $e');
      return false;
    }
  }

  Future<bool> checkSystemProxyStatus() async {
    try {
      if (Platform.isWindows) {
        final result = await Process.run('powershell', [
          '-Command',
          '(Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings").ProxyEnable',
        ]);
        _systemProxyEnabled = result.stdout.toString().trim() == '1';
        return _systemProxyEnabled;
      } else if (Platform.isAndroid) {
        _systemProxyEnabled = false;
        return false;
      }
      return _systemProxyEnabled;
    } catch (e) {
      return false;
    }
  }

  Future<bool> checkTunModeStatus() async {
    try {
      if (Platform.isAndroid) {
        final isRunning =
            await _channel.invokeMethod('isVpnRunning') as bool? ?? false;
        _tunModeEnabled = isRunning;
        if (isRunning) {
          _vpnFd = await _channel.invokeMethod('getVpnFd') as int? ?? -1;
        }
        return _tunModeEnabled;
      }
      if (PlatformUtils.isOHOS) {
        final result = await _ohosChannel.invokeMethod('isVpnRunning');
        _tunModeEnabled = result == true;
        return _tunModeEnabled;
      }
      final status = await rust_api.getTunStatus();
      _tunModeEnabled = status.enabled;
      return _tunModeEnabled;
    } catch (e) {
      debugPrint('Failed to check TUN status: $e');
      return false;
    }
  }

  /// Check if another VPN app is currently active (Android only)
  /// Returns true if another VPN is running and blocking our VPN
  Future<bool> isOtherVpnActive() async {
    if (!Platform.isAndroid) {
      return false;
    }
    try {
      final result = await _channel.invokeMethod('isOtherVpnActive');
      return result == true;
    } catch (e) {
      debugPrint('Failed to check if other VPN is active: $e');
      return false;
    }
  }

  Future<bool> enableUwpLoopback() async {
    if (!Platform.isWindows) return false;
    try {
      return await rust_api.enableUwpLoopback();
    } catch (e) {
      debugPrint('Failed to enable UWP loopback: $e');
      return false;
    }
  }

  Future<bool> openUwpLoopbackUtility() async {
    if (!Platform.isWindows) return false;
    try {
      return await rust_api.openUwpLoopbackUtility();
    } catch (e) {
      debugPrint('Failed to open UWP loopback utility: $e');
      return false;
    }
  }
}
