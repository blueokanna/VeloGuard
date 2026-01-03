import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:window_manager/window_manager.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';

class PlatformUtils {
  static bool? _isHarmonyOS;
  static bool get isHarmonyOS {
    if (_isHarmonyOS != null) return _isHarmonyOS!;

    if (kIsWeb) {
      _isHarmonyOS = false;
      return false;
    }

    try {
      final os = Platform.operatingSystem.toLowerCase();
      if (os == 'ohos' || os == 'harmonyos') {
        _isHarmonyOS = true;
        return true;
      }
    } catch (e) {
      // 忽略错误
    }

    _isHarmonyOS = false;
    return false;
  }

  /// 异步检测鸿蒙系统（更准确，可以检测基于 Android 的鸿蒙）
  static Future<bool> checkHarmonyOS() async {
    if (_isHarmonyOS != null) return _isHarmonyOS!;

    if (kIsWeb) {
      _isHarmonyOS = false;
      return false;
    }

    // 先检查 OHOS 平台
    try {
      final os = Platform.operatingSystem.toLowerCase();
      if (os == 'ohos' || os == 'harmonyos') {
        _isHarmonyOS = true;
        return true;
      }
    } catch (e) {
      // 忽略错误
    }

    // 对于 Android 平台，尝试检测是否为鸿蒙
    if (Platform.isAndroid) {
      try {
        const channel = MethodChannel('com.veloguard/proxy');
        final deviceInfo = await channel.invokeMethod('getDeviceInfo') as Map?;
        if (deviceInfo != null) {
          final brand = (deviceInfo['brand'] as String?)?.toUpperCase() ?? '';
          final manufacturer =
              (deviceInfo['manufacturer'] as String?)?.toUpperCase() ?? '';
          // 华为设备可能运行鸿蒙
          if (brand == 'HUAWEI' ||
              brand == 'HONOR' ||
              manufacturer == 'HUAWEI' ||
              manufacturer == 'HONOR') {
            // 进一步检测系统版本或特征
            // 注意：这只是一个启发式检测，不是100%准确
            final display =
                (deviceInfo['display'] as String?)?.toLowerCase() ?? '';
            if (display.contains('harmonyos') || display.contains('hmos')) {
              _isHarmonyOS = true;
              return true;
            }
          }
        }
      } catch (e) {
        debugPrint('Failed to check HarmonyOS: $e');
      }
    }

    _isHarmonyOS = false;
    return false;
  }

  static bool get isDesktop {
    return !kIsWeb &&
        (Platform.isWindows || Platform.isLinux || Platform.isMacOS);
  }

  /// 是否为移动平台（Android/iOS/鸿蒙）
  static bool get isMobile {
    if (kIsWeb) return false;
    return Platform.isAndroid || Platform.isIOS || isHarmonyOS;
  }

  static bool get isWindows {
    return !kIsWeb && Platform.isWindows;
  }

  static bool get isAndroid {
    return !kIsWeb && Platform.isAndroid;
  }

  static bool get isIOS {
    return !kIsWeb && Platform.isIOS;
  }

  static bool get isLinux {
    return !kIsWeb && Platform.isLinux;
  }

  static bool get isMacOS {
    return !kIsWeb && Platform.isMacOS;
  }

  /// 检测是否为 OHOS 平台（HarmonyOS NEXT）
  static bool get isOHOS {
    if (kIsWeb) return false;
    try {
      return Platform.operatingSystem.toLowerCase() == 'ohos';
    } catch (e) {
      return false;
    }
  }

  // Window management for desktop platforms
  static Future<void> initDesktopWindow() async {
    if (!isDesktop) return;

    await windowManager.ensureInitialized();

    const windowOptions = WindowOptions(
      size: Size(1280, 720), // 默认窗口大小 1280x720
      minimumSize: Size(600, 400),
      center: true,
      title: 'VeloGuard',
      titleBarStyle: TitleBarStyle.normal,
    );

    await windowManager.waitUntilReadyToShow(windowOptions, () async {
      await windowManager.show();
      await windowManager.focus();
    });
  }

  // Get platform-specific padding - 使用响应式工具
  static EdgeInsets getPlatformPadding(BuildContext context) {
    return ResponsiveUtils.getResponsivePadding(context);
  }

  // Get platform-specific app bar height
  static double getAppBarHeight([BuildContext? context]) {
    if (context != null) {
      return ResponsiveUtils.getAppBarHeight(context);
    }
    if (isDesktop) {
      return 64;
    } else {
      return kToolbarHeight;
    }
  }

  // Get platform-specific card elevation
  static double getCardElevation() {
    if (isDesktop) {
      return 2;
    } else {
      return 0;
    }
  }

  // Get platform-specific border radius
  static BorderRadius getBorderRadius([BuildContext? context]) {
    if (context != null) {
      return ResponsiveUtils.getCardBorderRadius(context);
    }
    if (isDesktop) {
      return BorderRadius.circular(8);
    } else {
      return BorderRadius.circular(12);
    }
  }

  // Get platform-specific icon size
  static double getIconSize(BuildContext context, {bool large = false}) {
    return ResponsiveUtils.getIconSize(context, large: large);
  }

  // Get platform-specific text scale factor
  static double getTextScaleFactor(BuildContext context) {
    return ResponsiveUtils.getFontScaleFactor(context);
  }

  // Check if running on Windows ARM64
  static bool get isWindowsArm64 {
    return isWindows && Platform.version.contains('ARM64');
  }

  // Get platform-specific file extension for executables
  static String getExecutableExtension() {
    if (isWindows) {
      return '.exe';
    } else {
      return '';
    }
  }

  // Get platform-specific configuration directory
  static String getConfigDirectory() {
    if (isWindows) {
      return '${Platform.environment['APPDATA']}\\VeloGuard';
    } else if (isLinux || isMacOS) {
      return '${Platform.environment['HOME']}/.config/veloguard';
    } else if (isAndroid || isHarmonyOS) {
      return '/data/data/com.blueokanna.veloguard/files';
    } else {
      return Directory.current.path;
    }
  }

  // Get platform-specific log directory
  static String getLogDirectory() {
    if (isWindows) {
      return '${Platform.environment['LOCALAPPDATA']}\\VeloGuard\\logs';
    } else if (isLinux || isMacOS) {
      return '${Platform.environment['HOME']}/.local/share/veloguard/logs';
    } else if (isAndroid || isHarmonyOS) {
      return '/data/data/com.blueokanna.veloguard/cache/logs';
    } else {
      return Directory.current.path;
    }
  }

  // Platform-specific navigation behavior
  static bool shouldUseBottomNavigation([BuildContext? context]) {
    if (context != null) {
      return ResponsiveUtils.shouldShowBottomNav(context);
    }
    return isMobile;
  }

  static bool shouldUseSideNavigation([BuildContext? context]) {
    if (context != null) {
      return ResponsiveUtils.shouldShowSideNav(context);
    }
    return isDesktop;
  }

  // Platform-specific scroll behavior
  static ScrollPhysics getScrollPhysics([BuildContext? context]) {
    if (context != null) {
      return ResponsiveUtils.getScrollPhysics(context);
    }
    if (isDesktop) {
      return const ClampingScrollPhysics();
    } else {
      return const BouncingScrollPhysics();
    }
  }

  // Platform-specific dialog width
  static double getDialogWidth(BuildContext context) {
    return ResponsiveUtils.getDialogMaxWidth(context);
  }

  // Platform-specific dialog height
  static double? getDialogHeight(BuildContext context) {
    final screenHeight = MediaQuery.of(context).size.height;
    if (isDesktop) {
      return screenHeight * 0.6;
    } else {
      return null;
    }
  }

  // Platform-specific grid layout
  static int getGridCrossAxisCount(BuildContext context) {
    return ResponsiveUtils.getGridColumnCount(context);
  }

  // Platform-specific list item height
  static double getListItemHeight([BuildContext? context]) {
    if (context != null) {
      return ResponsiveUtils.getListItemHeight(context);
    }
    if (isDesktop) {
      return 56;
    } else {
      return 48;
    }
  }

  // Platform-specific FAB size
  static FloatingActionButtonLocation getFabLocation() {
    return FloatingActionButtonLocation.endFloat;
  }

  // Platform-specific animation duration
  static Duration getAnimationDuration() {
    if (isDesktop) {
      return const Duration(milliseconds: 200);
    } else {
      return const Duration(milliseconds: 300);
    }
  }

  // Platform-specific haptic feedback
  static void performHapticFeedback() {
    if (isMobile) {
      HapticFeedback.lightImpact();
    }
  }

  // Platform-specific context menu behavior
  static bool shouldShowContextMenu() {
    return isDesktop;
  }

  // Platform-specific tooltip behavior
  static bool shouldShowTooltips() {
    return isDesktop;
  }

  // Platform-specific focus behavior
  static bool get autoFocusEnabled {
    return isDesktop;
  }

  // Platform-specific gesture settings
  static bool get enableSwipeGestures {
    return isMobile;
  }

  static bool get enableDragDrop {
    return isDesktop;
  }

  // Platform-specific keyboard shortcuts
  static Map<ShortcutActivator, Intent> getKeyboardShortcuts(
    BuildContext context,
  ) {
    if (!isDesktop) return {};

    return {
      const SingleActivator(LogicalKeyboardKey.keyR, control: true):
          const RefreshIntent(),
      const SingleActivator(LogicalKeyboardKey.keyQ, control: true):
          const QuitIntent(),
      const SingleActivator(LogicalKeyboardKey.f5): const RefreshIntent(),
    };
  }
}

// Custom intents for keyboard shortcuts
class RefreshIntent extends Intent {
  const RefreshIntent();
}

class QuitIntent extends Intent {
  const QuitIntent();
}
