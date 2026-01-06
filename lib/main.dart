import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:provider/provider.dart';
import 'package:veloguard/src/rust/frb_generated.dart';
import 'package:veloguard/src/theme/app_theme.dart';
import 'package:veloguard/src/providers/app_state_provider.dart';
import 'package:veloguard/src/providers/theme_provider.dart';
import 'package:veloguard/src/providers/profiles_provider.dart';
import 'package:veloguard/src/providers/network_settings_provider.dart';
import 'package:veloguard/src/providers/locale_provider.dart';
import 'package:veloguard/src/providers/proxies_provider.dart';
import 'package:veloguard/src/providers/dns_settings_provider.dart';
import 'package:veloguard/src/providers/general_settings_provider.dart';
import 'package:veloguard/src/services/storage_service.dart';
import 'package:veloguard/src/screens/home_screen.dart';
import 'package:veloguard/src/screens/settings_screen.dart';
import 'package:veloguard/src/screens/connections_screen.dart';
import 'package:veloguard/src/screens/logs_screen.dart';
import 'package:veloguard/src/screens/network_settings_screen.dart';
import 'package:veloguard/src/screens/dns_settings_screen.dart';
import 'package:veloguard/src/screens/basic_config_screen.dart';
import 'package:veloguard/src/screens/advanced_config_screen.dart';
import 'package:veloguard/src/screens/proxies_screen.dart';
import 'package:veloguard/src/widgets/adaptive_scaffold.dart';
import 'package:veloguard/src/widgets/rust_init_error_dialog.dart';
import 'package:veloguard/src/utils/platform_utils.dart';
import 'package:veloguard/src/utils/device_info_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/screens/profiles_screen.dart';
import 'package:go_router/go_router.dart';
import 'package:dynamic_color/dynamic_color.dart';
import 'dart:ffi' as ffi;
import 'dart:io' show Platform;

bool isRustLibInitialized = false;
bool _errorDialogShown = false;

final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

String? lastInitError;

Future<bool> _tryDirectLibraryLoad() async {
  if (!Platform.isAndroid && !Platform.isIOS) {
    return false;
  }

  try {
    debugPrint('Attempting direct library load via ffi.DynamicLibrary.open...');
    final lib = ffi.DynamicLibrary.open('librust_lib_veloguard.so');
    debugPrint('Direct library load SUCCESS: $lib');
    return true;
  } catch (e) {
    debugPrint('Direct library load FAILED: $e');
    return false;
  }
}

Future<bool> _initRustLibWithRetry({int maxRetries = 3}) async {
  if (Platform.isAndroid) {
    final directLoadSuccess = await _tryDirectLibraryLoad();
    debugPrint('Direct library load result: $directLoadSuccess');
  }

  for (int i = 0; i < maxRetries; i++) {
    try {
      await RustLib.init();
      isRustLibInitialized = true;
      lastInitError = null;
      debugPrint('RustLib initialized successfully on attempt ${i + 1}');
      return true;
    } catch (e, stackTrace) {
      lastInitError = e.toString();
      debugPrint('========================================');
      debugPrint('RustLib.init() FAILURE - Attempt ${i + 1}/$maxRetries');
      debugPrint('========================================');
      debugPrint('Error type: ${e.runtimeType}');
      debugPrint('Error message: $e');
      debugPrint('----------------------------------------');
      debugPrint('Full stack trace:');
      debugPrint('$stackTrace');
      debugPrint('========================================');
      if (i < maxRetries - 1) {
        debugPrint('Retrying in 500ms...');
        await Future.delayed(const Duration(milliseconds: 500));
      }
    }
  }
  isRustLibInitialized = false;
  debugPrint('========================================');
  debugPrint('RustLib initialization FAILED after $maxRetries attempts');
  debugPrint('Some features requiring Rust library will not work');
  debugPrint('========================================');
  return false;
}

Future<bool> retryRustLibInit() async {
  final success = await _initRustLibWithRetry(maxRetries: 3);
  return success;
}

/// Check native library status via method channel (Android only)
Future<Map<String, dynamic>?> _checkNativeLibraryStatus() async {
  if (!Platform.isAndroid) return null;

  try {
    const channel = MethodChannel('com.veloguard/proxy');
    final result = await channel.invokeMethod('getNativeLibraryInfo');
    if (result is Map) {
      debugPrint('========================================');
      debugPrint('Native Library Info from Android:');
      result.forEach((key, value) {
        debugPrint('  $key: $value');
      });
      debugPrint('========================================');
      return Map<String, dynamic>.from(result);
    }
  } catch (e) {
    debugPrint('Failed to get native library info: $e');
  }
  return null;
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // On Android, first check if the native library was loaded by Kotlin
  if (Platform.isAndroid) {
    final libInfo = await _checkNativeLibraryStatus();
    if (libInfo != null) {
      final loaded = libInfo['loaded'] as bool? ?? false;
      final error = libInfo['error'] as String? ?? '';
      if (!loaded) {
        debugPrint('========================================');
        debugPrint('CRITICAL: Native library NOT loaded by Android!');
        debugPrint('Error: $error');
        debugPrint('========================================');
        lastInitError = 'Native library not loaded: $error';
      }
    }
  }

  try {
    final success = await _initRustLibWithRetry(maxRetries: 3);
    if (!success) {
      debugPrint(
        'WARNING: RustLib failed to initialize - some features may not work',
      );
    }
  } catch (e, stackTrace) {
    debugPrint('Unexpected error during RustLib initialization: $e');
    debugPrint('Stack trace: $stackTrace');
    isRustLibInitialized = false;
  }

  try {
    await StorageService.instance.init();
    debugPrint('StorageService initialized successfully');

    final generalSettings = await StorageService.instance.getGeneralSettings();
    AnimationUtils.setHapticEnabled(generalSettings.hapticFeedbackEnabled);
    debugPrint(
      'Haptic feedback initialized: ${generalSettings.hapticFeedbackEnabled}',
    );
  } catch (e) {
    debugPrint('Failed to initialize StorageService: $e');
  }

  try {
    await DeviceInfoUtils.initialize();
    debugPrint('DeviceInfoUtils initialized successfully');
  } catch (e) {
    debugPrint('Failed to initialize DeviceInfoUtils: $e');
  }

  try {
    await PlatformUtils.checkHarmonyOS().timeout(
      const Duration(seconds: 3),
      onTimeout: () {
        debugPrint('HarmonyOS check timed out');
        return false;
      },
    );
  } catch (e) {
    debugPrint('Failed to check HarmonyOS: $e');
  }

  if (PlatformUtils.isDesktop) {
    try {
      await PlatformUtils.initDesktopWindow();
    } catch (e) {
      debugPrint('Failed to initialize desktop window: $e');
    }
  }

  // Set preferred orientations for mobile (including HarmonyOS)
  if (PlatformUtils.isMobile) {
    await SystemChrome.setPreferredOrientations([
      DeviceOrientation.portraitUp,
      DeviceOrientation.portraitDown,
    ]);
  }

  runApp(const VeloGuardApp());
}

class VeloGuardApp extends StatefulWidget {
  const VeloGuardApp({super.key});

  @override
  State<VeloGuardApp> createState() => _VeloGuardAppState();
}

class _VeloGuardAppState extends State<VeloGuardApp> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _showErrorDialogIfNeeded();
    });
  }

  Future<void> _showErrorDialogIfNeeded() async {
    if (!isRustLibInitialized && !_errorDialogShown) {
      _errorDialogShown = true;
      final context = navigatorKey.currentContext;
      if (context != null) {
        final shouldRetry = await RustInitErrorDialog.show(context);
        if (shouldRetry) {
          final success = await retryRustLibInit();
          if (success) {
            if (mounted) {
              setState(() {});
            }
          } else {
            _errorDialogShown = false;
            _showErrorDialogIfNeeded();
          }
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => AppStateProvider()),
        ChangeNotifierProvider(create: (_) => ThemeProvider()),
        ChangeNotifierProvider(create: (_) => ProfilesProvider()),
        ChangeNotifierProvider(create: (_) => NetworkSettingsProvider()),
        ChangeNotifierProvider(create: (_) => LocaleProvider()),
        ChangeNotifierProvider(create: (_) => ProxiesProvider()),
        ChangeNotifierProvider(create: (_) => DnsSettingsProvider()),
        ChangeNotifierProvider(create: (_) => GeneralSettingsProvider()),
      ],
      child: DynamicColorBuilder(
        builder: (lightColorScheme, darkColorScheme) {
          return Consumer3<AppStateProvider, ThemeProvider, LocaleProvider>(
            builder: (context, appState, themeProvider, localeProvider, child) {
              final lightTheme =
                  themeProvider.useDynamicColors && lightColorScheme != null
                  ? AppTheme.createDynamicTheme(
                      lightColorScheme,
                      Brightness.light,
                    )
                  : AppTheme.createTheme(
                      themeProvider.selectedTheme,
                      Brightness.light,
                    );

              final darkTheme =
                  themeProvider.useDynamicColors && darkColorScheme != null
                  ? AppTheme.createDynamicTheme(
                      darkColorScheme,
                      Brightness.dark,
                    )
                  : AppTheme.createTheme(
                      themeProvider.selectedTheme,
                      Brightness.dark,
                    );

              return MaterialApp.router(
                title: 'VeloGuard',
                debugShowCheckedModeBanner: false,
                theme: lightTheme,
                darkTheme: darkTheme,
                themeMode: appState.themeMode,
                locale: localeProvider.currentLocale,
                localizationsDelegates: const [
                  AppLocalizations.delegate,
                  GlobalMaterialLocalizations.delegate,
                  GlobalWidgetsLocalizations.delegate,
                  GlobalCupertinoLocalizations.delegate,
                ],
                supportedLocales: AppLocalizations.supportedLocales,
                routerConfig: _router,
              );
            },
          );
        },
      ),
    );
  }
}

final GoRouter _router = GoRouter(
  navigatorKey: navigatorKey,
  routes: [
    ShellRoute(
      builder: (context, state, child) {
        return AdaptiveScaffold(body: child);
      },
      routes: [
        GoRoute(
          path: '/',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const HomeScreen()),
        ),
        GoRoute(
          path: '/proxies',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const ProxiesScreen()),
        ),
        GoRoute(
          path: '/profiles',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const ProfilesScreen()),
        ),
        GoRoute(
          path: '/connections',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const ConnectionsScreen()),
        ),
        GoRoute(
          path: '/logs',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const LogsScreen()),
        ),
        GoRoute(
          path: '/settings',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const SettingsScreen()),
        ),
        GoRoute(
          path: '/network-settings',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const NetworkSettingsScreen()),
        ),
        GoRoute(
          path: '/dns-settings',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const DnsSettingsScreen()),
        ),
        GoRoute(
          path: '/basic-config',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const BasicConfigScreen()),
        ),
        GoRoute(
          path: '/advanced-config',
          pageBuilder: (context, state) =>
              _buildExpressivePage(state, const AdvancedConfigScreen()),
        ),
      ],
    ),
  ],
);

CustomTransitionPage<void> _buildExpressivePage(
  GoRouterState state,
  Widget child,
) {
  return CustomTransitionPage<void>(
    key: state.pageKey,
    child: child,
    transitionDuration: AnimationUtils.pageTransitionDuration,
    reverseTransitionDuration: const Duration(milliseconds: 300),
    transitionsBuilder: (context, animation, secondaryAnimation, child) {
      final curvedAnimation = CurvedAnimation(
        parent: animation,
        curve: AnimationUtils.curveEmphasizedDecelerate,
        reverseCurve: AnimationUtils.curveEmphasizedAccelerate,
      );

      final fadeAnimation = Tween<double>(
        begin: 0.0,
        end: 1.0,
      ).animate(curvedAnimation);

      final slideAnimation = Tween<Offset>(
        begin: const Offset(0.03, 0),
        end: Offset.zero,
      ).animate(curvedAnimation);

      final scaleAnimation = Tween<double>(
        begin: 0.96,
        end: 1.0,
      ).animate(curvedAnimation);

      return FadeTransition(
        opacity: fadeAnimation,
        child: SlideTransition(
          position: slideAnimation,
          child: ScaleTransition(scale: scaleAnimation, child: child),
        ),
      );
    },
  );
}
