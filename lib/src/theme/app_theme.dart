import 'package:flutter/material.dart';
import 'package:veloguard/src/theme/app_shapes.dart';

class AppTheme {
  static const String _fontFamily = 'Roboto';

  static TextStyle _textStyle({
    double? fontSize,
    FontWeight? fontWeight,
    double? letterSpacing,
    Color? color,
  }) {
    return TextStyle(
      fontFamily: _fontFamily,
      fontSize: fontSize,
      fontWeight: fontWeight,
      letterSpacing: letterSpacing,
      color: color,
    );
  }

  // Theme names
  static const String defaultTheme = 'default';
  static const String oceanTheme = 'ocean';
  static const String forestTheme = 'forest';
  static const String sunsetTheme = 'sunset';
  static const String purpleTheme = 'purple';
  static const String tealTheme = 'teal';
  static const String roseTheme = 'rose';
  static const String amberTheme = 'amber';
  static const String indigoTheme = 'indigo';
  static const String cyanTheme = 'cyan';

  // All available themes
  static const List<String> allThemes = [
    defaultTheme,
    oceanTheme,
    forestTheme,
    sunsetTheme,
    purpleTheme,
    tealTheme,
    roseTheme,
    amberTheme,
    indigoTheme,
    cyanTheme,
  ];

  // Theme display names
  static String getThemeDisplayName(String themeName) {
    switch (themeName) {
      case oceanTheme:
        return 'Ocean Blue';
      case forestTheme:
        return 'Forest Green';
      case sunsetTheme:
        return 'Sunset Red';
      case purpleTheme:
        return 'Deep Purple';
      case tealTheme:
        return 'Teal';
      case roseTheme:
        return 'Rose Pink';
      case amberTheme:
        return 'Amber';
      case indigoTheme:
        return 'Indigo';
      case cyanTheme:
        return 'Cyan';
      default:
        return 'Default Blue';
    }
  }

  // Theme seed colors for preview
  static Color getThemeSeedColor(String themeName) {
    switch (themeName) {
      case oceanTheme:
        return const Color(0xFF0061A4);
      case forestTheme:
        return const Color(0xFF146C2E);
      case sunsetTheme:
        return const Color(0xFF8F4A4A);
      case purpleTheme:
        return const Color(0xFF6750A4);
      case tealTheme:
        return const Color(0xFF006A6A);
      case roseTheme:
        return const Color(0xFFB4004E);
      case amberTheme:
        return const Color(0xFF7D5700);
      case indigoTheme:
        return const Color(0xFF3F51B5);
      case cyanTheme:
        return const Color(0xFF006978);
      default:
        return const Color(0xFF1976D2);
    }
  }

  // Generate ColorScheme from seed color using Material 3
  static ColorScheme _generateColorScheme(
    String themeName,
    Brightness brightness,
  ) {
    final seedColor = getThemeSeedColor(themeName);
    return ColorScheme.fromSeed(seedColor: seedColor, brightness: brightness);
  }

  // Create theme data for a specific theme
  static ThemeData createTheme(String themeName, Brightness brightness) {
    final colorScheme = _generateColorScheme(themeName, brightness);
    return _buildThemeData(colorScheme, brightness);
  }

  // Create dynamic theme from system colors
  static ThemeData createDynamicTheme(
    ColorScheme? dynamicColorScheme,
    Brightness brightness,
  ) {
    if (dynamicColorScheme != null) {
      return _buildThemeData(dynamicColorScheme, brightness);
    }
    return createTheme(defaultTheme, brightness);
  }

  // Build complete ThemeData from ColorScheme
  static ThemeData _buildThemeData(
    ColorScheme colorScheme,
    Brightness brightness,
  ) {
    return ThemeData(
      useMaterial3: true,
      colorScheme: colorScheme,
      fontFamily: _fontFamily,
      textTheme: _createTextTheme(colorScheme),
      appBarTheme: _createAppBarTheme(colorScheme),
      cardTheme: _createCardTheme(colorScheme),
      listTileTheme: _createListTileTheme(colorScheme),
      dividerTheme: _createDividerTheme(colorScheme),
      switchTheme: _createSwitchTheme(colorScheme),
      dropdownMenuTheme: _createDropdownMenuTheme(colorScheme),
      popupMenuTheme: _createPopupMenuTheme(colorScheme),
      iconButtonTheme: _createIconButtonTheme(colorScheme),
      segmentedButtonTheme: _createSegmentedButtonTheme(colorScheme),
      elevatedButtonTheme: _createElevatedButtonTheme(colorScheme),
      filledButtonTheme: _createFilledButtonTheme(colorScheme),
      outlinedButtonTheme: _createOutlinedButtonTheme(colorScheme),
      textButtonTheme: _createTextButtonTheme(colorScheme),
      floatingActionButtonTheme: _createFabTheme(colorScheme),
      navigationBarTheme: _createNavigationBarTheme(colorScheme),
      navigationRailTheme: _createNavigationRailTheme(colorScheme),
      bottomSheetTheme: _createBottomSheetTheme(colorScheme),
      dialogTheme: _createDialogTheme(colorScheme),
      snackBarTheme: _createSnackBarTheme(colorScheme),
      chipTheme: _createChipTheme(colorScheme),
      inputDecorationTheme: _createInputDecorationTheme(colorScheme),
      iconTheme: IconThemeData(color: colorScheme.onSurface),
      primaryIconTheme: IconThemeData(color: colorScheme.primary),
      scaffoldBackgroundColor: colorScheme.surface,
      canvasColor: colorScheme.surface,
      splashColor: colorScheme.primary.withValues(alpha: 0.08),
      highlightColor: colorScheme.primary.withValues(alpha: 0.04),
      hoverColor: colorScheme.primary.withValues(alpha: 0.04),
      focusColor: colorScheme.primary.withValues(alpha: 0.12),
      tooltipTheme: TooltipThemeData(
        decoration: ShapeDecoration(
          color: colorScheme.inverseSurface,
          shape: AppShapes.card,
        ),
        textStyle: _textStyle(
          fontSize: 12,
          color: colorScheme.onInverseSurface,
        ),
        waitDuration: const Duration(milliseconds: 500),
      ),
    );
  }

  static TextTheme _createTextTheme(ColorScheme colorScheme) {
    return const TextTheme().copyWith(
      displayLarge: _textStyle(
        fontSize: 57,
        fontWeight: FontWeight.w400,
        color: colorScheme.onSurface,
      ),
      displayMedium: _textStyle(
        fontSize: 45,
        fontWeight: FontWeight.w400,
        color: colorScheme.onSurface,
      ),
      displaySmall: _textStyle(
        fontSize: 36,
        fontWeight: FontWeight.w400,
        color: colorScheme.onSurface,
      ),
      headlineLarge: _textStyle(
        fontSize: 32,
        fontWeight: FontWeight.w400,
        color: colorScheme.onSurface,
      ),
      headlineMedium: _textStyle(
        fontSize: 28,
        fontWeight: FontWeight.w400,
        color: colorScheme.onSurface,
      ),
      headlineSmall: _textStyle(
        fontSize: 24,
        fontWeight: FontWeight.w400,
        color: colorScheme.onSurface,
      ),
      titleLarge: _textStyle(
        fontSize: 22,
        fontWeight: FontWeight.w500,
        color: colorScheme.onSurface,
      ),
      titleMedium: _textStyle(
        fontSize: 16,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.15,
        color: colorScheme.onSurface,
      ),
      titleSmall: _textStyle(
        fontSize: 14,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.1,
        color: colorScheme.onSurface,
      ),
      labelLarge: _textStyle(
        fontSize: 14,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.1,
        color: colorScheme.onSurface,
      ),
      labelMedium: _textStyle(
        fontSize: 12,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.5,
        color: colorScheme.onSurface,
      ),
      labelSmall: _textStyle(
        fontSize: 11,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.5,
        color: colorScheme.onSurface,
      ),
      bodyLarge: _textStyle(
        fontSize: 16,
        fontWeight: FontWeight.w400,
        letterSpacing: 0.15,
        color: colorScheme.onSurface,
      ),
      bodyMedium: _textStyle(
        fontSize: 14,
        fontWeight: FontWeight.w400,
        letterSpacing: 0.25,
        color: colorScheme.onSurface,
      ),
      bodySmall: _textStyle(
        fontSize: 12,
        fontWeight: FontWeight.w400,
        letterSpacing: 0.4,
        color: colorScheme.onSurfaceVariant,
      ),
    );
  }

  static AppBarTheme _createAppBarTheme(ColorScheme colorScheme) {
    return AppBarTheme(
      centerTitle: false,
      elevation: 0,
      scrolledUnderElevation: 0,
      backgroundColor: colorScheme.surface,
      foregroundColor: colorScheme.onSurface,
      surfaceTintColor: Colors.transparent,
      shadowColor: Colors.transparent,
      titleTextStyle: _textStyle(
        fontSize: 20,
        fontWeight: FontWeight.w600,
        color: colorScheme.onSurface,
      ),
      iconTheme: IconThemeData(color: colorScheme.onSurface),
      actionsIconTheme: IconThemeData(color: colorScheme.onSurface),
    );
  }

  static CardThemeData _createCardTheme(ColorScheme colorScheme) {
    return CardThemeData(
      elevation: 0,
      shape: AppShapes.card,
      color: colorScheme.surfaceContainerLow,
      shadowColor: Colors.transparent,
      surfaceTintColor: Colors.transparent,
      margin: EdgeInsets.zero,
    );
  }

  static ListTileThemeData _createListTileTheme(ColorScheme colorScheme) {
    return ListTileThemeData(
      tileColor: Colors.transparent,
      selectedTileColor: colorScheme.primaryContainer.withValues(alpha: 0.3),
      iconColor: colorScheme.onSurfaceVariant,
      textColor: colorScheme.onSurface,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      shape: AppShapes.control,
    );
  }

  static DividerThemeData _createDividerTheme(ColorScheme colorScheme) {
    return DividerThemeData(
      color: colorScheme.outlineVariant.withValues(alpha: 0.5),
      thickness: 1,
      space: 1,
    );
  }

  static SwitchThemeData _createSwitchTheme(ColorScheme colorScheme) {
    return SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) {
          return colorScheme.onPrimary;
        }
        return colorScheme.outline;
      }),
      trackColor: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) {
          return colorScheme.primary;
        }
        return colorScheme.surfaceContainerHighest;
      }),
      trackOutlineColor: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) {
          return Colors.transparent;
        }
        return colorScheme.outline;
      }),
      trackOutlineWidth: WidgetStateProperty.all(2),
    );
  }

  static DropdownMenuThemeData _createDropdownMenuTheme(
    ColorScheme colorScheme,
  ) {
    return DropdownMenuThemeData(
      textStyle: _textStyle(fontSize: 14, color: colorScheme.onSurface),
      menuStyle: MenuStyle(
        backgroundColor: WidgetStateProperty.all(
          colorScheme.surfaceContainerHigh,
        ),
        surfaceTintColor: WidgetStateProperty.all(Colors.transparent),
        elevation: WidgetStateProperty.all(3),
        shape: WidgetStateProperty.all(AppShapes.control),
        padding: WidgetStateProperty.all(
          const EdgeInsets.symmetric(vertical: 8),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: colorScheme.surfaceContainerHighest,
        border: OutlineInputBorder(
          borderRadius: AppShapes.medium,
          borderSide: BorderSide.none,
        ),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 16,
          vertical: 12,
        ),
      ),
    );
  }

  static PopupMenuThemeData _createPopupMenuTheme(ColorScheme colorScheme) {
    return PopupMenuThemeData(
      color: colorScheme.surfaceContainerHigh,
      surfaceTintColor: Colors.transparent,
      elevation: 3,
      shape: AppShapes.control,
      textStyle: _textStyle(fontSize: 14, color: colorScheme.onSurface),
    );
  }

  static IconButtonThemeData _createIconButtonTheme(ColorScheme colorScheme) {
    return IconButtonThemeData(
      style: ButtonStyle(
        shape: const WidgetStatePropertyAll(AppShapes.circle),
        foregroundColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.disabled)) {
            return colorScheme.onSurface.withValues(alpha: 0.38);
          }
          return colorScheme.onSurfaceVariant;
        }),
        overlayColor: WidgetStatePropertyAll(
          colorScheme.primary.withValues(alpha: 0.08),
        ),
      ),
    );
  }

  static SegmentedButtonThemeData _createSegmentedButtonTheme(
    ColorScheme colorScheme,
  ) {
    return SegmentedButtonThemeData(
      style: ButtonStyle(
        shape: const WidgetStatePropertyAll(AppShapes.control),
        side: WidgetStatePropertyAll(
          BorderSide(color: colorScheme.outlineVariant),
        ),
        backgroundColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return colorScheme.secondaryContainer;
          }
          return Colors.transparent;
        }),
        foregroundColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return colorScheme.onSecondaryContainer;
          }
          return colorScheme.onSurface;
        }),
      ),
    );
  }

  static ElevatedButtonThemeData _createElevatedButtonTheme(
    ColorScheme colorScheme,
  ) {
    return ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        elevation: 0,
        backgroundColor: colorScheme.surfaceContainerHigh,
        foregroundColor: colorScheme.primary,
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
        shape: AppShapes.pill,
        textStyle: _textStyle(fontWeight: FontWeight.w500, fontSize: 14),
      ),
    );
  }

  static FilledButtonThemeData _createFilledButtonTheme(
    ColorScheme colorScheme,
  ) {
    return FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: colorScheme.primary,
        foregroundColor: colorScheme.onPrimary,
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
        shape: AppShapes.pill,
        textStyle: _textStyle(fontWeight: FontWeight.w500, fontSize: 14),
      ),
    );
  }

  static OutlinedButtonThemeData _createOutlinedButtonTheme(
    ColorScheme colorScheme,
  ) {
    return OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: colorScheme.primary,
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
        shape: AppShapes.pill,
        side: BorderSide(color: colorScheme.outline, width: 1),
        textStyle: _textStyle(fontWeight: FontWeight.w500, fontSize: 14),
      ),
    );
  }

  static TextButtonThemeData _createTextButtonTheme(ColorScheme colorScheme) {
    return TextButtonThemeData(
      style: TextButton.styleFrom(
        foregroundColor: colorScheme.primary,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        shape: AppShapes.pill,
        textStyle: _textStyle(fontWeight: FontWeight.w500, fontSize: 14),
      ),
    );
  }

  static FloatingActionButtonThemeData _createFabTheme(
    ColorScheme colorScheme,
  ) {
    return FloatingActionButtonThemeData(
      backgroundColor: colorScheme.primaryContainer,
      foregroundColor: colorScheme.onPrimaryContainer,
      elevation: 0,
      focusElevation: 0,
      hoverElevation: 1,
      highlightElevation: 0,
      shape: AppShapes.floatingAction,
    );
  }

  static NavigationBarThemeData _createNavigationBarTheme(
    ColorScheme colorScheme,
  ) {
    return NavigationBarThemeData(
      backgroundColor: colorScheme.surfaceContainer,
      elevation: 0,
      shadowColor: Colors.transparent,
      surfaceTintColor: Colors.transparent,
      indicatorColor: colorScheme.secondaryContainer,
      indicatorShape: AppShapes.pill,
      labelTextStyle: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) {
          return _textStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: colorScheme.onSurface,
          );
        }
        return _textStyle(
          fontSize: 12,
          fontWeight: FontWeight.w500,
          color: colorScheme.onSurfaceVariant,
        );
      }),
      iconTheme: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) {
          return IconThemeData(
            color: colorScheme.onSecondaryContainer,
            size: 24,
          );
        }
        return IconThemeData(color: colorScheme.onSurfaceVariant, size: 24);
      }),
    );
  }

  static NavigationRailThemeData _createNavigationRailTheme(
    ColorScheme colorScheme,
  ) {
    return NavigationRailThemeData(
      backgroundColor: colorScheme.surface,
      elevation: 0,
      indicatorColor: colorScheme.secondaryContainer,
      indicatorShape: AppShapes.pill,
      selectedIconTheme: IconThemeData(
        color: colorScheme.onSecondaryContainer,
        size: 24,
      ),
      unselectedIconTheme: IconThemeData(
        color: colorScheme.onSurfaceVariant,
        size: 24,
      ),
      selectedLabelTextStyle: _textStyle(
        fontSize: 12,
        fontWeight: FontWeight.w600,
        color: colorScheme.onSurface,
      ),
      unselectedLabelTextStyle: _textStyle(
        fontSize: 12,
        fontWeight: FontWeight.w500,
        color: colorScheme.onSurfaceVariant,
      ),
    );
  }

  static BottomSheetThemeData _createBottomSheetTheme(ColorScheme colorScheme) {
    return BottomSheetThemeData(
      backgroundColor: colorScheme.surfaceContainerLow,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      modalElevation: 1,
      shape: AppShapes.bottomSheet,
      dragHandleColor: colorScheme.onSurfaceVariant.withValues(alpha: 0.4),
      dragHandleSize: const Size(32, 4),
    );
  }

  static DialogThemeData _createDialogTheme(ColorScheme colorScheme) {
    return DialogThemeData(
      backgroundColor: colorScheme.surfaceContainerHigh,
      surfaceTintColor: Colors.transparent,
      elevation: 3,
      shape: AppShapes.dialog,
      titleTextStyle: _textStyle(
        fontSize: 24,
        fontWeight: FontWeight.w600,
        color: colorScheme.onSurface,
      ),
      contentTextStyle: _textStyle(
        fontSize: 14,
        fontWeight: FontWeight.w400,
        color: colorScheme.onSurfaceVariant,
      ),
    );
  }

  static SnackBarThemeData _createSnackBarTheme(ColorScheme colorScheme) {
    return SnackBarThemeData(
      backgroundColor: colorScheme.inverseSurface,
      contentTextStyle: _textStyle(
        fontSize: 14,
        fontWeight: FontWeight.w400,
        color: colorScheme.onInverseSurface,
      ),
      actionTextColor: colorScheme.inversePrimary,
      shape: AppShapes.card,
      behavior: SnackBarBehavior.floating,
      elevation: 0,
    );
  }

  static ChipThemeData _createChipTheme(ColorScheme colorScheme) {
    return ChipThemeData(
      backgroundColor: colorScheme.surfaceContainerHigh,
      selectedColor: colorScheme.secondaryContainer,
      disabledColor: colorScheme.surfaceContainerHighest,
      labelStyle: _textStyle(
        fontSize: 14,
        fontWeight: FontWeight.w500,
        color: colorScheme.onSurface,
      ),
      secondaryLabelStyle: _textStyle(
        fontSize: 14,
        fontWeight: FontWeight.w500,
        color: colorScheme.onSecondaryContainer,
      ),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      shape: AppShapes.card,
      side: BorderSide.none,
    );
  }

  static InputDecorationTheme _createInputDecorationTheme(
    ColorScheme colorScheme,
  ) {
    return InputDecorationTheme(
      filled: true,
      fillColor: colorScheme.surfaceContainerHighest,
      border: OutlineInputBorder(
        borderRadius: AppShapes.medium,
        borderSide: BorderSide.none,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: AppShapes.medium,
        borderSide: BorderSide.none,
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: AppShapes.medium,
        borderSide: BorderSide(color: colorScheme.primary, width: 2),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: AppShapes.medium,
        borderSide: BorderSide(color: colorScheme.error, width: 1),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      hintStyle: _textStyle(fontSize: 14, color: colorScheme.onSurfaceVariant),
      labelStyle: _textStyle(fontSize: 14, color: colorScheme.onSurfaceVariant),
    );
  }

  // Default themes for backward compatibility
  static ThemeData get lightTheme =>
      createTheme(defaultTheme, Brightness.light);
  static ThemeData get darkTheme => createTheme(defaultTheme, Brightness.dark);

  // Custom colors for specific use cases
  static const Color successColor = Color(0xFF146C2E);
  static const Color warningColor = Color(0xFF7D5800);
  static const Color infoColor = Color(0xFF005AC1);
  static const Color connectedColor = Color(0xFF146C2E);
  static const Color disconnectedColor = Color(0xFFBA1A1A);
  static const Color connectingColor = Color(0xFF7D5800);
}
