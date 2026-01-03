import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:veloguard/src/theme/app_theme.dart';

class ThemeProvider extends ChangeNotifier {
  static const String _themeKey = 'selected_theme';
  static const String _dynamicColorsKey = 'use_dynamic_colors';

  String _selectedTheme = AppTheme.defaultTheme;
  bool _useDynamicColors = false;

  ThemeProvider() {
    _loadSettings();
  }

  String get selectedTheme => _selectedTheme;
  bool get useDynamicColors => _useDynamicColors;

  // Available themes
  List<String> get availableThemes => AppTheme.allThemes;

  String getThemeDisplayName(String themeName) {
    return AppTheme.getThemeDisplayName(themeName);
  }

  Color getThemeSeedColor(String themeName) {
    return AppTheme.getThemeSeedColor(themeName);
  }

  void setTheme(String themeName) {
    if (_selectedTheme != themeName && availableThemes.contains(themeName)) {
      _selectedTheme = themeName;
      _saveSettings();
      notifyListeners();
    }
  }

  void setUseDynamicColors(bool useDynamic) {
    if (_useDynamicColors != useDynamic) {
      _useDynamicColors = useDynamic;
      _saveSettings();
      notifyListeners();
    }
  }

  void _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    _selectedTheme = prefs.getString(_themeKey) ?? AppTheme.defaultTheme;
    _useDynamicColors = prefs.getBool(_dynamicColorsKey) ?? false;
    notifyListeners();
  }

  void _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_themeKey, _selectedTheme);
    await prefs.setBool(_dynamicColorsKey, _useDynamicColors);
  }

  // Get the current theme data
  ThemeData getCurrentTheme(Brightness brightness) {
    return AppTheme.createTheme(_selectedTheme, brightness);
  }

  // Cycle to next theme
  void cycleTheme() {
    final currentIndex = availableThemes.indexOf(_selectedTheme);
    final nextIndex = (currentIndex + 1) % availableThemes.length;
    setTheme(availableThemes[nextIndex]);
  }
}
