import 'package:flutter/material.dart';
import 'package:veloguard/src/services/storage_service.dart';

class LocaleProvider extends ChangeNotifier {
  Locale? _locale;
  bool _isLoading = false;

  Locale? get locale => _locale;
  Locale? get currentLocale => _locale;
  bool get isLoading => _isLoading;

  static const List<LocaleInfo> supportedLocales = [
    LocaleInfo(null, 'System Default', 'System Default', '🌐'),
    LocaleInfo(Locale('en'), 'English', 'English', '🇺🇸'),
    LocaleInfo(
      Locale('zh', 'CN'),
      'Simplified Chinese',
      'Simplified Chinese',
      '🇨🇳',
    ),
    LocaleInfo(
      Locale('zh', 'TW'),
      'Traditional Chinese',
      'Traditional Chinese',
      '🇹🇼',
    ),
    LocaleInfo(Locale('de'), 'Deutsch', 'German', '🇩🇪'),
    LocaleInfo(Locale('es'), 'Espanol', 'Spanish', '🇪🇸'),
    LocaleInfo(Locale('fr'), 'Francais', 'French', '🇫🇷'),
    LocaleInfo(Locale('it'), 'Italiano', 'Italian', '🇮🇹'),
    LocaleInfo(Locale('ja'), 'Japanese', 'Japanese', '🇯🇵'),
    LocaleInfo(Locale('ko'), 'Korean', 'Korean', '🇰🇷'),
    LocaleInfo(Locale('pt'), 'Portugues', 'Portuguese', '🇧🇷'),
    LocaleInfo(Locale('ru'), 'Russian', 'Russian', '🇷🇺'),
  ];

  LocaleProvider() {
    _loadLocale();
  }

  Future<void> _loadLocale() async {
    _isLoading = true;
    notifyListeners();

    try {
      final localeString = await StorageService.instance.getLocale();
      if (localeString != null) {
        final parts = localeString.split('_');
        if (parts.length == 2) {
          _locale = Locale(parts[0], parts[1]);
        } else if (parts.length == 1) {
          _locale = Locale(parts[0]);
        }
      }
    } catch (e) {
      debugPrint('Failed to load locale: $e');
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> setLocale(Locale? locale) async {
    _locale = locale;

    if (locale != null) {
      final localeString = locale.countryCode != null
          ? '${locale.languageCode}_${locale.countryCode}'
          : locale.languageCode;
      await StorageService.instance.setLocale(localeString);
    } else {
      await StorageService.instance.setLocale(null);
    }

    notifyListeners();
  }

  String getLocaleName(Locale? locale) {
    if (locale == null) return 'System Default';

    for (final info in supportedLocales) {
      if (info.locale?.languageCode == locale.languageCode &&
          info.locale?.countryCode == locale.countryCode) {
        return info.name;
      }
    }

    return locale.toLanguageTag();
  }
}

class LocaleInfo {
  final Locale? locale;
  final String name;
  final String englishName;
  final String flag;

  const LocaleInfo(this.locale, this.name, this.englishName, this.flag);
}
