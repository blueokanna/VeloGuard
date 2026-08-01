import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/providers/locale_provider.dart';

void main() {
  test(
    'locale selector and localization delegate support the same locales',
    () {
      final selectorLocales = LocaleProvider.supportedLocales
          .map((info) => info.locale)
          .whereType<Locale>()
          .toSet();

      expect(selectorLocales, AppLocalizations.supportedLocales.toSet());
    },
  );

  for (final locale in AppLocalizations.supportedLocales) {
    test('${locale.toLanguageTag()} has every localization key', () {
      expect(
        AppLocalizations.missingTranslationKeys(locale),
        isEmpty,
        reason: '${locale.toLanguageTag()} contains untranslated keys',
      );
    });
  }
}
