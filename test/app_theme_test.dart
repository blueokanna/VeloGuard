import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:veloguard/src/theme/app_shapes.dart';
import 'package:veloguard/src/theme/app_theme.dart';

void main() {
  test('application theme uses Material 3 and bundled Roboto', () {
    final theme = AppTheme.createTheme(AppTheme.defaultTheme, Brightness.light);

    expect(theme.useMaterial3, isTrue);
    expect(theme.textTheme.bodyMedium?.fontFamily, 'Roboto');
  });

  test('Material surfaces use the shared shape hierarchy', () {
    final theme = AppTheme.createTheme(AppTheme.defaultTheme, Brightness.dark);

    expect(theme.cardTheme.shape, AppShapes.card);
    expect(theme.dialogTheme.shape, AppShapes.dialog);
    expect(theme.bottomSheetTheme.shape, AppShapes.bottomSheet);
    expect(theme.floatingActionButtonTheme.shape, AppShapes.floatingAction);
    expect(
      theme.filledButtonTheme.style?.shape?.resolve(<WidgetState>{}),
      AppShapes.pill,
    );
  });
}
