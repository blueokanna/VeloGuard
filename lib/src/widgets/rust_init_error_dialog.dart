import 'package:flutter/material.dart';
import 'package:veloguard/src/widgets/adaptive_dialog.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/main.dart' show lastInitError;

/// Dialog shown when the Rust library fails to initialize.
/// Provides user-friendly error message and allows continuing with limited functionality.
class RustInitErrorDialog extends StatelessWidget {
  const RustInitErrorDialog({super.key});

  /// Shows the error dialog and returns true if user wants to retry
  static Future<bool> show(BuildContext context) async {
    final result = await AdaptiveDialog.show<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => const RustInitErrorDialog(),
    );
    return result ?? false;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    return AdaptiveDialog(
      title: Row(
        children: [
          Icon(
            Icons.warning_amber_rounded,
            color: theme.colorScheme.error,
            size: 28,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              l10n?.rustInitErrorTitle ?? 'Initialization Error',
              style: theme.textTheme.titleLarge?.copyWith(
                color: theme.colorScheme.error,
              ),
            ),
          ),
        ],
      ),
      scrollable: true,
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            l10n?.rustInitErrorMessage ??
                'The native library failed to load. Some features will not be available.',
            style: theme.textTheme.bodyMedium,
          ),
          if (lastInitError != null && lastInitError!.isNotEmpty) ...[
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: theme.colorScheme.errorContainer.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                'Error: $lastInitError',
                style: theme.textTheme.bodySmall?.copyWith(
                  fontFamily: 'monospace',
                  color: theme.colorScheme.error,
                ),
              ),
            ),
          ],
          const SizedBox(height: 16),
          _buildSection(
            context,
            icon: Icons.block_rounded,
            title: l10n?.rustInitErrorAffectedFeatures ?? 'Affected Features',
            items: [
              l10n?.rustInitErrorFeatureVpn ?? '• VPN connection',
              l10n?.rustInitErrorFeatureProxy ?? '• Proxy functionality',
              l10n?.rustInitErrorFeatureProfiles ?? '• Profile activation',
            ],
          ),
          const SizedBox(height: 16),
          _buildSection(
            context,
            icon: Icons.lightbulb_outline_rounded,
            title: l10n?.rustInitErrorSuggestions ?? 'Suggestions',
            items: [
              l10n?.rustInitErrorSuggestion1 ?? '• Restart the app',
              l10n?.rustInitErrorSuggestion2 ??
                  '• Update to the latest version',
              l10n?.rustInitErrorSuggestion3 ?? '• Check device compatibility',
            ],
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: Text(l10n?.rustInitErrorRetry ?? 'Retry'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: Text(l10n?.rustInitErrorContinue ?? 'Continue Anyway'),
        ),
      ],
    );
  }

  Widget _buildSection(
    BuildContext context, {
    required IconData icon,
    required String title,
    required List<String> items,
  }) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 18, color: theme.colorScheme.primary),
              const SizedBox(width: 8),
              Text(
                title,
                style: theme.textTheme.titleSmall?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ...items.map(
            (item) => Padding(
              padding: const EdgeInsets.only(left: 26, top: 4),
              child: Text(
                item,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
