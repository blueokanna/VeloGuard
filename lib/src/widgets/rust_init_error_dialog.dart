import 'package:flutter/material.dart';
import 'package:veloguard/src/widgets/adaptive_dialog.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';

/// Dialog shown when the Rust library fails to initialize.
/// The application cannot continue until the native core is available.
class RustInitErrorDialog extends StatelessWidget {
  const RustInitErrorDialog({super.key, this.errorDetails});

  final String? errorDetails;

  static Future<void> show(BuildContext context, {String? errorDetails}) async {
    await AdaptiveDialog.show<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => PopScope(
        canPop: false,
        child: RustInitErrorDialog(errorDetails: errorDetails),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context)!;

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
              l10n.rustInitErrorTitle,
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
          Text(l10n.rustInitErrorMessage, style: theme.textTheme.bodyMedium),
          if (errorDetails != null && errorDetails!.isNotEmpty) ...[
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: theme.colorScheme.errorContainer.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                '${l10n.rustInitErrorDetails}: $errorDetails',
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
            title: l10n.rustInitErrorAffectedFeatures,
            items: [
              l10n.rustInitErrorFeatureVpn,
              l10n.rustInitErrorFeatureProxy,
              l10n.rustInitErrorFeatureProfiles,
            ],
          ),
          const SizedBox(height: 16),
          _buildSection(
            context,
            icon: Icons.lightbulb_outline_rounded,
            title: l10n.rustInitErrorSuggestions,
            items: [
              l10n.rustInitErrorSuggestion1,
              l10n.rustInitErrorSuggestion2,
              l10n.rustInitErrorSuggestion3,
            ],
          ),
        ],
      ),
      actions: [
        FilledButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l10n.rustInitErrorRetry),
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
