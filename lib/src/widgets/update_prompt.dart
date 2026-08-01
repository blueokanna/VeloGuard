import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/providers/update_provider.dart';

class UpdatePromptHost extends StatefulWidget {
  const UpdatePromptHost({required this.child, super.key});

  final Widget child;

  @override
  State<UpdatePromptHost> createState() => _UpdatePromptHostState();
}

class _UpdatePromptHostState extends State<UpdatePromptHost> {
  String? _shownTag;

  @override
  Widget build(BuildContext context) {
    final updater = context.watch<UpdateProvider>();
    final update = updater.availableUpdate;
    if (update != null && _shownTag != update.tag) {
      _shownTag = update.tag;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) _showUpdateDialog(updater);
      });
    }
    return widget.child;
  }

  Future<void> _showUpdateDialog(UpdateProvider updater) async {
    final update = updater.availableUpdate;
    if (update == null) return;
    final l10n = AppLocalizations.of(context);
    final publishedAt = update.publishedAt
        .toLocal()
        .toString()
        .split('.')
        .first;
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        icon: const Icon(Icons.system_update_alt_rounded),
        title: Text('VeloGuard ${update.version}'),
        content: Text(
          l10n?.publishedOn(publishedAt) ?? 'Published $publishedAt',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: Text(l10n?.cancel ?? 'Cancel'),
          ),
          FilledButton.icon(
            onPressed: () {
              Navigator.pop(dialogContext);
              updater.downloadAndInstall();
            },
            icon: const Icon(Icons.download_rounded),
            label: Text(l10n?.download ?? 'Download'),
          ),
        ],
      ),
    );
  }
}
