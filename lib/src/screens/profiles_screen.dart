import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/providers/profiles_provider.dart';
import 'package:veloguard/src/services/storage_service.dart';

class ProfilesScreen extends StatefulWidget {
  const ProfilesScreen({super.key});

  @override
  State<ProfilesScreen> createState() => _ProfilesScreenState();
}

class _ProfilesScreenState extends State<ProfilesScreen> {
  @override
  void initState() {
    super.initState();
    // Load profiles on init
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<ProfilesProvider>().loadProfiles();
    });
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);

    return Consumer<ProfilesProvider>(
      builder: (context, profilesProvider, child) {
        return Scaffold(
          appBar: AppBar(
            title: Text(l10n?.profiles ?? 'Profiles'),
            actions: [
              if (profilesProvider.isLoading)
                const Padding(
                  padding: EdgeInsets.all(16),
                  child: SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                )
              else
                IconButton(
                  icon: const Icon(Icons.add),
                  tooltip: l10n?.addProfile ?? 'Add Profile',
                  onPressed: () => _showAddProfileDialog(context),
                ),
            ],
          ),
          body: profilesProvider.profiles.isEmpty
              ? _buildEmptyState(context, l10n)
              : ListView.builder(
                  padding: const EdgeInsets.all(16),
                  itemCount: profilesProvider.profiles.length,
                  itemBuilder: (context, index) {
                    return _buildProfileCard(
                      context,
                      profilesProvider.profiles[index],
                      profilesProvider,
                      l10n,
                    );
                  },
                ),
          floatingActionButton: FloatingActionButton.extended(
            onPressed: () => _showAddProfileDialog(context),
            icon: const Icon(Icons.add),
            label: Text(l10n?.addProfile ?? 'Add Profile'),
          ),
        );
      },
    );
  }

  Widget _buildEmptyState(BuildContext context, AppLocalizations? l10n) {
    final colorScheme = Theme.of(context).colorScheme;

    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.folder_off_outlined,
            size: 72,
            color: colorScheme.onSurfaceVariant.withValues(alpha: 0.5),
          ),
          const SizedBox(height: 16),
          Text(
            l10n?.noProfiles ?? 'No profiles',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            l10n?.addProfileHint ?? 'Tap + to add a configuration profile',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildProfileCard(
    BuildContext context,
    ProfileConfig profile,
    ProfilesProvider provider,
    AppLocalizations? l10n,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final isActive = profile.id == provider.activeProfileId;

    return Card(
      elevation: 0,
      color: isActive
          ? colorScheme.primaryContainer
          : colorScheme.surfaceContainerLow,
      margin: const EdgeInsets.only(bottom: 12),
      child: InkWell(
        onTap: () => provider.selectProfile(profile.id),
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: isActive
                          ? colorScheme.primary
                          : colorScheme.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Icon(
                      _getProfileTypeIcon(profile.type),
                      color: isActive
                          ? colorScheme.onPrimary
                          : colorScheme.onSurfaceVariant,
                      size: 20,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          profile.name,
                          style: textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.w600,
                            color: isActive
                                ? colorScheme.onPrimaryContainer
                                : colorScheme.onSurface,
                          ),
                        ),
                        if (profile.lastUpdated != null)
                          Text(
                            '${l10n?.lastUpdated ?? 'Updated'}: ${_formatDate(profile.lastUpdated!)}',
                            style: textTheme.bodySmall?.copyWith(
                              color: isActive
                                  ? colorScheme.onPrimaryContainer.withValues(
                                      alpha: 0.7,
                                    )
                                  : colorScheme.onSurfaceVariant,
                            ),
                          ),
                      ],
                    ),
                  ),
                  if (isActive)
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: colorScheme.primary,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(
                        l10n?.inUse ?? 'In Use',
                        style: textTheme.labelSmall?.copyWith(
                          color: colorScheme.onPrimary,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                  PopupMenuButton<String>(
                    icon: Icon(
                      Icons.more_vert,
                      color: isActive
                          ? colorScheme.onPrimaryContainer
                          : colorScheme.onSurfaceVariant,
                    ),
                    onSelected: (value) =>
                        _handleProfileAction(profile, value, provider),
                    itemBuilder: (context) => [
                      PopupMenuItem(
                        value: 'update',
                        child: ListTile(
                          leading: const Icon(Icons.refresh),
                          title: Text(l10n?.updateProfile ?? 'Update'),
                          contentPadding: EdgeInsets.zero,
                          visualDensity: VisualDensity.compact,
                        ),
                      ),
                      PopupMenuItem(
                        value: 'edit',
                        child: ListTile(
                          leading: const Icon(Icons.edit),
                          title: Text(l10n?.editProfile ?? 'Edit'),
                          contentPadding: EdgeInsets.zero,
                          visualDensity: VisualDensity.compact,
                        ),
                      ),
                      const PopupMenuDivider(),
                      PopupMenuItem(
                        value: 'delete',
                        child: ListTile(
                          leading: Icon(Icons.delete, color: colorScheme.error),
                          title: Text(
                            l10n?.deleteProfile ?? 'Delete',
                            style: TextStyle(color: colorScheme.error),
                          ),
                          contentPadding: EdgeInsets.zero,
                          visualDensity: VisualDensity.compact,
                        ),
                      ),
                    ],
                  ),
                ],
              ),

              // Traffic info if available
              if (profile.usedTraffic != null &&
                  profile.totalTraffic != null) ...[
                const SizedBox(height: 12),
                _buildTrafficProgress(context, profile, isActive),
              ],

              // Expiry info
              if (profile.expiresAt != null) ...[
                const SizedBox(height: 8),
                Row(
                  children: [
                    Icon(
                      Icons.schedule,
                      size: 14,
                      color: isActive
                          ? colorScheme.onPrimaryContainer.withValues(
                              alpha: 0.7,
                            )
                          : colorScheme.onSurfaceVariant,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      '${l10n?.expiresOn ?? 'Expires'}: ${_formatDate(profile.expiresAt!)}',
                      style: textTheme.bodySmall?.copyWith(
                        color: isActive
                            ? colorScheme.onPrimaryContainer.withValues(
                                alpha: 0.7,
                              )
                            : colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTrafficProgress(
    BuildContext context,
    ProfileConfig profile,
    bool isActive,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    final used = profile.usedTraffic ?? 0;
    final total = profile.totalTraffic ?? 1;
    final progress = used / total;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              _formatTraffic(used),
              style: textTheme.bodySmall?.copyWith(
                color: isActive
                    ? colorScheme.onPrimaryContainer
                    : colorScheme.onSurface,
                fontWeight: FontWeight.w500,
              ),
            ),
            Text(
              _formatTraffic(total),
              style: textTheme.bodySmall?.copyWith(
                color: isActive
                    ? colorScheme.onPrimaryContainer.withValues(alpha: 0.7)
                    : colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        LinearProgressIndicator(
          value: progress,
          backgroundColor: isActive
              ? colorScheme.onPrimaryContainer.withValues(alpha: 0.2)
              : colorScheme.surfaceContainerHighest,
          valueColor: AlwaysStoppedAnimation<Color>(
            progress > 0.9
                ? colorScheme.error
                : (isActive ? colorScheme.primary : colorScheme.primary),
          ),
        ),
      ],
    );
  }

  void _showAddProfileDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final colorScheme = Theme.of(context).colorScheme;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Center(
                  child: Container(
                    width: 40,
                    height: 4,
                    decoration: BoxDecoration(
                      color: colorScheme.onSurfaceVariant.withValues(
                        alpha: 0.3,
                      ),
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
                ),
                const SizedBox(height: 20),
                Text(
                  l10n?.addProfile ?? 'Add Profile',
                  style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 24),

                // URL option
                _buildAddOption(
                  context,
                  icon: Icons.link,
                  title: l10n?.importUrl ?? 'Import from URL',
                  subtitle: l10n?.importUrlDesc ?? 'Enter subscription URL',
                  onTap: () {
                    Navigator.pop(context);
                    _showUrlInputDialog(context);
                  },
                ),
                const SizedBox(height: 12),

                // File option
                _buildAddOption(
                  context,
                  icon: Icons.folder_open,
                  title: l10n?.importFile ?? 'Import File',
                  subtitle:
                      l10n?.importFileDesc ??
                      'Select configuration file from storage',
                  onTap: () {
                    Navigator.pop(context);
                    _handleFileImport();
                  },
                ),
                const SizedBox(height: 12),

                // Clipboard option
                _buildAddOption(
                  context,
                  icon: Icons.content_paste,
                  title: l10n?.importClipboard ?? 'Import from Clipboard',
                  subtitle:
                      l10n?.importClipboardDesc ??
                      'Paste configuration from clipboard',
                  onTap: () {
                    Navigator.pop(context);
                    _handleClipboardImport();
                  },
                ),
                const SizedBox(height: 16),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildAddOption(
    BuildContext context, {
    required IconData icon,
    required String title,
    required String subtitle,
    required VoidCallback onTap,
  }) {
    final colorScheme = Theme.of(context).colorScheme;

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      child: ListTile(
        leading: Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: colorScheme.primaryContainer,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: colorScheme.onPrimaryContainer),
        ),
        title: Text(title),
        subtitle: Text(subtitle),
        trailing: const Icon(Icons.chevron_right),
        onTap: onTap,
      ),
    );
  }

  void _showUrlInputDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final urlController = TextEditingController();
    final nameController = TextEditingController();
    // Get provider reference at the beginning, before showing dialog
    final provider = context.read<ProfilesProvider>();

    showDialog(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          title: Text(l10n?.importUrl ?? 'Import from URL'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nameController,
                decoration: InputDecoration(
                  labelText: l10n?.profileName ?? 'Profile Name',
                  hintText:
                      l10n?.profileNameHint ?? 'Enter a name for this profile',
                  prefixIcon: const Icon(Icons.label),
                  border: const OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: urlController,
                decoration: InputDecoration(
                  labelText: l10n?.subscriptionUrl ?? 'Subscription URL',
                  hintText: 'https://',
                  prefixIcon: const Icon(Icons.link),
                  border: const OutlineInputBorder(),
                ),
                keyboardType: TextInputType.url,
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(l10n?.cancel ?? 'Cancel'),
            ),
            FilledButton(
              onPressed: () async {
                if (urlController.text.isNotEmpty) {
                  final name = nameController.text.isEmpty
                      ? 'Profile ${provider.profiles.length + 1}'
                      : nameController.text;
                  final url = urlController.text;

                  Navigator.pop(dialogContext);

                  final success = await provider.addProfileFromUrl(name, url);
                  if (!mounted) return;

                  if (success) {
                    _showSnackBar('Profile added successfully');
                  } else {
                    _showSnackBar(
                      'Failed to import: ${provider.error ?? "Unknown error"}',
                    );
                  }
                }
              },
              child: Text(l10n?.import_ ?? 'Import'),
            ),
          ],
        );
      },
    );
  }

  void _handleFileImport() {
    // TODO: Implement file picker
    _showSnackBar('File import not implemented yet');
  }

  void _handleClipboardImport() async {
    // Get provider reference before any async operations
    final provider = context.read<ProfilesProvider>();

    try {
      final data = await Clipboard.getData(Clipboard.kTextPlain);
      if (!mounted) return;

      if (data?.text != null && data!.text!.isNotEmpty) {
        final name = 'Clipboard ${DateTime.now().millisecondsSinceEpoch}';

        // Check if it's a URL or raw config
        if (data.text!.startsWith('http://') ||
            data.text!.startsWith('https://')) {
          final success = await provider.addProfileFromUrl(name, data.text!);
          if (!mounted) return;

          if (success) {
            _showSnackBar('Profile added successfully');
          } else {
            _showSnackBar(
              'Failed to import: ${provider.error ?? "Unknown error"}',
            );
          }
        } else {
          // Treat as raw config content
          final success = await provider.addProfileFromFile(
            name,
            'clipboard',
            data.text!,
          );
          if (!mounted) return;

          if (success) {
            _showSnackBar('Profile added successfully');
          } else {
            _showSnackBar(
              'Failed to import: ${provider.error ?? "Unknown error"}',
            );
          }
        }
      } else {
        _showSnackBar('Clipboard is empty');
      }
    } catch (e) {
      if (!mounted) return;
      _showSnackBar('Failed to read clipboard');
    }
  }

  void _handleProfileAction(
    ProfileConfig profile,
    String action,
    ProfilesProvider provider,
  ) async {
    final l10n = AppLocalizations.of(context);

    switch (action) {
      case 'update':
        final success = await provider.updateProfile(profile.id);
        if (!mounted) return;
        if (success) {
          _showSnackBar('Profile updated successfully');
        } else {
          _showSnackBar(
            'Failed to update: ${provider.error ?? "Unknown error"}',
          );
        }
        break;
      case 'edit':
        _showEditProfileDialog(context, profile, provider);
        break;
      case 'delete':
        showDialog(
          context: context,
          builder: (dialogContext) {
            return AlertDialog(
              title: Text(l10n?.deleteProfile ?? 'Delete Profile'),
              content: Text(
                l10n?.deleteProfileConfirm ??
                    'Are you sure you want to delete this profile?',
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(dialogContext),
                  child: Text(l10n?.cancel ?? 'Cancel'),
                ),
                FilledButton(
                  style: FilledButton.styleFrom(
                    backgroundColor: Theme.of(context).colorScheme.error,
                  ),
                  onPressed: () async {
                    Navigator.pop(dialogContext);
                    await provider.deleteProfile(profile.id);
                    if (!mounted) return;
                    _showSnackBar('Profile deleted');
                  },
                  child: Text(l10n?.delete ?? 'Delete'),
                ),
              ],
            );
          },
        );
        break;
    }
  }

  void _showEditProfileDialog(
    BuildContext context,
    ProfileConfig profile,
    ProfilesProvider provider,
  ) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
      ),
      builder: (context) => _EditProfileSheet(
        profile: profile,
        provider: provider,
        onSaved: () {
          _showSnackBar('Profile saved');
        },
      ),
    );
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }

  IconData _getProfileTypeIcon(String type) {
    switch (type) {
      case 'url':
        return Icons.link;
      case 'file':
        return Icons.insert_drive_file;
      case 'qrcode':
        return Icons.qr_code;
      default:
        return Icons.description;
    }
  }

  String _formatDate(DateTime date) {
    return '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')} ${date.hour.toString().padLeft(2, '0')}:${date.minute.toString().padLeft(2, '0')}';
  }

  String _formatTraffic(int bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var value = bytes.toDouble();
    var unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }
    // Always show 2 decimal places for GB and above
    if (unitIndex >= 3) {
      return '${value.toStringAsFixed(2)} ${units[unitIndex]}';
    }
    return '${value.toStringAsFixed(value < 10 ? 1 : 0)} ${units[unitIndex]}';
  }
}

/// Edit Profile Bottom Sheet - Material Design 3 Expressive
class _EditProfileSheet extends StatefulWidget {
  final ProfileConfig profile;
  final ProfilesProvider provider;
  final VoidCallback? onSaved;

  const _EditProfileSheet({
    required this.profile,
    required this.provider,
    this.onSaved,
  });

  @override
  State<_EditProfileSheet> createState() => _EditProfileSheetState();
}

class _EditProfileSheetState extends State<_EditProfileSheet> {
  late TextEditingController _nameController;
  late TextEditingController _urlController;
  late TextEditingController _intervalController;
  late bool _autoUpdate;
  bool _isSaving = false;
  int? _configSize;

  @override
  void initState() {
    super.initState();
    _nameController = TextEditingController(text: widget.profile.name);
    _urlController = TextEditingController(
      text: widget.profile.type == 'url' ? widget.profile.source : '',
    );
    _intervalController = TextEditingController(
      text: widget.profile.autoUpdateInterval.toString(),
    );
    _autoUpdate = widget.profile.autoUpdate;
    _loadConfigSize();
  }

  Future<void> _loadConfigSize() async {
    final size = await widget.provider.getProfileConfigSize(widget.profile.id);
    if (mounted) {
      setState(() {
        _configSize = size;
      });
    }
  }

  @override
  void dispose() {
    _nameController.dispose();
    _urlController.dispose();
    _intervalController.dispose();
    super.dispose();
  }

  String _formatFileSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
  }

  String _formatTimeAgo(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);

    if (difference.inMinutes < 1) {
      return '刚刚';
    } else if (difference.inMinutes < 60) {
      return '${difference.inMinutes} 分钟前';
    } else if (difference.inHours < 24) {
      return '${difference.inHours} 小时前';
    } else if (difference.inDays < 30) {
      return '${difference.inDays} 天前';
    } else {
      return '${dateTime.year}-${dateTime.month.toString().padLeft(2, '0')}-${dateTime.day.toString().padLeft(2, '0')}';
    }
  }

  Future<void> _handleSave() async {
    if (_nameController.text.trim().isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('名称不能为空')));
      return;
    }

    setState(() => _isSaving = true);

    try {
      final interval = int.tryParse(_intervalController.text) ?? 180;

      final success = await widget.provider.editProfile(
        id: widget.profile.id,
        name: _nameController.text.trim(),
        source: widget.profile.type == 'url'
            ? _urlController.text.trim()
            : null,
        autoUpdate: _autoUpdate,
        autoUpdateInterval: interval,
      );

      if (!mounted) return;

      if (success) {
        widget.onSaved?.call();
        Navigator.pop(context);
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('保存失败: ${widget.provider.error ?? "未知错误"}')),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isSaving = false);
      }
    }
  }

  Future<void> _handleUpdate() async {
    if (widget.profile.type != 'url') return;

    setState(() => _isSaving = true);

    try {
      final success = await widget.provider.updateProfile(widget.profile.id);
      if (!mounted) return;

      if (success) {
        await _loadConfigSize();
        if (!mounted) return;
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('配置已更新')));
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('更新失败: ${widget.provider.error ?? "未知错误"}')),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isSaving = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final isUrlType = widget.profile.type == 'url';

    return Padding(
      padding: EdgeInsets.only(
        bottom: MediaQuery.of(context).viewInsets.bottom,
      ),
      child: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 16, 24, 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Drag handle
              Center(
                child: Container(
                  width: 32,
                  height: 4,
                  decoration: BoxDecoration(
                    color: colorScheme.onSurfaceVariant.withValues(alpha: 0.4),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              const SizedBox(height: 16),

              // Header
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    '编辑配置',
                    style: textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close),
                    style: IconButton.styleFrom(
                      backgroundColor: colorScheme.surfaceContainerHighest,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 24),

              // Name field
              TextField(
                controller: _nameController,
                decoration: InputDecoration(
                  labelText: '名称',
                  hintText: '输入配置名称',
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                  filled: true,
                  fillColor: colorScheme.surfaceContainerLow,
                ),
              ),
              const SizedBox(height: 16),

              // URL field (only for URL type)
              if (isUrlType) ...[
                TextField(
                  controller: _urlController,
                  decoration: InputDecoration(
                    labelText: 'URL',
                    hintText: 'https://',
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                    filled: true,
                    fillColor: colorScheme.surfaceContainerLow,
                  ),
                  keyboardType: TextInputType.url,
                  maxLines: 1,
                ),
                const SizedBox(height: 20),

                // Auto update switch
                Container(
                  decoration: BoxDecoration(
                    color: colorScheme.surfaceContainerLow,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: SwitchListTile(
                    title: const Text('自动更新'),
                    value: _autoUpdate,
                    onChanged: (value) {
                      setState(() => _autoUpdate = value);
                    },
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Auto update interval (only show when auto update is enabled)
                AnimatedSize(
                  duration: const Duration(milliseconds: 200),
                  child: _autoUpdate
                      ? Column(
                          children: [
                            TextField(
                              controller: _intervalController,
                              decoration: InputDecoration(
                                labelText: '自动更新间隔（分钟）',
                                hintText: '180',
                                border: OutlineInputBorder(
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                filled: true,
                                fillColor: colorScheme.surfaceContainerLow,
                              ),
                              keyboardType: TextInputType.number,
                            ),
                            const SizedBox(height: 20),
                          ],
                        )
                      : const SizedBox.shrink(),
                ),
              ],

              // Config info section
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: colorScheme.surfaceContainerLow,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '配置',
                      style: textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        if (_configSize != null) ...[
                          Text(
                            _formatFileSize(_configSize!),
                            style: textTheme.bodyMedium?.copyWith(
                              color: colorScheme.onSurfaceVariant,
                            ),
                          ),
                          Text(
                            '  ·  ',
                            style: textTheme.bodyMedium?.copyWith(
                              color: colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                        if (widget.profile.lastUpdated != null)
                          Text(
                            _formatTimeAgo(widget.profile.lastUpdated!),
                            style: textTheme.bodyMedium?.copyWith(
                              color: colorScheme.onSurfaceVariant,
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // Action buttons
                    Row(
                      children: [
                        // Edit config button
                        OutlinedButton.icon(
                          onPressed: () {
                            // TODO: Open config editor
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(content: Text('配置编辑器即将推出')),
                            );
                          },
                          icon: const Icon(Icons.edit_outlined, size: 18),
                          label: const Text('编辑'),
                          style: OutlinedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 16,
                              vertical: 10,
                            ),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(20),
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),

                        // Update button (only for URL type)
                        if (isUrlType)
                          OutlinedButton.icon(
                            onPressed: _isSaving ? null : _handleUpdate,
                            icon: _isSaving
                                ? SizedBox(
                                    width: 18,
                                    height: 18,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                      color: colorScheme.primary,
                                    ),
                                  )
                                : const Icon(
                                    Icons.cloud_upload_outlined,
                                    size: 18,
                                  ),
                            label: const Text('上传'),
                            style: OutlinedButton.styleFrom(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 10,
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(20),
                              ),
                            ),
                          ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // Save button
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: _isSaving ? null : _handleSave,
                  icon: _isSaving
                      ? SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: colorScheme.onPrimary,
                          ),
                        )
                      : const Icon(Icons.save_outlined),
                  label: const Text('保存'),
                  style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 8),
            ],
          ),
        ),
      ),
    );
  }
}
