import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:go_router/go_router.dart';
import 'package:veloguard/src/providers/general_settings_provider.dart';
import 'package:veloguard/src/widgets/adaptive_list_tile.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';

class AdvancedConfigScreen extends StatefulWidget {
  const AdvancedConfigScreen({super.key});

  @override
  State<AdvancedConfigScreen> createState() => _AdvancedConfigScreenState();
}

class _AdvancedConfigScreenState extends State<AdvancedConfigScreen> {
  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    return Consumer<GeneralSettingsProvider>(
      builder: (context, settings, child) {
        return Scaffold(
          appBar: AppBar(
            title: Text(l10n?.advancedConfig ?? 'Advanced Config'),
            leading: IconButton(
              icon: const Icon(Icons.arrow_back),
              onPressed: () => context.go('/settings'),
            ),
          ),
          body: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              // TCP 设置
              _buildSectionHeader(
                context,
                l10n?.tcpSettings ?? 'TCP Settings',
                Icons.cable_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.tcpKeepAlive ?? 'TCP Keep-Alive'),
                      subtitle: Text(
                        '${settings.tcpKeepAliveInterval} ${l10n?.seconds ?? "s"}',
                      ),
                      leading: Icon(
                        Icons.timer_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showNumberDialog(
                        context,
                        l10n?.tcpKeepAliveInterval ?? 'TCP Keep-Alive Interval',
                        settings.tcpKeepAliveInterval,
                        (v) => settings.setTcpKeepAliveInterval(v),
                        suffix: l10n?.seconds ?? 's',
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.tcpConcurrent ?? 'TCP Concurrent'),
                      subtitle: Text(
                        l10n?.tcpConcurrentDesc ??
                            'Enable TCP concurrent connections',
                      ),
                      leading: Icon(
                        Icons.multiple_stop_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: settings.tcpConcurrent,
                        onChanged: (v) => settings.setTcpConcurrent(v),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // 测速设置
              _buildSectionHeader(
                context,
                l10n?.speedTestSettings ?? 'Speed Test Settings',
                Icons.speed_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.speedTestUrl ?? 'Speed Test URL'),
                      subtitle: Text(
                        settings.speedTestUrl,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      leading: Icon(
                        Icons.link_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showTextDialog(
                        context,
                        l10n?.speedTestUrl ?? 'Speed Test URL',
                        settings.speedTestUrl,
                        (v) => settings.setSpeedTestUrl(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.unifiedDelay ?? 'Unified Delay'),
                      subtitle: Text(
                        l10n?.unifiedDelayDesc ??
                            'Use unified delay calculation',
                      ),
                      leading: Icon(
                        Icons.sync_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: settings.unifiedDelay,
                        onChanged: (v) => settings.setUnifiedDelay(v),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // DNS 相关
              _buildSectionHeader(
                context,
                l10n?.dnsRelated ?? 'DNS Related',
                Icons.dns_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.appendSystemDns ?? 'Append System DNS'),
                      subtitle: Text(
                        l10n?.appendSystemDnsDesc ??
                            'Append system DNS to nameserver',
                      ),
                      leading: Icon(
                        Icons.add_circle_outline,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: settings.appendSystemDns,
                        onChanged: (v) => settings.setAppendSystemDns(v),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // 进程相关
              _buildSectionHeader(
                context,
                l10n?.processRelated ?? 'Process Related',
                Icons.memory_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.findProcess ?? 'Find Process'),
                      subtitle: Text(
                        l10n?.findProcessDesc ??
                            'Enable process name matching rules',
                      ),
                      leading: Icon(
                        Icons.search_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: settings.findProcess,
                        onChanged: (v) => settings.setFindProcess(v),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // 信息卡片
              _buildInfoCard(context, l10n),

              const SizedBox(height: 32),
            ],
          ),
        );
      },
    );
  }

  Widget _buildSectionHeader(
    BuildContext context,
    String title,
    IconData icon,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12, left: 4),
      child: Row(
        children: [
          Icon(icon, size: 20, color: colorScheme.primary),
          const SizedBox(width: 8),
          Text(
            title,
            style: textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
              color: colorScheme.primary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoCard(BuildContext context, AppLocalizations? l10n) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: colorScheme.primaryContainer.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: colorScheme.primary.withValues(alpha: 0.2)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: colorScheme.primary.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(Icons.info_outline, color: colorScheme.primary),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  l10n?.info ?? 'Tip',
                  style: textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600,
                    color: colorScheme.primary,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  l10n?.restartServiceDesc ??
                      'Changes require service restart to take effect',
                  style: textTheme.bodySmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showNumberDialog(
    BuildContext context,
    String title,
    int currentValue,
    Function(int) onSave, {
    String? suffix,
  }) {
    final controller = TextEditingController(text: currentValue.toString());
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          keyboardType: TextInputType.number,
          decoration: InputDecoration(
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
            filled: true,
            fillColor: colorScheme.surfaceContainerHighest,
            suffixText: suffix,
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n?.cancel ?? 'Cancel'),
          ),
          FilledButton(
            onPressed: () {
              final value = int.tryParse(controller.text);
              if (value != null && value > 0) {
                onSave(value);
                Navigator.pop(context);
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(
                      l10n?.validPortHint ?? 'Please enter a valid number',
                    ),
                  ),
                );
              }
            },
            child: Text(l10n?.save ?? 'Save'),
          ),
        ],
      ),
    );
  }

  void _showTextDialog(
    BuildContext context,
    String title,
    String currentValue,
    Function(String) onSave,
  ) {
    final controller = TextEditingController(text: currentValue);
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          decoration: InputDecoration(
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
            filled: true,
            fillColor: colorScheme.surfaceContainerHighest,
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n?.cancel ?? 'Cancel'),
          ),
          FilledButton(
            onPressed: () {
              onSave(controller.text);
              Navigator.pop(context);
            },
            child: Text(l10n?.save ?? 'Save'),
          ),
        ],
      ),
    );
  }
}
