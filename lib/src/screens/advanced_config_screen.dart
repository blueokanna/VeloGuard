import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:go_router/go_router.dart';
import 'package:veloguard/src/providers/general_settings_provider.dart';
import 'package:veloguard/src/widgets/adaptive_list_tile.dart';

class AdvancedConfigScreen extends StatefulWidget {
  const AdvancedConfigScreen({super.key});

  @override
  State<AdvancedConfigScreen> createState() => _AdvancedConfigScreenState();
}

class _AdvancedConfigScreenState extends State<AdvancedConfigScreen> {
  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;

    return Consumer<GeneralSettingsProvider>(
      builder: (context, settings, child) {
        return Scaffold(
          appBar: AppBar(
            title: const Text('高级配置'),
            leading: IconButton(
              icon: const Icon(Icons.arrow_back),
              onPressed: () => context.go('/settings'),
            ),
          ),
          body: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              // TCP 设置
              _buildSectionHeader(context, 'TCP 设置', Icons.cable_outlined),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: const Text('TCP Keep-Alive'),
                      subtitle: Text('${settings.tcpKeepAliveInterval} 秒'),
                      leading: Icon(
                        Icons.timer_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showNumberDialog(
                        context,
                        'TCP Keep-Alive 间隔',
                        settings.tcpKeepAliveInterval,
                        (v) => settings.setTcpKeepAliveInterval(v),
                        suffix: '秒',
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: const Text('TCP 并发'),
                      subtitle: const Text('启用 TCP 并发连接'),
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
              _buildSectionHeader(context, '测速设置', Icons.speed_outlined),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: const Text('测速 URL'),
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
                        '测速 URL',
                        settings.speedTestUrl,
                        (v) => settings.setSpeedTestUrl(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: const Text('统一延迟'),
                      subtitle: const Text('使用统一的延迟计算方式'),
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
              _buildSectionHeader(context, 'DNS 相关', Icons.dns_outlined),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: const Text('追加系统 DNS'),
                      subtitle: const Text('将系统 DNS 追加到 nameserver'),
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
              _buildSectionHeader(context, '进程相关', Icons.memory_outlined),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: const Text('查找进程'),
                      subtitle: const Text('启用进程名匹配规则'),
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
              _buildInfoCard(context),

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

  Widget _buildInfoCard(BuildContext context) {
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
                  '提示',
                  style: textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600,
                    color: colorScheme.primary,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '修改高级配置后需要重启服务才能生效',
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
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () {
              final value = int.tryParse(controller.text);
              if (value != null && value > 0) {
                onSave(value);
                Navigator.pop(context);
              } else {
                ScaffoldMessenger.of(
                  context,
                ).showSnackBar(const SnackBar(content: Text('请输入有效的数字')));
              }
            },
            child: const Text('保存'),
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
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () {
              onSave(controller.text);
              Navigator.pop(context);
            },
            child: const Text('保存'),
          ),
        ],
      ),
    );
  }
}
