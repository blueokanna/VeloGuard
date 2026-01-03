import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:veloguard/src/providers/app_state_provider.dart';
import 'package:veloguard/src/rust/types.dart';
import 'package:veloguard/src/utils/platform_utils.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';

class ConnectionsScreen extends StatefulWidget {
  const ConnectionsScreen({super.key});

  @override
  State<ConnectionsScreen> createState() => _ConnectionsScreenState();
}

class _ConnectionsScreenState extends State<ConnectionsScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<AppStateProvider>().refreshStatus();
    });
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(
          l10n?.connections ?? '连接',
          style: textTheme.headlineMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        actions: [
          Consumer<AppStateProvider>(
            builder: (context, appState, child) {
              if (appState.activeConnections.isNotEmpty) {
                return TextButton.icon(
                  onPressed: () => _showCloseAllDialog(context),
                  icon: const Icon(Icons.close),
                  label: Text(l10n?.closeAll ?? '关闭全部'),
                  style: TextButton.styleFrom(
                    foregroundColor: colorScheme.error,
                  ),
                );
              }
              return const SizedBox.shrink();
            },
          ),
          IconButton(
            icon: const Icon(Icons.refresh_outlined),
            tooltip: l10n?.refresh ?? '刷新',
            onPressed: () => context.read<AppStateProvider>().refreshStatus(),
          ),
        ],
      ),
      body: Consumer<AppStateProvider>(
        builder: (context, appState, child) {
          if (!appState.isServiceRunning) {
            return _buildNotRunningView(context);
          }

          if (appState.activeConnections.isEmpty) {
            return _buildEmptyView(context);
          }

          return _buildConnectionsList(context, appState);
        },
      ),
    );
  }

  Widget _buildNotRunningView(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);
    final spacing = ResponsiveUtils.getSpacing(context);
    final iconSize = ResponsiveUtils.getIconSize(context, large: true);

    return Center(
      child: Padding(
        padding: ResponsiveUtils.getResponsivePadding(context),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: EdgeInsets.all(spacing * 3),
              decoration: BoxDecoration(
                color: colorScheme.errorContainer.withValues(alpha: 0.3),
                shape: BoxShape.circle,
              ),
              child: Icon(
                Icons.power_off_rounded,
                size: iconSize * 2,
                color: colorScheme.error,
              ),
            ),
            SizedBox(height: spacing * 3),
            Text(
              l10n?.serviceNotRunningTitle ?? '服务未运行',
              style: textTheme.headlineSmall?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
            SizedBox(height: spacing),
            Text(
              l10n?.startServiceToViewConnections2 ?? '启动 VeloGuard 服务以查看活动连接',
              style: textTheme.bodyMedium?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEmptyView(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);
    final spacing = ResponsiveUtils.getSpacing(context);
    final iconSize = ResponsiveUtils.getIconSize(context, large: true);

    return Center(
      child: Padding(
        padding: ResponsiveUtils.getResponsivePadding(context),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: EdgeInsets.all(spacing * 3),
              decoration: BoxDecoration(
                color: colorScheme.primaryContainer.withValues(alpha: 0.3),
                shape: BoxShape.circle,
              ),
              child: Icon(
                Icons.link_off_rounded,
                size: iconSize * 2,
                color: colorScheme.primary,
              ),
            ),
            SizedBox(height: spacing * 3),
            Text(
              l10n?.noActiveConnectionsTitle ?? '无活动连接',
              style: textTheme.headlineSmall?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
            SizedBox(height: spacing),
            Text(
              l10n?.connectionsWillAppear2 ?? '当数据流经代理时，活动连接将显示在此处',
              style: textTheme.bodyMedium?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildConnectionsList(
    BuildContext context,
    AppStateProvider appState,
  ) {
    final connections = appState.activeConnections;
    final padding = ResponsiveUtils.getResponsivePadding(context);
    final spacing = ResponsiveUtils.getSpacing(context);

    return RefreshIndicator(
      onRefresh: () async {
        await context.read<AppStateProvider>().refreshStatus();
      },
      child: CustomScrollView(
        physics: PlatformUtils.getScrollPhysics(context),
        slivers: [
          SliverToBoxAdapter(
            child: Padding(
              padding: EdgeInsets.fromLTRB(
                padding.left,
                spacing,
                padding.right,
                spacing * 2,
              ),
              child: _buildStatsHeader(context, appState),
            ),
          ),
          SliverPadding(
            padding: EdgeInsets.symmetric(horizontal: padding.left),
            sliver: SliverList(
              delegate: SliverChildBuilderDelegate((context, index) {
                final connection = connections[index];
                return StaggeredListItem(
                  index: index,
                  delay: const Duration(milliseconds: 30),
                  duration: AnimationUtils.durationMedium2,
                  child: Padding(
                    padding: EdgeInsets.only(bottom: spacing * 1.5),
                    child: _buildConnectionCard(context, connection, appState),
                  ),
                );
              }, childCount: connections.length),
            ),
          ),
          SliverToBoxAdapter(child: SizedBox(height: spacing * 2)),
        ],
      ),
    );
  }

  Widget _buildStatsHeader(BuildContext context, AppStateProvider appState) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final cardPadding = ResponsiveUtils.getCardPadding(context);

    return Container(
      padding: cardPadding,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            colorScheme.primaryContainer.withValues(alpha: 0.5),
            colorScheme.secondaryContainer.withValues(alpha: 0.3),
          ],
        ),
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(color: colorScheme.primary.withValues(alpha: 0.2)),
      ),
      child: Row(
        children: [
          Expanded(
            child: _buildStatItem(
              context,
              icon: Icons.link_rounded,
              label: l10n?.activeConnections ?? '活动连接',
              value: appState.activeConnections.length.toString(),
              color: colorScheme.primary,
            ),
          ),
          Container(width: 1, height: 40, color: colorScheme.outlineVariant),
          Expanded(
            child: _buildStatItem(
              context,
              icon: Icons.arrow_upward_rounded,
              label: l10n?.totalUploadShort ?? '总上传',
              value: appState.getFormattedTraffic(appState.totalUploadBytes),
              color: colorScheme.tertiary,
            ),
          ),
          Container(width: 1, height: 40, color: colorScheme.outlineVariant),
          Expanded(
            child: _buildStatItem(
              context,
              icon: Icons.arrow_downward_rounded,
              label: l10n?.totalDownloadShort ?? '总下载',
              value: appState.getFormattedTraffic(appState.totalDownloadBytes),
              color: colorScheme.secondary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatItem(
    BuildContext context, {
    required IconData icon,
    required String label,
    required String value,
    required Color color,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final colorScheme = Theme.of(context).colorScheme;
    final iconSize = ResponsiveUtils.getIconSize(context);
    final spacing = ResponsiveUtils.getSpacing(context);

    return Column(
      children: [
        Icon(icon, size: iconSize * 0.9, color: color),
        SizedBox(height: spacing * 0.5),
        Text(
          value,
          style: textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w700,
            color: colorScheme.onSurface,
          ),
        ),
        Text(
          label,
          style: textTheme.bodySmall?.copyWith(
            color: colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  Widget _buildConnectionCard(
    BuildContext context,
    ActiveConnection connection,
    AppStateProvider appState,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final cardPadding = ResponsiveUtils.getCardPadding(context);
    final spacing = ResponsiveUtils.getSpacing(context);

    Color protocolColor;
    switch (connection.protocol.toUpperCase()) {
      case 'HTTPS':
        protocolColor = Colors.green;
        break;
      case 'HTTP':
        protocolColor = Colors.orange;
        break;
      case 'SOCKS5':
        protocolColor = Colors.blue;
        break;
      default:
        protocolColor = colorScheme.primary;
    }

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
        side: BorderSide(
          color: colorScheme.outlineVariant.withValues(alpha: 0.5),
        ),
      ),
      child: InkWell(
        borderRadius: BorderRadius.circular(borderRadius),
        onTap: () => _showConnectionDetails(context, connection),
        child: Padding(
          padding: cardPadding,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Container(
                    width: 10,
                    height: 10,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: protocolColor,
                      boxShadow: [
                        BoxShadow(
                          color: protocolColor.withValues(alpha: 0.5),
                          blurRadius: 6,
                          spreadRadius: 1,
                        ),
                      ],
                    ),
                  ),
                  SizedBox(width: spacing * 1.5),
                  Expanded(
                    child: Text(
                      '${connection.host}:${connection.destinationPort}',
                      style: textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  _buildTrafficBadge(context, connection, appState),
                  SizedBox(width: spacing),
                  IconButton(
                    icon: Icon(
                      Icons.close_rounded,
                      color: colorScheme.error,
                      size: 20,
                    ),
                    onPressed: () => _closeConnection(context, connection),
                    tooltip: '关闭连接',
                    visualDensity: VisualDensity.compact,
                    style: IconButton.styleFrom(
                      backgroundColor: colorScheme.errorContainer.withValues(
                        alpha: 0.3,
                      ),
                    ),
                  ),
                ],
              ),
              SizedBox(height: spacing * 1.5),
              Wrap(
                spacing: spacing,
                runSpacing: spacing,
                children: [
                  _buildInfoChip(
                    context,
                    icon: Icons.rule_rounded,
                    label: connection.rule,
                    color: colorScheme.tertiary,
                  ),
                  _buildInfoChip(
                    context,
                    icon: Icons.security_rounded,
                    label: '${connection.protocol}/${connection.network}',
                    color: protocolColor,
                  ),
                  if (connection.outboundTag.isNotEmpty)
                    _buildInfoChip(
                      context,
                      icon: Icons.output_rounded,
                      label: connection.outboundTag,
                      color: colorScheme.secondary,
                    ),
                ],
              ),
              if (connection.rulePayload.isNotEmpty) ...[
                SizedBox(height: spacing),
                Text(
                  connection.rulePayload,
                  style: textTheme.bodySmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                    fontFamily: 'monospace',
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTrafficBadge(
    BuildContext context,
    ActiveConnection connection,
    AppStateProvider appState,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final spacing = ResponsiveUtils.getSpacing(context);

    final uploadStr = _formatTrafficCompact(connection.uploadBytes);
    final downloadStr = _formatTrafficCompact(connection.downloadBytes);

    return AnimatedContainer(
      duration: AnimationUtils.durationMedium2,
      curve: AnimationUtils.curveStandard,
      padding: EdgeInsets.symmetric(
        horizontal: spacing * 1.25,
        vertical: spacing * 0.75,
      ),
      decoration: BoxDecoration(
        color: colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(borderRadius * 0.75),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.arrow_upward_rounded,
            size: 12,
            color: colorScheme.tertiary,
          ),
          const SizedBox(width: 4),
          Text(
            uploadStr,
            style: textTheme.labelSmall?.copyWith(
              fontWeight: FontWeight.w600,
              color: colorScheme.tertiary,
              fontFeatures: const [FontFeature.tabularFigures()],
            ),
          ),
          SizedBox(width: spacing),
          Icon(
            Icons.arrow_downward_rounded,
            size: 12,
            color: colorScheme.primary,
          ),
          const SizedBox(width: 4),
          Text(
            downloadStr,
            style: textTheme.labelSmall?.copyWith(
              fontWeight: FontWeight.w600,
              color: colorScheme.primary,
              fontFeatures: const [FontFeature.tabularFigures()],
            ),
          ),
        ],
      ),
    );
  }

  String _formatTrafficCompact(BigInt bytes) {
    final value = bytes.toDouble();
    if (value < 1024) {
      return '${value.toStringAsFixed(0)} B';
    } else if (value < 1024 * 1024) {
      return '${(value / 1024).toStringAsFixed(1)} KB';
    } else if (value < 1024 * 1024 * 1024) {
      return '${(value / 1024 / 1024).toStringAsFixed(2)} MB';
    } else {
      return '${(value / 1024 / 1024 / 1024).toStringAsFixed(2)} GB';
    }
  }

  Widget _buildInfoChip(
    BuildContext context, {
    required IconData icon,
    required String label,
    required Color color,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final spacing = ResponsiveUtils.getSpacing(context);

    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: spacing * 1.25,
        vertical: spacing * 0.75,
      ),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          SizedBox(width: spacing * 0.5),
          Text(
            label,
            style: textTheme.labelSmall?.copyWith(
              color: color,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  void _closeConnection(BuildContext context, ActiveConnection connection) {
    context.read<AppStateProvider>().closeActiveConnectionById(connection.id);
  }

  void _showCloseAllDialog(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        icon: Icon(Icons.warning_rounded, color: colorScheme.error, size: 48),
        title: const Text('关闭所有连接'),
        content: const Text('确定要关闭所有活动连接吗？这可能会中断正在进行的下载或流媒体。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () {
              context.read<AppStateProvider>().closeAllActiveConnections();
              Navigator.of(context).pop();
            },
            style: FilledButton.styleFrom(backgroundColor: colorScheme.error),
            child: const Text('关闭全部'),
          ),
        ],
      ),
    );
  }

  void _showConnectionDetails(
    BuildContext context,
    ActiveConnection connection,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final appState = context.read<AppStateProvider>();

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: colorScheme.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
      ),
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.7,
        minChildSize: 0.5,
        maxChildSize: 0.95,
        expand: false,
        builder: (context, scrollController) => Column(
          children: [
            Container(
              margin: const EdgeInsets.only(top: 12),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: colorScheme.onSurfaceVariant.withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 16, 16, 0),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: colorScheme.primaryContainer,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Icon(
                      Icons.info_outline_rounded,
                      color: colorScheme.onPrimaryContainer,
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '连接详情',
                          style: textTheme.titleLarge?.copyWith(
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        Text(
                          connection.host,
                          style: textTheme.bodySmall?.copyWith(
                            color: colorScheme.onSurfaceVariant,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close_rounded),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
            ),
            const Divider(height: 24),
            Expanded(
              child: ListView(
                controller: scrollController,
                padding: const EdgeInsets.symmetric(horizontal: 24),
                children: [
                  _buildDetailSection(
                    context,
                    title: '基本信息',
                    items: [
                      _DetailItem('主机', connection.host),
                      _DetailItem('端口', connection.destinationPort.toString()),
                      _DetailItem(
                        '协议',
                        '${connection.protocol}/${connection.network}',
                      ),
                      if (connection.destinationIp != null &&
                          connection.destinationIp!.isNotEmpty)
                        _DetailItem('目标 IP', connection.destinationIp!),
                    ],
                  ),
                  const SizedBox(height: 20),
                  _buildDetailSection(
                    context,
                    title: '路由信息',
                    items: [
                      _DetailItem('规则', connection.rule),
                      if (connection.rulePayload.isNotEmpty)
                        _DetailItem('规则载荷', connection.rulePayload),
                      _DetailItem('入站', connection.inboundTag),
                      _DetailItem('出站', connection.outboundTag),
                    ],
                  ),
                  const SizedBox(height: 20),
                  _buildDetailSection(
                    context,
                    title: '流量统计',
                    items: [
                      _DetailItem(
                        '上传',
                        appState.getFormattedTraffic(connection.uploadBytes),
                      ),
                      _DetailItem(
                        '下载',
                        appState.getFormattedTraffic(connection.downloadBytes),
                      ),
                      _DetailItem(
                        '创建时间',
                        _formatTimestamp(connection.startTime),
                      ),
                    ],
                  ),
                  if (connection.processName != null &&
                      connection.processName!.isNotEmpty) ...[
                    const SizedBox(height: 20),
                    _buildDetailSection(
                      context,
                      title: '进程信息',
                      items: [_DetailItem('进程名', connection.processName!)],
                    ),
                  ],
                  const SizedBox(height: 24),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: () {
                            Clipboard.setData(
                              ClipboardData(
                                text:
                                    '${connection.host}:${connection.destinationPort}',
                              ),
                            );
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(content: Text('已复制到剪贴板')),
                            );
                          },
                          icon: const Icon(Icons.copy_rounded),
                          label: const Text('复制地址'),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: FilledButton.icon(
                          onPressed: () {
                            appState.closeActiveConnectionById(connection.id);
                            Navigator.of(context).pop();
                          },
                          icon: const Icon(Icons.close_rounded),
                          label: const Text('关闭连接'),
                          style: FilledButton.styleFrom(
                            backgroundColor: colorScheme.error,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 24),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailSection(
    BuildContext context, {
    required String title,
    required List<_DetailItem> items,
  }) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: textTheme.titleSmall?.copyWith(
            color: colorScheme.primary,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 12),
        Container(
          decoration: BoxDecoration(
            color: colorScheme.surfaceContainerLow,
            borderRadius: BorderRadius.circular(16),
          ),
          child: Column(
            children: items.asMap().entries.map((entry) {
              final index = entry.key;
              final item = entry.value;
              return Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 14,
                    ),
                    child: Row(
                      children: [
                        Text(
                          item.label,
                          style: textTheme.bodyMedium?.copyWith(
                            color: colorScheme.onSurfaceVariant,
                          ),
                        ),
                        const Spacer(),
                        Flexible(
                          child: Text(
                            item.value,
                            style: textTheme.bodyMedium?.copyWith(
                              fontWeight: FontWeight.w500,
                            ),
                            textAlign: TextAlign.end,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (index < items.length - 1)
                    Divider(
                      height: 1,
                      indent: 16,
                      endIndent: 16,
                      color: colorScheme.outlineVariant,
                    ),
                ],
              );
            }).toList(),
          ),
        ),
      ],
    );
  }

  String _formatTimestamp(BigInt timestamp) {
    final date = DateTime.fromMillisecondsSinceEpoch(timestamp.toInt());
    final now = DateTime.now();
    final diff = now.difference(date);

    if (diff.inSeconds < 60) {
      return '${diff.inSeconds} 秒前';
    } else if (diff.inMinutes < 60) {
      return '${diff.inMinutes} 分钟前';
    } else if (diff.inHours < 24) {
      return '${diff.inHours} 小时前';
    } else {
      return '${date.month}/${date.day} ${date.hour.toString().padLeft(2, '0')}:${date.minute.toString().padLeft(2, '0')}';
    }
  }
}

class _DetailItem {
  final String label;
  final String value;

  _DetailItem(this.label, this.value);
}
