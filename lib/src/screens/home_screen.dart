import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:veloguard/src/providers/app_state_provider.dart';
import 'package:veloguard/src/providers/theme_provider.dart';
import 'package:veloguard/src/widgets/traffic_chart.dart';
import 'package:veloguard/src/widgets/status_card.dart';
import 'package:veloguard/src/widgets/quick_actions.dart';
import 'package:veloguard/src/widgets/adaptive_list_tile.dart';
import 'package:veloguard/src/utils/platform_utils.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/utils/device_info_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/rust/types.dart';

// Default traffic stats when service is not running
final _defaultTrafficStats = TrafficStats(
  upload: BigInt.zero,
  download: BigInt.zero,
  uploadSpeed: BigInt.zero,
  downloadSpeed: BigInt.zero,
);

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<AppStateProvider>().startPeriodicUpdates();
    });
  }

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);

    return Consumer2<AppStateProvider, ThemeProvider>(
      builder: (context, appState, themeProvider, _) {
        return Scaffold(
          appBar: AppBar(
            title: Text(
              'VeloGuard',
              style: textTheme.headlineMedium?.copyWith(
                fontWeight: FontWeight.w700,
              ),
            ),
            actions: [
              IconButton(
                icon: const Icon(Icons.palette_outlined),
                onPressed: () => _showThemeSelector(context, themeProvider),
                tooltip: l10n?.changeTheme ?? 'Change theme',
              ),
              IconButton(
                icon: const Icon(Icons.refresh_outlined),
                onPressed: () => appState.refreshStatus(),
                tooltip: l10n?.refresh ?? 'Refresh',
              ),
            ],
          ),
          body: RefreshIndicator(
            onRefresh: () async {
              await appState.refreshStatus();
            },
            child: SingleChildScrollView(
              physics: PlatformUtils.getScrollPhysics(context),
              padding: ResponsiveUtils.getResponsivePadding(context),
              child: SafeArea(
                top: false,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildSectionHeader(
                      context,
                      l10n?.serviceStatus ?? 'Service Status',
                      Icons.power_settings_new_outlined,
                    ),
                    ResponsiveSpacing(multiplier: 1.5),
                    StatusCard(
                      isRunning: appState.isServiceRunning,
                      isLoading: appState.isLoading,
                      proxyStatus: appState.proxyStatus,
                      onStartStop: () {
                        if (appState.isServiceRunning) {
                          appState.stopService();
                        } else {
                          appState.startService();
                        }
                      },
                    ),

                    // 服务详细统计（运行时显示）
                    AnimatedSize(
                      duration: AnimationUtils.stateChangeDuration,
                      curve: AnimationUtils.curveEmphasized,
                      child:
                          appState.isServiceRunning &&
                              appState.proxyStatus != null
                          ? Padding(
                              padding: const EdgeInsets.only(top: 12),
                              child: ServiceStatsCard(
                                proxyStatus: appState.proxyStatus!,
                              ),
                            )
                          : const SizedBox.shrink(),
                    ),

                    ResponsiveSpacing(multiplier: 3),

                    // 流量统计 - 包含下载、上传、IP 三列
                    _buildSectionHeader(
                      context,
                      l10n?.trafficStatistics ?? 'Traffic Statistics',
                      Icons.show_chart_outlined,
                    ),
                    ResponsiveSpacing(multiplier: 1.5),
                    TrafficChart(
                      trafficStats:
                          appState.trafficStats ?? _defaultTrafficStats,
                      downloadSpeed: appState.currentDownloadSpeed,
                      uploadSpeed: appState.currentUploadSpeed,
                      isProxyRunning: appState.isServiceRunning,
                    ),

                    ResponsiveSpacing(multiplier: 3),

                    // 快捷操作
                    _buildSectionHeader(
                      context,
                      l10n?.quickActions ?? 'Quick Actions',
                      Icons.bolt_outlined,
                    ),
                    ResponsiveSpacing(multiplier: 1.5),
                    const QuickActions(),

                    ResponsiveSpacing(multiplier: 3),

                    // 系统信息
                    if (appState.systemInfo != null) ...[
                      _buildSectionHeader(
                        context,
                        l10n?.systemInformation ?? 'System Information',
                        Icons.info_outline,
                      ),
                      ResponsiveSpacing(multiplier: 1.5),
                      _buildSystemInfoCard(context, appState, l10n),
                      ResponsiveSpacing(multiplier: 2),
                    ],
                  ],
                ),
              ),
            ),
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
    final iconSize = ResponsiveUtils.getIconSize(context);

    return Row(
      children: [
        Icon(icon, size: iconSize * 0.9, color: colorScheme.primary),
        SizedBox(width: ResponsiveUtils.getSpacing(context)),
        Text(
          title,
          style: textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
            color: colorScheme.primary,
          ),
        ),
      ],
    );
  }

  Widget _buildSystemInfoCard(
    BuildContext context,
    AppStateProvider appState,
    AppLocalizations? l10n,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final borderRadius = ResponsiveUtils.getBorderRadius(context);

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: Padding(
        padding: ResponsiveUtils.getCardPadding(context),
        child: Column(
          children: [
            _buildInfoRow(
              context,
              icon: Icons.computer_outlined,
              label: l10n?.platform ?? 'Platform',
              value: appState.systemInfo!.platform,
            ),
            const Divider(height: 24),
            _buildInfoRow(
              context,
              icon: Icons.phone_android_outlined,
              label: l10n?.deviceModel ?? 'Device Model',
              value: _getDeviceModel(),
            ),
            const Divider(height: 24),
            _buildInfoRow(
              context,
              icon: Icons.memory_outlined,
              label: l10n?.memory ?? 'Memory',
              value:
                  '${appState.systemInfo!.memoryTotal ~/ BigInt.from(1024) ~/ BigInt.from(1024)} MB',
            ),
            const Divider(height: 24),
            _buildInfoRow(
              context,
              icon: Icons.developer_board_outlined,
              label: l10n?.cpuCores ?? 'CPU',
              value: appState.systemInfo!.cpuName.isNotEmpty
                  ? '${appState.systemInfo!.cpuName} (${appState.systemInfo!.cpuCores}C/${appState.systemInfo!.cpuThreads}T)'
                  : '${appState.systemInfo!.cpuCores} ${l10n?.cpuCores ?? "cores"} / ${appState.systemInfo!.cpuThreads} ${l10n?.cpuThreads ?? "threads"}',
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoRow(
    BuildContext context, {
    required IconData icon,
    required String label,
    required String value,
  }) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final iconSize = ResponsiveUtils.getIconSize(context);
    final spacing = ResponsiveUtils.getSpacing(context);

    return Row(
      children: [
        Icon(icon, size: iconSize * 0.85, color: colorScheme.primary),
        SizedBox(width: spacing),
        Expanded(
          child: Text(
            label,
            style: textTheme.bodyMedium?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
          ),
        ),
        SizedBox(width: spacing),
        Flexible(
          child: Text(
            value,
            style: textTheme.bodyMedium?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
            textAlign: TextAlign.end,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }

  String _getDeviceModel() {
    if (Platform.isAndroid) {
      return DeviceInfoUtils.model;
    } else if (Platform.isWindows) {
      return 'Windows PC';
    } else if (Platform.isMacOS) {
      return 'Mac';
    } else if (Platform.isLinux) {
      return 'Linux PC';
    }
    return 'Unknown Device';
  }

  void _showThemeSelector(BuildContext context, ThemeProvider themeProvider) {
    final l10n = AppLocalizations.of(context);

    showModalBottomSheet(
      context: context,
      showDragHandle: true,
      isScrollControlled: true,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.5,
        minChildSize: 0.3,
        maxChildSize: 0.8,
        expand: false,
        builder: (context, scrollController) => Padding(
          padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                l10n?.chooseTheme ?? 'Choose Theme',
                style: Theme.of(
                  context,
                ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 16),
              Expanded(
                child: ListView(
                  controller: scrollController,
                  children: [
                    ...themeProvider.availableThemes.map((themeName) {
                      final isSelected =
                          themeProvider.selectedTheme == themeName;
                      return AdaptiveListTile(
                        title: Text(
                          themeProvider.getThemeDisplayName(themeName),
                        ),
                        leading: Container(
                          width: 24,
                          height: 24,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: _getThemeColor(themeName, context),
                          ),
                        ),
                        trailing: isSelected
                            ? Icon(
                                Icons.check,
                                color: Theme.of(context).colorScheme.primary,
                              )
                            : null,
                        onTap: () {
                          themeProvider.setTheme(themeName);
                          Navigator.of(context).pop();
                        },
                        selected: isSelected,
                      );
                    }),
                    const Divider(),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        const Icon(Icons.auto_awesome_outlined),
                        const SizedBox(width: 12),
                        Text(
                          l10n?.dynamicColors ?? 'Dynamic Colors',
                          style: Theme.of(context).textTheme.bodyLarge,
                        ),
                        const Spacer(),
                        Switch(
                          value: themeProvider.useDynamicColors,
                          onChanged: (value) =>
                              themeProvider.setUseDynamicColors(value),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Color _getThemeColor(String themeName, BuildContext context) {
    switch (themeName) {
      case 'ocean':
        return const Color(0xFF0061A4);
      case 'forest':
        return const Color(0xFF146C2E);
      case 'sunset':
        return const Color(0xFF8F4A4A);
      default:
        return Theme.of(context).colorScheme.primary;
    }
  }
}
