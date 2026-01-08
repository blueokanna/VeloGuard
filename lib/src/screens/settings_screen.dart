import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:go_router/go_router.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:veloguard/src/providers/app_state_provider.dart';
import 'package:veloguard/src/providers/theme_provider.dart';
import 'package:veloguard/src/providers/locale_provider.dart';
import 'package:veloguard/src/providers/general_settings_provider.dart';
import 'package:veloguard/src/widgets/adaptive_list_tile.dart';
import 'package:veloguard/src/utils/platform_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:package_info_plus/package_info_plus.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  PackageInfo? _packageInfo;

  @override
  void initState() {
    super.initState();
    _loadPackageInfo();
  }

  Future<void> _loadPackageInfo() async {
    final info = await PackageInfo.fromPlatform();
    if (mounted) {
      setState(() {
        _packageInfo = info;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);

    return Consumer2<AppStateProvider, ThemeProvider>(
      builder: (context, appState, themeProvider, child) {
        return Scaffold(
          appBar: AppBar(
            title: Text(
              l10n?.settings ?? '设置',
              style: textTheme.headlineMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          body: RefreshIndicator(
            onRefresh: () async => await appState.refreshStatus(),
            child: ListView(
              physics: PlatformUtils.getScrollPhysics(),
              padding: PlatformUtils.getPlatformPadding(context),
              children: [
                // 外观设置
                _buildSectionHeader(
                  context,
                  l10n?.appearance ?? '外观',
                  Icons.palette_outlined,
                ),
                Card(
                  elevation: 0,
                  color: colorScheme.surfaceContainerLow,
                  child: Column(
                    children: [
                      AdaptiveListTile(
                        title: Text(l10n?.themeMode ?? '主题模式'),
                        subtitle: Text(
                          _getThemeModeText(appState.themeMode, l10n),
                        ),
                        leading: Icon(
                          appState.themeMode == ThemeMode.dark
                              ? Icons.dark_mode_outlined
                              : appState.themeMode == ThemeMode.light
                              ? Icons.light_mode_outlined
                              : Icons.brightness_auto_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 6,
                          ),
                          decoration: BoxDecoration(
                            color: colorScheme.surfaceContainerHighest,
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: DropdownButton<ThemeMode>(
                            value: appState.themeMode,
                            underline: const SizedBox.shrink(),
                            isDense: true,
                            borderRadius: BorderRadius.circular(12),
                            dropdownColor: colorScheme.surfaceContainerHigh,
                            items: [
                              DropdownMenuItem(
                                value: ThemeMode.system,
                                child: Text(l10n?.system ?? '跟随系统'),
                              ),
                              DropdownMenuItem(
                                value: ThemeMode.light,
                                child: Text(l10n?.light ?? '浅色'),
                              ),
                              DropdownMenuItem(
                                value: ThemeMode.dark,
                                child: Text(l10n?.dark ?? '深色'),
                              ),
                            ],
                            onChanged: (value) {
                              if (value != null) appState.setThemeMode(value);
                            },
                          ),
                        ),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.themeStyle ?? '主题风格'),
                        subtitle: Text(
                          themeProvider.useDynamicColors
                              ? (l10n?.dynamicColors ?? '动态颜色')
                              : themeProvider.getThemeDisplayName(
                                  themeProvider.selectedTheme,
                                ),
                        ),
                        leading: Container(
                          width: 24,
                          height: 24,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: themeProvider.useDynamicColors
                                ? colorScheme.primary
                                : _getThemePreviewColor(
                                    themeProvider.selectedTheme,
                                    context,
                                  ),
                          ),
                        ),
                        trailing: themeProvider.useDynamicColors
                            ? Icon(
                                Icons.lock_outline,
                                color: colorScheme.onSurfaceVariant,
                              )
                            : const Icon(Icons.chevron_right),
                        onTap: themeProvider.useDynamicColors
                            ? null
                            : () => _showThemeSelector(context, themeProvider),
                        enabled: !themeProvider.useDynamicColors,
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.dynamicColors ?? '动态颜色'),
                        subtitle: Text(
                          l10n?.useSystemAccentColors ?? '使用系统强调色',
                        ),
                        leading: Icon(
                          Icons.color_lens_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: Switch.adaptive(
                          value: themeProvider.useDynamicColors,
                          onChanged: (value) =>
                              themeProvider.setUseDynamicColors(value),
                        ),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      Consumer<LocaleProvider>(
                        builder: (context, localeProvider, child) {
                          return AdaptiveListTile(
                            title: Text(l10n?.language ?? '语言'),
                            subtitle: Text(
                              localeProvider.getLocaleName(
                                localeProvider.currentLocale,
                              ),
                            ),
                            leading: Icon(
                              Icons.language_outlined,
                              color: colorScheme.primary,
                            ),
                            trailing: const Icon(Icons.chevron_right),
                            onTap: () =>
                                _showLanguageSelector(context, localeProvider),
                          );
                        },
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      Consumer<GeneralSettingsProvider>(
                        builder: (context, generalSettings, child) {
                          return AdaptiveListTile(
                            title: Text(l10n?.hapticFeedback ?? '震动反馈'),
                            subtitle: Text(
                              l10n?.hapticFeedbackDesc ?? '操作时触发手机震动',
                            ),
                            leading: Icon(
                              Icons.vibration_outlined,
                              color: colorScheme.primary,
                            ),
                            trailing: Switch.adaptive(
                              value: generalSettings.hapticFeedbackEnabled,
                              onChanged: (value) {
                                generalSettings.setHapticFeedbackEnabled(value);
                                AnimationUtils.setHapticEnabled(value);
                                if (value) {
                                  AnimationUtils.mediumHaptic();
                                }
                              },
                            ),
                          );
                        },
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 24),

                // 配置设置
                _buildSectionHeader(
                  context,
                  l10n?.configuration ?? '配置',
                  Icons.tune_outlined,
                ),
                Card(
                  elevation: 0,
                  color: colorScheme.surfaceContainerLow,
                  child: Column(
                    children: [
                      AdaptiveListTile(
                        title: Text(l10n?.basicConfig ?? '基本配置'),
                        subtitle: Text(
                          l10n?.basicConfigDesc ?? '端口、模式、日志等基本设置',
                        ),
                        leading: Icon(
                          Icons.settings_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => context.push('/basic-config'),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.advancedConfig ?? '高级配置'),
                        subtitle: Text(
                          l10n?.advancedConfigDesc ?? 'TCP、测速、进程等高级设置',
                        ),
                        leading: Icon(
                          Icons.build_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => context.push('/advanced-config'),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.dnsSettings ?? 'DNS 设置'),
                        subtitle: Text(
                          l10n?.dnsSettingsDesc ?? 'DNS 服务器、Fake-IP、Fallback 等',
                        ),
                        leading: Icon(
                          Icons.dns_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => context.push('/dns-settings'),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 24),

                // 网络设置 - 仅桌面平台显示
                if (PlatformUtils.isDesktop) ...[
                  _buildSectionHeader(
                    context,
                    l10n?.network ?? '网络',
                    Icons.wifi_outlined,
                  ),
                  Card(
                    elevation: 0,
                    color: colorScheme.surfaceContainerLow,
                    child: Column(
                      children: [
                        AdaptiveListTile(
                          title: Text(l10n?.networkSettings ?? '网络设置'),
                          subtitle: Text(
                            l10n?.systemProxyTunUwp ?? '系统代理、TUN、UWP 回环',
                          ),
                          leading: Icon(
                            Icons.settings_ethernet_outlined,
                            color: colorScheme.primary,
                          ),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: () => context.push('/network-settings'),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 24),
                ],

                // 服务设置
                _buildSectionHeader(
                  context,
                  l10n?.service ?? '服务',
                  Icons.miscellaneous_services_outlined,
                ),
                Card(
                  elevation: 0,
                  color: colorScheme.surfaceContainerLow,
                  child: Column(
                    children: [
                      AdaptiveListTile(
                        title: Text(l10n?.serviceStatus ?? '服务状态'),
                        subtitle: Text(
                          appState.isServiceRunning
                              ? (l10n?.running ?? '运行中')
                              : (l10n?.stopped ?? '已停止'),
                        ),
                        leading: Icon(
                          appState.isServiceRunning
                              ? Icons.play_circle_outline
                              : Icons.stop_circle_outlined,
                          color: appState.isServiceRunning
                              ? colorScheme.primary
                              : colorScheme.error,
                        ),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      // 自动系统代理设置 (Windows)
                      if (PlatformUtils.isDesktop) ...[
                        AdaptiveListTile(
                          title: const Text('自动系统代理'),
                          subtitle: const Text('启动服务时自动配置系统代理'),
                          leading: Icon(
                            Icons.settings_system_daydream_outlined,
                            color: colorScheme.primary,
                          ),
                          trailing: Switch.adaptive(
                            value: appState.autoSystemProxy,
                            onChanged: (value) =>
                                appState.setAutoSystemProxy(value),
                          ),
                        ),
                        const Divider(height: 1, indent: 16, endIndent: 16),
                      ],

                      AdaptiveListTile(
                        title: Text(l10n?.viewLogs ?? '查看日志'),
                        subtitle: Text(l10n?.viewLogsDesc ?? '查看运行时日志和调试信息'),
                        leading: Icon(
                          Icons.article_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => context.push('/logs'),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 24),

                // 关于
                _buildSectionHeader(
                  context,
                  l10n?.about ?? '关于',
                  Icons.info_outline,
                ),
                Card(
                  elevation: 0,
                  color: colorScheme.surfaceContainerLow,
                  child: Column(
                    children: [
                      AdaptiveListTile(
                        title: Text(l10n?.version ?? '版本'),
                        subtitle: Text(
                          _packageInfo?.version ?? appState.version,
                        ),
                        leading: Icon(
                          Icons.tag_outlined,
                          color: colorScheme.primary,
                        ),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.buildInfo ?? '构建信息'),
                        subtitle: Text(appState.buildInfo),
                        leading: Icon(
                          Icons.build_outlined,
                          color: colorScheme.primary,
                        ),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.disclaimer ?? '免责声明'),
                        subtitle: Text(l10n?.disclaimerDesc ?? '使用条款和法律声明'),
                        leading: Icon(
                          Icons.gavel_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => _showDisclaimerDialog(context),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.aboutVeloguard ?? '关于 VeloGuard'),
                        subtitle: Text(l10n?.aboutVeloguardDesc ?? '了解更多关于此应用'),
                        leading: Icon(
                          Icons.flash_on_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => _showAboutDialog(context),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.license ?? '许可证'),
                        subtitle: Text(l10n?.licenseName ?? 'AGPL-3.0'),
                        leading: Icon(
                          Icons.article_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => _showLicenseDialog(context),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 24),

                // 操作
                _buildSectionHeader(
                  context,
                  l10n?.actions ?? '操作',
                  Icons.bolt_outlined,
                ),
                Card(
                  elevation: 0,
                  color: colorScheme.surfaceContainerLow,
                  child: Column(
                    children: [
                      AdaptiveListTile(
                        title: Text(l10n?.restartService ?? '重启服务'),
                        subtitle: Text(
                          l10n?.restartServiceDesc ?? '重启 VeloGuard 服务',
                        ),
                        leading: Icon(
                          Icons.restart_alt_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: appState.isServiceRunning
                            ? () => _showRestartDialog(context, appState)
                            : null,
                        enabled: appState.isServiceRunning,
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.resetSettings ?? '重置设置'),
                        subtitle: Text(l10n?.resetSettingsDesc ?? '重置所有设置为默认值'),
                        leading: Icon(
                          Icons.settings_backup_restore_outlined,
                          color: colorScheme.error,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => _showResetDialog(context, appState),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 32),
              ],
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

  String _getThemeModeText(ThemeMode mode, AppLocalizations? l10n) {
    switch (mode) {
      case ThemeMode.system:
        return l10n?.system ?? '跟随系统';
      case ThemeMode.light:
        return l10n?.light ?? '浅色';
      case ThemeMode.dark:
        return l10n?.dark ?? '深色';
    }
  }

  Color _getThemePreviewColor(String themeName, BuildContext context) {
    return context.read<ThemeProvider>().getThemeSeedColor(themeName);
  }

  void _showLicenseDialog(BuildContext context) {
    showLicensePage(
      context: context,
      applicationName: 'VeloGuard',
      applicationVersion: _packageInfo?.version ?? '1.0.0',
      applicationLegalese: '© 2024-2026 VeloGuard. AGPL-3.0 License.',
    );
  }

  void _showDisclaimerDialog(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.gavel_outlined, color: colorScheme.primary),
            const SizedBox(width: 12),
            Text(l10n?.disclaimer ?? '免责声明'),
          ],
        ),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                l10n?.disclaimerTitle ?? '使用条款',
                style: Theme.of(
                  context,
                ).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 12),
              Text(
                l10n?.disclaimerContent ?? 'VeloGuard 是一款网络代理工具，仅供合法用途使用。',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: colorScheme.errorContainer.withValues(alpha: 0.3),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.warning_amber_outlined,
                      color: colorScheme.error,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        l10n?.disclaimerWarning ?? '非法使用代理工具可能导致法律后果。',
                        style: TextStyle(
                          color: colorScheme.error,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          FilledButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n?.understood ?? '我已了解'),
          ),
        ],
      ),
    );
  }

  void _showAboutDialog(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: colorScheme.primaryContainer,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(Icons.flash_on, color: colorScheme.primary, size: 32),
            ),
            const SizedBox(width: 16),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('VeloGuard'),
                Text(
                  'v${_packageInfo?.version ?? '1.0.0'}',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ],
        ),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                l10n?.aboutDescription ??
                    'VeloGuard 是一款现代化的跨平台代理客户端，使用 Flutter 和 Rust 构建。'
                        '它提供了精美的 Material You 界面和强大的代理功能。',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: 20),
              Text(
                l10n?.features ?? '功能特性',
                style: Theme.of(
                  context,
                ).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 8),
              _buildFeatureItem(
                context,
                Icons.speed_outlined,
                l10n?.featureSpeed ?? '高性能 Rust 核心',
              ),
              _buildFeatureItem(
                context,
                Icons.palette_outlined,
                l10n?.featureTheme ?? 'Material You 动态颜色',
              ),
              _buildFeatureItem(
                context,
                Icons.devices_outlined,
                l10n?.featurePlatform ?? '跨平台支持',
              ),
              _buildFeatureItem(
                context,
                Icons.security_outlined,
                l10n?.featureSecurity ?? '多种代理协议',
              ),
              _buildFeatureItem(
                context,
                Icons.rule_outlined,
                l10n?.featureRules ?? '灵活的路由规则',
              ),
              _buildFeatureItem(
                context,
                Icons.dns_outlined,
                l10n?.featureDns ?? '内置 DNS 服务器',
              ),
              const SizedBox(height: 20),
              Text(
                l10n?.supportedProtocols ?? '支持的协议',
                style: Theme.of(
                  context,
                ).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  _buildProtocolChip(context, 'Shadowsocks'),
                  _buildProtocolChip(context, 'VMess'),
                  _buildProtocolChip(context, 'Trojan'),
                  _buildProtocolChip(context, 'SOCKS5'),
                  _buildProtocolChip(context, 'HTTP'),
                  _buildProtocolChip(context, 'WireGuard'),
                  _buildProtocolChip(context, 'TUIC'),
                  _buildProtocolChip(context, 'Hysteria2'),
                ],
              ),
              const SizedBox(height: 20),
              InkWell(
                onTap: () async {
                  final uri = Uri.parse(
                    'https://github.com/blueokanna/VeloGuard',
                  );
                  if (await canLaunchUrl(uri)) {
                    await launchUrl(uri, mode: LaunchMode.externalApplication);
                  }
                },
                borderRadius: BorderRadius.circular(8),
                child: Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      Icon(Icons.code_outlined, color: colorScheme.primary),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              l10n?.openSource ?? '开源项目',
                              style: Theme.of(context).textTheme.titleSmall
                                  ?.copyWith(fontWeight: FontWeight.w600),
                            ),
                            Text(
                              l10n?.openSourceDesc ?? '使用 Flutter & Rust 构建',
                              style: Theme.of(context).textTheme.bodySmall
                                  ?.copyWith(
                                    color: colorScheme.onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                      ),
                      Icon(
                        Icons.open_in_new,
                        color: colorScheme.primary,
                        size: 18,
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n?.close ?? '关闭'),
          ),
        ],
      ),
    );
  }

  Widget _buildFeatureItem(BuildContext context, IconData icon, String text) {
    final colorScheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(icon, size: 18, color: colorScheme.primary),
          const SizedBox(width: 12),
          Expanded(child: Text(text)),
        ],
      ),
    );
  }

  Widget _buildProtocolChip(BuildContext context, String protocol) {
    final colorScheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: colorScheme.primaryContainer,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Text(
        protocol,
        style: TextStyle(
          color: colorScheme.onPrimaryContainer,
          fontSize: 12,
          fontWeight: FontWeight.w500,
        ),
      ),
    );
  }

  void _showRestartDialog(BuildContext context, AppStateProvider appState) {
    final l10n = AppLocalizations.of(context);
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n?.restartService ?? '重启服务'),
        content: const Text('确定要重启 VeloGuard 服务吗？这将暂时断开所有活动连接。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n?.cancel ?? '取消'),
          ),
          FilledButton(
            onPressed: () {
              appState.restartService();
              Navigator.of(context).pop();
            },
            child: const Text('重启'),
          ),
        ],
      ),
    );
  }

  void _showResetDialog(BuildContext context, AppStateProvider appState) {
    final l10n = AppLocalizations.of(context);
    final colorScheme = Theme.of(context).colorScheme;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n?.resetSettings ?? '重置设置'),
        content: const Text('确定要重置所有设置为默认值吗？此操作无法撤销。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n?.cancel ?? '取消'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.of(context).pop();
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: const Text('设置已重置'),
                  behavior: SnackBarBehavior.floating,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
              );
            },
            style: FilledButton.styleFrom(backgroundColor: colorScheme.error),
            child: const Text('重置'),
          ),
        ],
      ),
    );
  }

  void _showThemeSelector(BuildContext context, ThemeProvider themeProvider) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: colorScheme.surfaceContainerLow,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
      ),
      builder: (context) {
        return DraggableScrollableSheet(
          initialChildSize: 0.6,
          minChildSize: 0.4,
          maxChildSize: 0.9,
          expand: false,
          builder: (context, scrollController) {
            return SafeArea(
              child: Column(
                children: [
                  Container(
                    margin: const EdgeInsets.only(top: 12, bottom: 8),
                    width: 32,
                    height: 4,
                    decoration: BoxDecoration(
                      color: colorScheme.onSurfaceVariant.withValues(
                        alpha: 0.4,
                      ),
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(24, 8, 24, 16),
                    child: Row(
                      children: [
                        Icon(
                          Icons.palette_outlined,
                          color: colorScheme.primary,
                        ),
                        const SizedBox(width: 12),
                        Text(
                          l10n?.chooseTheme ?? '选择主题',
                          style: Theme.of(context).textTheme.titleLarge
                              ?.copyWith(fontWeight: FontWeight.w600),
                        ),
                      ],
                    ),
                  ),
                  Expanded(
                    child: GridView.builder(
                      controller: scrollController,
                      padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
                      gridDelegate:
                          const SliverGridDelegateWithFixedCrossAxisCount(
                            crossAxisCount: 2,
                            childAspectRatio: 2.5,
                            crossAxisSpacing: 12,
                            mainAxisSpacing: 12,
                          ),
                      itemCount: themeProvider.availableThemes.length,
                      itemBuilder: (context, index) {
                        final themeName = themeProvider.availableThemes[index];
                        final isSelected =
                            themeProvider.selectedTheme == themeName;
                        final seedColor = themeProvider.getThemeSeedColor(
                          themeName,
                        );

                        return Material(
                          color: isSelected
                              ? colorScheme.primaryContainer
                              : colorScheme.surfaceContainerHigh,
                          borderRadius: BorderRadius.circular(16),
                          child: InkWell(
                            onTap: () {
                              themeProvider.setTheme(themeName);
                              Navigator.of(context).pop();
                            },
                            borderRadius: BorderRadius.circular(16),
                            child: Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 12,
                              ),
                              decoration: BoxDecoration(
                                borderRadius: BorderRadius.circular(16),
                                border: isSelected
                                    ? Border.all(
                                        color: colorScheme.primary,
                                        width: 2,
                                      )
                                    : null,
                              ),
                              child: Row(
                                children: [
                                  Container(
                                    width: 32,
                                    height: 32,
                                    decoration: BoxDecoration(
                                      shape: BoxShape.circle,
                                      color: seedColor,
                                      boxShadow: [
                                        BoxShadow(
                                          color: seedColor.withValues(
                                            alpha: 0.3,
                                          ),
                                          blurRadius: 8,
                                          offset: const Offset(0, 2),
                                        ),
                                      ],
                                    ),
                                    child: isSelected
                                        ? const Icon(
                                            Icons.check,
                                            color: Colors.white,
                                            size: 18,
                                          )
                                        : null,
                                  ),
                                  const SizedBox(width: 12),
                                  Expanded(
                                    child: Text(
                                      themeProvider.getThemeDisplayName(
                                        themeName,
                                      ),
                                      style: Theme.of(context)
                                          .textTheme
                                          .bodyMedium
                                          ?.copyWith(
                                            fontWeight: isSelected
                                                ? FontWeight.w600
                                                : FontWeight.w500,
                                            color: isSelected
                                                ? colorScheme.onPrimaryContainer
                                                : colorScheme.onSurface,
                                          ),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  void _showLanguageSelector(
    BuildContext context,
    LocaleProvider localeProvider,
  ) {
    final l10n = AppLocalizations.of(context);
    final colorScheme = Theme.of(context).colorScheme;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) {
        return DraggableScrollableSheet(
          initialChildSize: 0.5,
          minChildSize: 0.3,
          maxChildSize: 0.8,
          expand: false,
          builder: (context, scrollController) {
            return SafeArea(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
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
                      l10n?.language ?? '语言',
                      style: Theme.of(context).textTheme.headlineSmall
                          ?.copyWith(fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 16),
                    Expanded(
                      child: ListView.builder(
                        controller: scrollController,
                        itemCount: LocaleProvider.supportedLocales.length,
                        itemBuilder: (context, index) {
                          final localeInfo =
                              LocaleProvider.supportedLocales[index];
                          final isSelected =
                              localeProvider.currentLocale == localeInfo.locale;

                          return Card(
                            elevation: 0,
                            color: isSelected
                                ? colorScheme.primaryContainer
                                : colorScheme.surfaceContainerLow,
                            margin: const EdgeInsets.only(bottom: 8),
                            child: ListTile(
                              leading: Container(
                                width: 32,
                                height: 32,
                                decoration: BoxDecoration(
                                  color: isSelected
                                      ? colorScheme.primary
                                      : colorScheme.surfaceContainerHighest,
                                  borderRadius: BorderRadius.circular(8),
                                ),
                                child: Center(
                                  child: Text(
                                    localeInfo.flag,
                                    style: const TextStyle(fontSize: 16),
                                  ),
                                ),
                              ),
                              title: Text(
                                localeInfo.name,
                                style: TextStyle(
                                  fontWeight: isSelected
                                      ? FontWeight.w600
                                      : FontWeight.normal,
                                  color: isSelected
                                      ? colorScheme.onPrimaryContainer
                                      : colorScheme.onSurface,
                                ),
                              ),
                              trailing: isSelected
                                  ? Icon(
                                      Icons.check_circle,
                                      color: colorScheme.primary,
                                    )
                                  : null,
                              onTap: () {
                                localeProvider.setLocale(localeInfo.locale);
                                Navigator.pop(context);
                              },
                            ),
                          );
                        },
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }
}
