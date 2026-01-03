import 'package:flutter/material.dart';
import 'package:flutter/gestures.dart';
import 'package:provider/provider.dart';
import 'package:veloguard/src/providers/proxies_provider.dart';
import 'package:veloguard/src/services/config_converter.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/utils/animation_utils.dart';

class ProxiesScreen extends StatefulWidget {
  const ProxiesScreen({super.key});

  @override
  State<ProxiesScreen> createState() => _ProxiesScreenState();
}

class _ProxiesScreenState extends State<ProxiesScreen>
    with TickerProviderStateMixin {
  late AnimationController _headerController;

  @override
  void initState() {
    super.initState();
    _headerController = AnimationController(
      vsync: this,
      duration: AnimationUtils.durationMedium4,
    );
    _headerController.forward();

    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<ProxiesProvider>().loadFromActiveProfile();
    });
  }

  @override
  void dispose() {
    _headerController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Consumer<ProxiesProvider>(
      builder: (context, provider, child) {
        if (provider.isLoading) {
          return _buildLoadingState(colorScheme, textTheme, l10n);
        }

        if (provider.error != null && provider.config == null) {
          return _buildErrorState(context, l10n, colorScheme, textTheme);
        }

        if (provider.config == null || provider.proxyGroups.isEmpty) {
          return _buildEmptyState(context, l10n, colorScheme, textTheme);
        }

        return _buildMainContent(
          context,
          provider,
          l10n,
          colorScheme,
          textTheme,
        );
      },
    );
  }

  Widget _buildLoadingState(
    ColorScheme colorScheme,
    TextTheme textTheme,
    AppLocalizations? l10n,
  ) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 16),
            Text(
              l10n?.loading ?? 'Loading...',
              style: textTheme.bodyMedium?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildErrorState(
    BuildContext context,
    AppLocalizations? l10n,
    ColorScheme colorScheme,
    TextTheme textTheme,
  ) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              // Header
              Row(
                children: [
                  Text(
                    l10n?.proxies ?? 'Proxies',
                    style: textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
              const Spacer(),
              Icon(
                Icons.cloud_off_rounded,
                size: 64,
                color: colorScheme.outline,
              ),
              const SizedBox(height: 16),
              Text(
                l10n?.noActiveProfile ?? 'Please select a profile first',
                style: textTheme.titleMedium,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                l10n?.goToProfiles ?? 'Go to Profiles',
                style: textTheme.bodyMedium?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              FilledButton.icon(
                onPressed: () => Navigator.of(context).pushNamed('/profiles'),
                icon: const Icon(Icons.folder_open_rounded),
                label: Text(l10n?.profiles ?? 'Profiles'),
              ),
              const Spacer(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildEmptyState(
    BuildContext context,
    AppLocalizations? l10n,
    ColorScheme colorScheme,
    TextTheme textTheme,
  ) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              Row(
                children: [
                  Text(
                    l10n?.proxies ?? 'Proxies',
                    style: textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
              const Spacer(),
              Icon(Icons.dns_rounded, size: 64, color: colorScheme.outline),
              const SizedBox(height: 16),
              Text(
                l10n?.noProxies ?? 'No proxies available',
                style: textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Text(
                l10n?.noProxyNodes ?? 'No proxy nodes found in config',
                style: textTheme.bodyMedium?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
              const Spacer(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildMainContent(
    BuildContext context,
    ProxiesProvider provider,
    AppLocalizations? l10n,
    ColorScheme colorScheme,
    TextTheme textTheme,
  ) {
    return Scaffold(
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header - 紧贴顶部
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 16, 24, 0),
              child: Row(
                children: [
                  Text(
                    l10n?.proxies ?? 'Proxies',
                    style: textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const Icon(Icons.refresh_rounded),
                    onPressed: () => provider.loadFromActiveProfile(),
                    tooltip: l10n?.refresh ?? 'Refresh',
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            // 代理组选择�?
            _buildGroupSelector(
              context,
              provider,
              l10n,
              colorScheme,
              textTheme,
            ),
            const SizedBox(height: 16),
            // 代理列表
            Expanded(
              child: provider.selectedGroup != null
                  ? _buildProxiesGrid(
                      context,
                      provider,
                      l10n,
                      colorScheme,
                      textTheme,
                    )
                  : const SizedBox.shrink(),
            ),
          ],
        ),
      ),
      floatingActionButton: _buildSpeedTestFab(context, provider, colorScheme),
    );
  }

  Widget _buildGroupSelector(
    BuildContext context,
    ProxiesProvider provider,
    AppLocalizations? l10n,
    ColorScheme colorScheme,
    TextTheme textTheme,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Section header
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Row(
            children: [
              Icon(Icons.layers_rounded, size: 16, color: colorScheme.primary),
              const SizedBox(width: 8),
              Text(
                l10n?.proxyGroups ?? 'Proxy Groups',
                style: textTheme.labelMedium?.copyWith(
                  color: colorScheme.primary,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: colorScheme.primaryContainer,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  '${provider.proxyGroups.length}',
                  style: textTheme.labelSmall?.copyWith(
                    color: colorScheme.onPrimaryContainer,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        // 横向滚动的代理组列表
        SizedBox(
          height: 48,
          child: ScrollConfiguration(
            behavior: ScrollConfiguration.of(context).copyWith(
              dragDevices: {
                PointerDeviceKind.touch,
                PointerDeviceKind.mouse,
                PointerDeviceKind.trackpad,
              },
            ),
            child: ListView.builder(
              scrollDirection: Axis.horizontal,
              physics: const BouncingScrollPhysics(
                parent: AlwaysScrollableScrollPhysics(),
              ),
              padding: const EdgeInsets.symmetric(horizontal: 20),
              itemCount: provider.proxyGroups.length,
              itemBuilder: (context, index) {
                final group = provider.proxyGroups[index];
                final isSelected = group.name == provider.selectedGroupName;
                return Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: _buildGroupChip(
                    context,
                    group,
                    isSelected,
                    colorScheme,
                    textTheme,
                    () => provider.selectGroup(group.name),
                  ),
                );
              },
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildGroupChip(
    BuildContext context,
    ParsedProxyGroup group,
    bool isSelected,
    ColorScheme colorScheme,
    TextTheme textTheme,
    VoidCallback onTap,
  ) {
    final icon = _getGroupIcon(group.type);
    return ExpressiveButton(
      onPressed: onTap,
      pressedScale: 0.95,
      child: AnimatedContainer(
        duration: AnimationUtils.stateChangeDuration,
        curve: AnimationUtils.curveSpring,
        decoration: BoxDecoration(
          color: isSelected
              ? colorScheme.primaryContainer
              : colorScheme.surfaceContainerHigh,
          borderRadius: BorderRadius.circular(12),
          boxShadow: isSelected
              ? [
                  BoxShadow(
                    color: colorScheme.primary.withValues(alpha: 0.2),
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ]
              : null,
        ),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              AnimatedContainer(
                duration: AnimationUtils.durationMedium2,
                child: Icon(
                  icon,
                  size: 16,
                  color: isSelected
                      ? colorScheme.onPrimaryContainer
                      : colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(width: 8),
              Text(
                _getDisplayName(group.name),
                style: textTheme.labelMedium?.copyWith(
                  color: isSelected
                      ? colorScheme.onPrimaryContainer
                      : colorScheme.onSurface,
                  fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
                ),
              ),
              const SizedBox(width: 6),
              AnimatedContainer(
                duration: AnimationUtils.durationMedium2,
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                decoration: BoxDecoration(
                  color: isSelected
                      ? colorScheme.primary.withValues(alpha: 0.2)
                      : colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  '${group.proxies.length}',
                  style: textTheme.labelSmall?.copyWith(
                    color: isSelected
                        ? colorScheme.onPrimaryContainer
                        : colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildProxiesGrid(
    BuildContext context,
    ProxiesProvider provider,
    AppLocalizations? l10n,
    ColorScheme colorScheme,
    TextTheme textTheme,
  ) {
    final group = provider.selectedGroup!;
    final items = provider.getProxiesForGroup(group);
    final selectedProxy = provider.getSelectedProxyForGroup(group.name);

    final screenWidth = MediaQuery.of(context).size.width;
    final crossAxisCount = _calculateColumns(screenWidth);

    return GridView.builder(
      padding: const EdgeInsets.fromLTRB(20, 0, 20, 100),
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: crossAxisCount,
        mainAxisSpacing: 10,
        crossAxisSpacing: 10,
        childAspectRatio: 1.2, // 调整比例以适应三行内容
      ),
      itemCount: items.length,
      itemBuilder: (context, index) {
        final item = items[index];
        return _buildProxyItem(
          context,
          l10n,
          colorScheme,
          textTheme,
          item: item,
          selectedProxy: selectedProxy,
          group: group,
          provider: provider,
        );
      },
    );
  }

  int _calculateColumns(double width) {
    if (width >= 1400) return 6;
    if (width >= 1200) return 5;
    if (width >= 900) return 4;
    if (width >= 600) return 3;
    return 2;
  }

  Widget _buildProxyItem(
    BuildContext context,
    AppLocalizations? l10n,
    ColorScheme colorScheme,
    TextTheme textTheme, {
    required dynamic item,
    required String? selectedProxy,
    required ParsedProxyGroup group,
    required ProxiesProvider provider,
  }) {
    if (item is ParsedProxy) {
      final latency = provider.getLatency(item.name);
      return _ProxyCard(
        name: item.name,
        type: item.displayType,
        isSelected: item.name == selectedProxy,
        onTap: () => provider.selectProxyInGroup(group.name, item.name),
        latency: latency,
        colorScheme: colorScheme,
        textTheme: textTheme,
        l10n: l10n,
      );
    } else if (item is ParsedProxyGroup) {
      return _ProxyCard(
        name: item.name,
        type: '${item.proxies.length} ${l10n?.nodes ?? 'nodes'}',
        isSelected: item.name == selectedProxy,
        onTap: () => provider.selectProxyInGroup(group.name, item.name),
        isGroup: true,
        colorScheme: colorScheme,
        textTheme: textTheme,
        l10n: l10n,
      );
    } else if (item is String) {
      return _SpecialCard(
        name: item,
        isSelected: item == selectedProxy,
        onTap: () => provider.selectProxyInGroup(group.name, item),
        colorScheme: colorScheme,
        textTheme: textTheme,
      );
    }
    return const SizedBox.shrink();
  }

  Widget _buildSpeedTestFab(
    BuildContext context,
    ProxiesProvider provider,
    ColorScheme colorScheme,
  ) {
    final l10n = AppLocalizations.of(context);
    return FloatingActionButton.extended(
      onPressed: provider.isTesting ? null : () => provider.testAllLatencies(),
      backgroundColor: provider.isTesting
          ? colorScheme.surfaceContainerHighest
          : null,
      icon: provider.isTesting
          ? SizedBox(
              width: 20,
              height: 20,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: colorScheme.primary,
              ),
            )
          : const Icon(Icons.wifi_tethering_rounded),
      label: Text(
        provider.isTesting
            ? (l10n?.loading ?? 'Testing...')
            : (l10n?.latencyTest ?? 'Latency Test'),
      ),
    );
  }

  IconData _getGroupIcon(String type) {
    switch (type.toLowerCase()) {
      case 'select':
        return Icons.touch_app_rounded;
      case 'url-test':
        return Icons.speed_rounded;
      case 'fallback':
        return Icons.swap_horiz_rounded;
      case 'load-balance':
        return Icons.balance_rounded;
      default:
        return Icons.folder_rounded;
    }
  }

  String _getDisplayName(String name) {
    final emojiPattern = RegExp(r'^[\u{1F300}-\u{1F9FF}]+ ?', unicode: true);
    return name.replaceFirst(emojiPattern, '').trim();
  }
}

// 代理卡片组件 - 优化显示，名称可滚动
class _ProxyCard extends StatelessWidget {
  final String name;
  final String type;
  final bool isSelected;
  final VoidCallback onTap;
  final LatencyResult? latency;
  final bool isGroup;
  final ColorScheme colorScheme;
  final TextTheme textTheme;
  final AppLocalizations? l10n;

  const _ProxyCard({
    required this.name,
    required this.type,
    required this.isSelected,
    required this.onTap,
    this.latency,
    this.isGroup = false,
    required this.colorScheme,
    required this.textTheme,
    this.l10n,
  });

  @override
  Widget build(BuildContext context) {
    final flag = _getCountryFlag(name);
    final displayName = _getDisplayName(name);

    return ExpressiveButton(
      onPressed: onTap,
      pressedScale: 0.96,
      child: AnimatedContainer(
        duration: AnimationUtils.stateChangeDuration,
        curve: AnimationUtils.curveSpring,
        decoration: BoxDecoration(
          color: isSelected
              ? colorScheme.primaryContainer
              : colorScheme.surfaceContainerLow,
          borderRadius: BorderRadius.circular(14),
          boxShadow: isSelected
              ? [
                  BoxShadow(
                    color: colorScheme.primary.withValues(alpha: 0.2),
                    blurRadius: 12,
                    offset: const Offset(0, 4),
                  ),
                ]
              : null,
          border: Border.all(
            color: isSelected
                ? colorScheme.primary.withValues(alpha: 0.3)
                : colorScheme.outlineVariant.withValues(alpha: 0.3),
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Padding(
          padding: const EdgeInsets.all(10),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // 顶部：国�?图标 + 选中标记
              Row(
                children: [
                  if (flag != null)
                    Text(flag, style: const TextStyle(fontSize: 18))
                  else if (isGroup)
                    _buildIcon(
                      Icons.folder_rounded,
                      colorScheme.tertiaryContainer,
                      colorScheme.onTertiaryContainer,
                    )
                  else
                    _buildIcon(
                      Icons.public_rounded,
                      colorScheme.surfaceContainerHighest,
                      colorScheme.onSurfaceVariant,
                    ),
                  const Spacer(),
                  AnimatedScale(
                    scale: isSelected ? 1.0 : 0.0,
                    duration: AnimationUtils.durationMedium2,
                    curve: AnimationUtils.curveSpring,
                    child: Container(
                      padding: const EdgeInsets.all(2),
                      decoration: BoxDecoration(
                        color: colorScheme.primary,
                        shape: BoxShape.circle,
                      ),
                      child: Icon(
                        Icons.check_rounded,
                        size: 10,
                        color: colorScheme.onPrimary,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              // 名称 - 单独一行，可滚�?
              Expanded(
                child: _MarqueeText(
                  text: displayName,
                  style: textTheme.labelMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                    color: isSelected
                        ? colorScheme.onPrimaryContainer
                        : colorScheme.onSurface,
                  ),
                ),
              ),
              const SizedBox(height: 4),
              // 底部：类�?+ 延迟
              Row(
                children: [
                  _buildTypeBadge(),
                  const Spacer(),
                  if (!isGroup) _buildLatencyBadge(),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildIcon(IconData icon, Color bgColor, Color iconColor) {
    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: bgColor,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Icon(icon, size: 14, color: iconColor),
    );
  }

  Widget _buildTypeBadge() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
      decoration: BoxDecoration(
        color: isSelected
            ? colorScheme.primary.withValues(alpha: 0.15)
            : colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        type,
        style: textTheme.labelSmall?.copyWith(
          fontSize: 9,
          color: isSelected
              ? colorScheme.primary
              : colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }

  Widget _buildLatencyBadge() {
    final latencyColor = _getLatencyColor();
    final latencyText = _getLatencyText();

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
      decoration: BoxDecoration(
        color: latencyColor.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        latencyText,
        style: textTheme.labelSmall?.copyWith(
          fontSize: 9,
          color: latencyColor,
          fontWeight: FontWeight.w500,
        ),
      ),
    );
  }

  Color _getLatencyColor() {
    if (latency == null) return colorScheme.outline;
    if (!latency!.isSuccess) return colorScheme.error;
    final ms = latency!.latencyMs ?? 0;
    if (ms < 100) return Colors.green;
    if (ms < 300) return Colors.orange;
    return colorScheme.error;
  }

  String _getLatencyText() {
    if (latency == null) return l10n?.notTested ?? 'N/A';
    if (!latency!.isSuccess) {
      final error = latency!.error?.toLowerCase() ?? '';
      if (error.contains('timeout')) return l10n?.timeout ?? 'Timeout';
      return l10n?.failed ?? 'Failed';
    }
    return '${latency!.latencyMs ?? 0}ms';
  }

  String? _getCountryFlag(String name) {
    // 先检查名称中是否已经包含 emoji 国旗
    final emojiPattern = RegExp(r'[\u{1F1E0}-\u{1F1FF}]{2}', unicode: true);
    final existingFlag = emojiPattern.firstMatch(name);
    if (existingFlag != null) {
      // 名称中已有国旗，不再添加
      return null;
    }

    final patterns = {
      '🇭🇰': ['香港', 'Hong Kong'],
      '🇯🇵': ['日本', 'Japan'],
      '🇸🇬': ['新加坡', 'Singapore'],
      '🇺🇸': ['美国', 'United States', 'USA'],
      '🇹🇼': ['台湾', 'Taiwan'],
      '🇰🇷': ['韩国', 'Korea'],
      '🇬🇧': ['英国', 'United Kingdom'],
      '🇩🇪': ['德国', 'Germany'],
      '🇫🇷': ['法国', 'France'],
      '🇦🇺': ['澳大利亚', 'Australia'],
      '🇨🇦': ['加拿大', 'Canada'],
      '🇷🇺': ['俄罗斯', 'Russia'],
      '🇮🇳': ['印度', 'India'],
      '🇳🇱': ['荷兰', 'Netherlands'],
    };

    // 检查名称中是否包含国家/地区关键词（不包括短代码如 HK、JP）
    for (final entry in patterns.entries) {
      for (final pattern in entry.value) {
        if (name.contains(pattern)) {
          return entry.key;
        }
      }
    }
    return null;
  }

  String _getDisplayName(String name) {
    final emojiPattern = RegExp(r'^[\u{1F300}-\u{1F9FF}]+ ?', unicode: true);
    return name.replaceFirst(emojiPattern, '').trim();
  }
}

/// 滚动文字组件 - 文字过长时自动滚�?
class _MarqueeText extends StatefulWidget {
  final String text;
  final TextStyle? style;

  const _MarqueeText({required this.text, this.style});

  @override
  State<_MarqueeText> createState() => _MarqueeTextState();
}

class _MarqueeTextState extends State<_MarqueeText>
    with SingleTickerProviderStateMixin {
  late ScrollController _scrollController;
  bool _needsScroll = false;
  bool _isScrolling = false;

  @override
  void initState() {
    super.initState();
    _scrollController = ScrollController();
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkOverflow());
  }

  @override
  void didUpdateWidget(_MarqueeText oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.text != oldWidget.text) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _checkOverflow());
    }
  }

  void _checkOverflow() {
    if (!mounted) return;
    final maxScroll = _scrollController.position.maxScrollExtent;
    setState(() {
      _needsScroll = maxScroll > 0;
    });
    if (_needsScroll && !_isScrolling) {
      _startScrolling();
    }
  }

  void _startScrolling() async {
    if (!mounted || !_needsScroll) return;
    _isScrolling = true;

    while (mounted && _needsScroll) {
      await Future.delayed(const Duration(seconds: 2));
      if (!mounted) break;

      final maxScroll = _scrollController.position.maxScrollExtent;
      if (maxScroll <= 0) break;

      await _scrollController.animateTo(
        maxScroll,
        duration: Duration(
          milliseconds: (maxScroll * 30).toInt().clamp(1000, 5000),
        ),
        curve: Curves.linear,
      );

      if (!mounted) break;
      await Future.delayed(const Duration(seconds: 1));

      if (!mounted) break;
      await _scrollController.animateTo(
        0,
        duration: const Duration(milliseconds: 500),
        curve: Curves.easeOut,
      );
    }
    _isScrolling = false;
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      controller: _scrollController,
      scrollDirection: Axis.horizontal,
      physics: const NeverScrollableScrollPhysics(),
      child: Text(widget.text, style: widget.style, maxLines: 1),
    );
  }
}

// 特殊卡片（DIRECT/REJECT�?
class _SpecialCard extends StatelessWidget {
  final String name;
  final bool isSelected;
  final VoidCallback onTap;
  final ColorScheme colorScheme;
  final TextTheme textTheme;

  const _SpecialCard({
    required this.name,
    required this.isSelected,
    required this.onTap,
    required this.colorScheme,
    required this.textTheme,
  });

  @override
  Widget build(BuildContext context) {
    final isDirect = name == 'DIRECT';
    final isReject = name == 'REJECT';
    final icon = isDirect
        ? Icons.arrow_forward_rounded
        : isReject
        ? Icons.block_rounded
        : Icons.help_outline_rounded;
    final label = isDirect
        ? '直连'
        : isReject
        ? '拒绝'
        : name;
    final desc = isDirect
        ? '不使用代理'
        : isReject
        ? '拒绝连接'
        : '未知类型';
    final iconColor = isDirect
        ? colorScheme.tertiary
        : isReject
        ? colorScheme.error
        : colorScheme.outline;

    return ExpressiveButton(
      onPressed: onTap,
      pressedScale: 0.96,
      child: AnimatedContainer(
        duration: AnimationUtils.stateChangeDuration,
        curve: AnimationUtils.curveSpring,
        decoration: BoxDecoration(
          color: isSelected
              ? colorScheme.primaryContainer
              : colorScheme.surfaceContainerLow,
          borderRadius: BorderRadius.circular(14),
          boxShadow: isSelected
              ? [
                  BoxShadow(
                    color: colorScheme.primary.withValues(alpha: 0.2),
                    blurRadius: 12,
                    offset: const Offset(0, 4),
                  ),
                ]
              : null,
          border: Border.all(
            color: isSelected
                ? colorScheme.primary.withValues(alpha: 0.3)
                : colorScheme.outlineVariant.withValues(alpha: 0.3),
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  AnimatedContainer(
                    duration: AnimationUtils.durationMedium2,
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: iconColor.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Icon(icon, size: 16, color: iconColor),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      label,
                      style: textTheme.labelLarge?.copyWith(
                        fontWeight: FontWeight.w600,
                        color: isSelected
                            ? colorScheme.onPrimaryContainer
                            : colorScheme.onSurface,
                      ),
                    ),
                  ),
                  AnimatedScale(
                    scale: isSelected ? 1.0 : 0.0,
                    duration: AnimationUtils.durationMedium2,
                    curve: AnimationUtils.curveSpring,
                    child: Container(
                      padding: const EdgeInsets.all(2),
                      decoration: BoxDecoration(
                        color: colorScheme.primary,
                        shape: BoxShape.circle,
                      ),
                      child: Icon(
                        Icons.check_rounded,
                        size: 10,
                        color: colorScheme.onPrimary,
                      ),
                    ),
                  ),
                ],
              ),
              const Spacer(),
              Text(
                desc,
                style: textTheme.bodySmall?.copyWith(
                  fontSize: 11,
                  color: isSelected
                      ? colorScheme.onPrimaryContainer.withValues(alpha: 0.7)
                      : colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
