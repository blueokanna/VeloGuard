import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:veloguard/src/services/platform_proxy_service.dart';
import 'package:veloguard/src/providers/app_state_provider.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/utils/platform_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';

class QuickActions extends StatefulWidget {
  const QuickActions({super.key});

  @override
  State<QuickActions> createState() => _QuickActionsState();
}

class _QuickActionsState extends State<QuickActions> {
  bool _systemProxyEnabled = false;
  bool _isProxyLoading = false;
  Timer? _statusCheckTimer;

  ProxyMode _currentProxyMode = ProxyMode.rule;
  bool _isUpdating = false;

  @override
  void initState() {
    super.initState();
    _checkProxyStatus();
    _statusCheckTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => _checkProxyStatus(),
    );
  }

  @override
  void dispose() {
    _statusCheckTimer?.cancel();
    super.dispose();
  }

  Future<void> _checkProxyStatus() async {
    if (_isUpdating) return;

    try {
      final proxyStatus = await PlatformProxyService.instance
          .checkSystemProxyStatus();
      if (mounted) {
        setState(() {
          _systemProxyEnabled = proxyStatus;
          if (Platform.isAndroid || PlatformUtils.isOHOS) {
            _currentProxyMode = PlatformProxyService.instance.currentProxyMode;
          }
        });
      }
    } catch (e) {
      debugPrint('Failed to check proxy status: $e');
    }
  }

  Future<void> _toggleSystemProxy(bool enable) async {
    if (_isProxyLoading || _isUpdating) return;

    if (Platform.isAndroid || PlatformUtils.isOHOS) {
      return;
    }

    setState(() {
      _isProxyLoading = true;
      _isUpdating = true;
    });

    try {
      bool success;
      if (enable) {
        success = await PlatformProxyService.instance.enableSystemProxy(
          host: '127.0.0.1',
          httpPort: 7890,
          socksPort: 7891,
        );
      } else {
        success = await PlatformProxyService.instance.disableSystemProxy();
      }

      if (success) {
        setState(() => _systemProxyEnabled = enable);
        AnimationUtils.mediumHaptic();
        if (!mounted) return;
        final l10n = AppLocalizations.of(context);
        _showSnackBar(
          enable
              ? (l10n?.systemProxyEnabled ?? 'System proxy enabled')
              : (l10n?.systemProxyDisabled ?? 'System proxy disabled'),
        );
      } else {
        await _checkProxyStatus();
        if (!mounted) return;
        final l10n = AppLocalizations.of(context);
        _showSnackBar(
          enable
              ? (l10n?.enableSystemProxyFailed ??
                    'Failed to enable system proxy')
              : (l10n?.disableSystemProxyFailed ??
                    'Failed to disable system proxy'),
          isError: true,
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isProxyLoading = false;
          _isUpdating = false;
        });
      }
    }
  }

  Future<void> _switchProxyMode(ProxyMode mode) async {
    if (_isUpdating) return;

    // 检查服务是否正在运行
    final appState = context.read<AppStateProvider>();
    if (!appState.isServiceRunning) {
      if (!mounted) return;
      _showSnackBar('Please start the service first', isError: true);
      return;
    }

    setState(() {
      _isUpdating = true;
    });

    try {
      final success = await PlatformProxyService.instance.setProxyMode(mode);
      if (success) {
        setState(() => _currentProxyMode = mode);
        AnimationUtils.selectionHaptic();
        if (!mounted) return;
        final l10n = AppLocalizations.of(context);
        final modeText = mode == ProxyMode.global
            ? (l10n?.globalProxy ?? 'Global Proxy')
            : (l10n?.ruleMode ?? 'Rule Mode');
        _showSnackBar('${l10n?.switchedTo ?? "Switched to"} $modeText');
      }
    } finally {
      if (mounted) {
        setState(() {
          _isUpdating = false;
        });
      }
    }
  }

  void _showSnackBar(String message, {bool isError = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        backgroundColor: isError ? Theme.of(context).colorScheme.error : null,
        duration: const Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final spacing = ResponsiveUtils.getSpacing(context);
    final isMobile =
        Platform.isAndroid || PlatformUtils.isOHOS || Platform.isIOS;

    if (isMobile) {
      return _buildMobileLayout(colorScheme, spacing);
    }
    return _buildDesktopLayout(colorScheme, spacing);
  }

  Widget _buildMobileLayout(ColorScheme colorScheme, double spacing) {
    final appState = context.watch<AppStateProvider>();
    final isServiceRunning = appState.isServiceRunning;
    final tunEnabled = PlatformProxyService.instance.tunModeEnabled;

    return Column(
      children: [
        // 服务状态显示
        _ServiceStatusCard(
          isRunning: isServiceRunning,
          isTunEnabled: tunEnabled,
          currentMode: _currentProxyMode,
        ),
        SizedBox(height: spacing * 2),
        // 模式选择按钮组(仅在服务运行时可用)
        _ProxyModeSelectorSimple(
          currentMode: _currentProxyMode,
          isEnabled: isServiceRunning && tunEnabled,
          isLoading: _isUpdating,
          onModeSelected: _switchProxyMode,
        ),
        SizedBox(height: spacing * 2),
        // 模式说明卡片
        _buildModeExplanation(colorScheme),
      ],
    );
  }

  Widget _buildDesktopLayout(ColorScheme colorScheme, double spacing) {
    final l10n = AppLocalizations.of(context);
    return Row(
      children: [
        Expanded(
          child: _ProxyCard(
            icon: Icons.language_rounded,
            title: l10n?.systemProxy ?? 'System Proxy',
            subtitle: _systemProxyEnabled
                ? (l10n?.enabled ?? 'Enabled')
                : (l10n?.disabled ?? 'Disabled'),
            description:
                l10n?.setSystemHttpSocksProxy ?? 'Set system HTTP/SOCKS proxy',
            isEnabled: _systemProxyEnabled,
            isLoading: _isProxyLoading,
            onToggle: _toggleSystemProxy,
          ),
        ),
      ],
    );
  }

  Widget _buildModeExplanation(ColorScheme colorScheme) {
    final textTheme = Theme.of(context).textTheme;
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final l10n = AppLocalizations.of(context);
    final tunEnabled = PlatformProxyService.instance.tunModeEnabled;

    return AnimatedContainer(
      duration: AnimationUtils.stateChangeDuration,
      curve: AnimationUtils.curveEmphasized,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(
          color: colorScheme.outlineVariant.withValues(alpha: 0.5),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                Icons.info_outline_rounded,
                size: 18,
                color: colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Text(
                l10n?.proxyModeDesc ?? 'Proxy Mode Description',
                style: textTheme.titleSmall?.copyWith(
                  fontWeight: FontWeight.w600,
                  color: colorScheme.primary,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          _buildModeExplanationItem(
            colorScheme,
            textTheme,
            icon: Icons.rule_rounded,
            title: l10n?.ruleMode ?? 'Rule Mode',
            description:
                l10n?.ruleModeDesc ??
                'Route traffic based on rules, domestic direct, foreign proxy',
            isActive: _currentProxyMode == ProxyMode.rule && tunEnabled,
          ),
          const SizedBox(height: 8),
          _buildModeExplanationItem(
            colorScheme,
            textTheme,
            icon: Icons.public_rounded,
            title: l10n?.globalProxy ?? 'Global Proxy',
            description:
                l10n?.globalModeDesc ?? 'All traffic goes through proxy server',
            isActive: _currentProxyMode == ProxyMode.global && tunEnabled,
          ),
        ],
      ),
    );
  }

  Widget _buildModeExplanationItem(
    ColorScheme colorScheme,
    TextTheme textTheme, {
    required IconData icon,
    required String title,
    required String description,
    required bool isActive,
  }) {
    return AnimatedContainer(
      duration: AnimationUtils.durationMedium2,
      curve: AnimationUtils.curveEmphasized,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: isActive
            ? colorScheme.primaryContainer.withValues(alpha: 0.5)
            : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(
            icon,
            size: 20,
            color: isActive
                ? colorScheme.primary
                : colorScheme.onSurfaceVariant,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: textTheme.bodyMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                    color: isActive
                        ? colorScheme.primary
                        : colorScheme.onSurface,
                  ),
                ),
                Text(
                  description,
                  style: textTheme.bodySmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
          if (isActive)
            Icon(
              Icons.check_circle_rounded,
              size: 18,
              color: colorScheme.primary,
            ),
        ],
      ),
    );
  }
}

/// 服务状态卡片 - 显示当前服务和VPN状态
class _ServiceStatusCard extends StatelessWidget {
  final bool isRunning;
  final bool isTunEnabled;
  final ProxyMode currentMode;

  const _ServiceStatusCard({
    required this.isRunning,
    required this.isTunEnabled,
    required this.currentMode,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final l10n = AppLocalizations.of(context);

    final isActive = isRunning && isTunEnabled;

    return AnimatedContainer(
      duration: AnimationUtils.stateChangeDuration,
      curve: AnimationUtils.curveEmphasized,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(borderRadius),
        gradient: isActive
            ? LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  colorScheme.primaryContainer,
                  colorScheme.primaryContainer.withValues(alpha: 0.7),
                ],
              )
            : null,
        color: isActive ? null : colorScheme.surfaceContainerHigh,
        boxShadow: isActive
            ? [
                BoxShadow(
                  color: colorScheme.primary.withValues(alpha: 0.2),
                  blurRadius: 16,
                  offset: const Offset(0, 4),
                ),
              ]
            : null,
      ),
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            // 图标
            AnimatedContainer(
              duration: AnimationUtils.stateChangeDuration,
              curve: AnimationUtils.curveSpring,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: isActive
                    ? colorScheme.primary
                    : colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(borderRadius * 0.7),
              ),
              child: AnimatedSwitcher(
                duration: AnimationUtils.iconMorphDuration,
                transitionBuilder: (child, animation) {
                  return ScaleTransition(scale: animation, child: child);
                },
                child: Icon(
                  isActive ? Icons.vpn_lock_rounded : Icons.vpn_lock_outlined,
                  key: ValueKey(isActive),
                  size: 28,
                  color: isActive
                      ? colorScheme.onPrimary
                      : colorScheme.onSurfaceVariant,
                ),
              ),
            ),
            const SizedBox(width: 16),
            // 文字
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    l10n?.vpnProxy ?? 'VPN Proxy',
                    style: textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                      color: isActive
                          ? colorScheme.onPrimaryContainer
                          : colorScheme.onSurface,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      AnimatedContainer(
                        duration: AnimationUtils.durationMedium2,
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: isActive
                              ? Colors.green
                              : isRunning
                              ? Colors.orange
                              : colorScheme.outline,
                        ),
                      ),
                      const SizedBox(width: 6),
                      Text(
                        isActive
                            ? (currentMode == ProxyMode.global
                                  ? (l10n?.globalModeRunning ??
                                        'Global proxy running')
                                  : (l10n?.ruleModeRunning ??
                                        'Rule mode running'))
                            : isRunning
                            ? 'VPN starting...'
                            : (l10n?.serviceNotRunning ??
                                  'Service not running'),
                        style: textTheme.bodySmall?.copyWith(
                          color: isActive
                              ? colorScheme.onPrimaryContainer.withValues(
                                  alpha: 0.8,
                                )
                              : colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            // 状态指示器
            if (isActive)
              Icon(Icons.check_circle_rounded, color: Colors.green, size: 24)
            else if (isRunning)
              SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(
                  strokeWidth: 2.5,
                  color: colorScheme.primary,
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// 简化的代理模式选择器 - 仅用于切换模式
class _ProxyModeSelectorSimple extends StatelessWidget {
  final ProxyMode currentMode;
  final bool isEnabled;
  final bool isLoading;
  final Function(ProxyMode) onModeSelected;

  const _ProxyModeSelectorSimple({
    required this.currentMode,
    required this.isEnabled,
    required this.isLoading,
    required this.onModeSelected,
  });

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);

    return IntrinsicHeight(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Expanded(
            child: _ModeButton(
              icon: Icons.rule_rounded,
              label: l10n?.ruleMode ?? 'Rule Mode',
              sublabel: l10n?.smartRouting ?? 'Smart Routing',
              isSelected: currentMode == ProxyMode.rule,
              isEnabled: isEnabled,
              isLoading: isLoading,
              onTap: () => onModeSelected(ProxyMode.rule),
              isRecommended: true,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: _ModeButton(
              icon: Icons.public_rounded,
              label: l10n?.globalProxy ?? 'Global Proxy',
              sublabel: l10n?.allProxy ?? 'All Proxy',
              isSelected: currentMode == ProxyMode.global,
              isEnabled: isEnabled,
              isLoading: isLoading,
              onTap: () => onModeSelected(ProxyMode.global),
            ),
          ),
        ],
      ),
    );
  }
}

/// 模式选择按钮
class _ModeButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final String sublabel;
  final bool isSelected;
  final bool isEnabled;
  final bool isLoading;
  final VoidCallback onTap;
  final bool isRecommended;

  const _ModeButton({
    required this.icon,
    required this.label,
    required this.sublabel,
    required this.isSelected,
    required this.isEnabled,
    required this.isLoading,
    required this.onTap,
    this.isRecommended = false,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final l10n = AppLocalizations.of(context);

    final isActive = isSelected && isEnabled;

    return ExpressiveButton(
      onPressed: isLoading ? null : onTap,
      pressedScale: 0.97,
      child: AnimatedContainer(
        duration: AnimationUtils.stateChangeDuration,
        curve: AnimationUtils.curveSpring,
        padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 12),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(borderRadius),
          color: isActive
              ? colorScheme.primaryContainer
              : colorScheme.surfaceContainerHigh,
          border: Border.all(
            color: isActive
                ? colorScheme.primary
                : isRecommended && !isEnabled
                ? colorScheme.primary.withValues(alpha: 0.5)
                : colorScheme.outlineVariant.withValues(alpha: 0.5),
            width: isActive || (isRecommended && !isEnabled) ? 2 : 1,
          ),
          boxShadow: isActive
              ? [
                  BoxShadow(
                    color: colorScheme.primary.withValues(alpha: 0.15),
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ]
              : null,
        ),
        child: Stack(
          alignment: Alignment.center,
          children: [
            Column(
              mainAxisAlignment: MainAxisAlignment.center,
              mainAxisSize: MainAxisSize.min,
              children: [
                AnimatedContainer(
                  duration: AnimationUtils.durationMedium2,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: isActive
                        ? colorScheme.primary
                        : colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(borderRadius * 0.6),
                  ),
                  child: Icon(
                    icon,
                    size: 24,
                    color: isActive
                        ? colorScheme.onPrimary
                        : colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 10),
                Text(
                  label,
                  textAlign: TextAlign.center,
                  style: textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600,
                    color: isActive
                        ? colorScheme.onPrimaryContainer
                        : colorScheme.onSurface,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  sublabel,
                  textAlign: TextAlign.center,
                  style: textTheme.bodySmall?.copyWith(
                    color: isActive
                        ? colorScheme.onPrimaryContainer.withValues(alpha: 0.7)
                        : colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
            // 推荐标签
            if (isRecommended && !isEnabled)
              Positioned(
                top: 0,
                right: 0,
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 6,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: colorScheme.primary,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    l10n?.recommended ?? 'Recommended',
                    style: textTheme.labelSmall?.copyWith(
                      color: colorScheme.onPrimary,
                      fontWeight: FontWeight.w600,
                      fontSize: 9,
                    ),
                  ),
                ),
              ),
            // 选中标记
            if (isActive)
              Positioned(
                top: 0,
                right: 0,
                child: Container(
                  padding: const EdgeInsets.all(2),
                  decoration: BoxDecoration(
                    color: colorScheme.primary,
                    shape: BoxShape.circle,
                  ),
                  child: Icon(
                    Icons.check_rounded,
                    size: 12,
                    color: colorScheme.onPrimary,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// 桌面端代理卡片
class _ProxyCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final String description;
  final bool isEnabled;
  final bool isLoading;
  final Function(bool) onToggle;

  const _ProxyCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.description,
    required this.isEnabled,
    required this.isLoading,
    required this.onToggle,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final spacing = ResponsiveUtils.getSpacing(context);

    return AnimatedContainer(
      duration: AnimationUtils.stateChangeDuration,
      curve: AnimationUtils.curveEmphasized,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(borderRadius),
        gradient: isEnabled
            ? LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  colorScheme.primaryContainer,
                  colorScheme.primaryContainer.withValues(alpha: 0.7),
                ],
              )
            : null,
        color: isEnabled ? null : colorScheme.surfaceContainerHigh,
        boxShadow: isEnabled
            ? [
                BoxShadow(
                  color: colorScheme.primary.withValues(alpha: 0.2),
                  blurRadius: 12,
                  offset: const Offset(0, 4),
                ),
              ]
            : null,
      ),
      child: Material(
        color: Colors.transparent,
        borderRadius: BorderRadius.circular(borderRadius),
        child: InkWell(
          onTap: isLoading ? null : () => onToggle(!isEnabled),
          borderRadius: BorderRadius.circular(borderRadius),
          child: Padding(
            padding: EdgeInsets.all(spacing * 2),
            child: Row(
              children: [
                AnimatedContainer(
                  duration: AnimationUtils.stateChangeDuration,
                  padding: EdgeInsets.all(spacing * 1.5),
                  decoration: BoxDecoration(
                    color: isEnabled
                        ? colorScheme.primary
                        : colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(borderRadius * 0.7),
                  ),
                  child: Icon(
                    icon,
                    size: 24,
                    color: isEnabled
                        ? colorScheme.onPrimary
                        : colorScheme.onSurfaceVariant,
                  ),
                ),
                SizedBox(width: spacing * 1.75),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w600,
                          color: isEnabled
                              ? colorScheme.onPrimaryContainer
                              : colorScheme.onSurface,
                        ),
                      ),
                      SizedBox(height: spacing * 0.25),
                      Row(
                        children: [
                          AnimatedContainer(
                            duration: AnimationUtils.durationMedium2,
                            width: 6,
                            height: 6,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: isEnabled
                                  ? Colors.green
                                  : colorScheme.outline,
                            ),
                          ),
                          SizedBox(width: spacing * 0.75),
                          Text(
                            subtitle,
                            style: textTheme.bodySmall?.copyWith(
                              color: isEnabled
                                  ? colorScheme.onPrimaryContainer.withValues(
                                      alpha: 0.7,
                                    )
                                  : colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                if (isLoading)
                  SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: isEnabled
                          ? colorScheme.onPrimaryContainer
                          : colorScheme.primary,
                    ),
                  )
                else
                  Switch(
                    value: isEnabled,
                    onChanged: isLoading ? null : onToggle,
                    activeTrackColor: colorScheme.primary,
                    thumbIcon: WidgetStateProperty.resolveWith((states) {
                      if (states.contains(WidgetState.selected)) {
                        return Icon(
                          Icons.check,
                          size: 14,
                          color: colorScheme.onPrimary,
                        );
                      }
                      return null;
                    }),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
