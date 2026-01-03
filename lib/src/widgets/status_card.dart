import 'package:flutter/material.dart';
import 'package:veloguard/src/rust/types.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';

/// Material Design 3 Expressive 风格的服务状态卡片
/// 垂直布局：上方状态信息 + 下方控制按钮
class StatusCard extends StatefulWidget {
  final bool isRunning;
  final bool isLoading;
  final ProxyStatus? proxyStatus;
  final VoidCallback onStartStop;

  const StatusCard({
    super.key,
    required this.isRunning,
    required this.isLoading,
    this.proxyStatus,
    required this.onStartStop,
  });

  @override
  State<StatusCard> createState() => _StatusCardState();
}

class _StatusCardState extends State<StatusCard> with TickerProviderStateMixin {
  late AnimationController _pulseController;
  late AnimationController _statusController;
  late Animation<double> _pulseAnimation;
  late Animation<double> _statusScaleAnimation;

  @override
  void initState() {
    super.initState();

    // 脉冲动画 - 运行时的呼吸效果
    _pulseController = AnimationController(
      duration: const Duration(milliseconds: 1800),
      vsync: this,
    );
    _pulseAnimation = Tween<double>(begin: 1.0, end: 1.15).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );

    // 状态切换动画
    _statusController = AnimationController(
      duration: AnimationUtils.stateChangeDuration,
      vsync: this,
    );
    _statusScaleAnimation = Tween<double>(begin: 0.8, end: 1.0).animate(
      CurvedAnimation(
        parent: _statusController,
        curve: AnimationUtils.curveSpring,
      ),
    );
    _statusController.forward();

    _updateAnimations();
  }

  @override
  void didUpdateWidget(StatusCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.isRunning != oldWidget.isRunning ||
        widget.isLoading != oldWidget.isLoading) {
      _updateAnimations();
      _statusController.reset();
      _statusController.forward();
    }
  }

  void _updateAnimations() {
    if (widget.isRunning && !widget.isLoading) {
      _pulseController.repeat(reverse: true);
    } else {
      _pulseController.stop();
      _pulseController.reset();
    }
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _statusController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);
    final spacing = ResponsiveUtils.getSpacing(context);
    final borderRadius = ResponsiveUtils.getBorderRadius(context);

    return ScaleTransition(
      scale: _statusScaleAnimation,
      child: Card(
        elevation: 0,
        color: colorScheme.surfaceContainerLow,
        clipBehavior: Clip.antiAlias,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(borderRadius),
          side: BorderSide(
            color: widget.isRunning
                ? colorScheme.primary.withValues(alpha: 0.3)
                : colorScheme.outlineVariant.withValues(alpha: 0.5),
            width: 1,
          ),
        ),
        child: AnimatedContainer(
          duration: AnimationUtils.stateChangeDuration,
          curve: AnimationUtils.curveEmphasized,
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: widget.isRunning
                  ? [
                      colorScheme.primaryContainer.withValues(alpha: 0.3),
                      colorScheme.surfaceContainerLow,
                    ]
                  : [
                      colorScheme.surfaceContainerLow,
                      colorScheme.surfaceContainerLow,
                    ],
            ),
          ),
          padding: EdgeInsets.all(spacing * 2),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // 上方：状态指示器和文字
              Row(
                children: [
                  _buildStatusIndicator(colorScheme, textTheme, l10n),
                  SizedBox(width: spacing * 2),
                  Expanded(
                    child: _buildStatusText(colorScheme, textTheme, l10n),
                  ),
                ],
              ),

              SizedBox(height: spacing * 2),

              // 下方：控制按钮（全宽）
              _buildControlButton(colorScheme, textTheme, l10n, borderRadius),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStatusIndicator(
    ColorScheme colorScheme,
    TextTheme textTheme,
    AppLocalizations? l10n,
  ) {
    final indicatorSize = 56.0;
    final iconSize = 28.0;

    return AnimatedBuilder(
      animation: _pulseAnimation,
      builder: (context, child) {
        return Transform.scale(
          scale: widget.isRunning && !widget.isLoading
              ? _pulseAnimation.value
              : 1.0,
          child: AnimatedContainer(
            duration: AnimationUtils.stateChangeDuration,
            curve: AnimationUtils.curveSpring,
            width: indicatorSize,
            height: indicatorSize,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: _getStatusColor(colorScheme).withValues(alpha: 0.15),
              border: Border.all(
                color: _getStatusColor(colorScheme).withValues(alpha: 0.4),
                width: 2,
              ),
            ),
            child: AnimatedSwitcher(
              duration: AnimationUtils.iconMorphDuration,
              switchInCurve: AnimationUtils.curveEmphasizedDecelerate,
              switchOutCurve: AnimationUtils.curveEmphasizedAccelerate,
              transitionBuilder: (child, animation) {
                return ScaleTransition(
                  scale: animation,
                  child: FadeTransition(opacity: animation, child: child),
                );
              },
              child: widget.isLoading
                  ? SizedBox(
                      key: const ValueKey('loading'),
                      width: iconSize,
                      height: iconSize,
                      child: CircularProgressIndicator(
                        strokeWidth: 2.5,
                        color: _getStatusColor(colorScheme),
                      ),
                    )
                  : Icon(
                      _getStatusIcon(),
                      key: ValueKey(widget.isRunning),
                      size: iconSize,
                      color: _getStatusColor(colorScheme),
                    ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildStatusText(
    ColorScheme colorScheme,
    TextTheme textTheme,
    AppLocalizations? l10n,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        // 状态标题
        AnimatedSwitcher(
          duration: AnimationUtils.stateChangeDuration,
          switchInCurve: AnimationUtils.curveSpring,
          transitionBuilder: (child, animation) {
            return SlideTransition(
              position: Tween<Offset>(
                begin: const Offset(0, 0.2),
                end: Offset.zero,
              ).animate(animation),
              child: FadeTransition(opacity: animation, child: child),
            );
          },
          child: Text(
            _getStatusText(l10n),
            key: ValueKey('${widget.isRunning}_${widget.isLoading}'),
            style: textTheme.titleLarge?.copyWith(
              color: _getStatusColor(colorScheme),
              fontWeight: FontWeight.w700,
            ),
          ),
        ),

        const SizedBox(height: 4),

        // 状态描述
        AnimatedSwitcher(
          duration: AnimationUtils.durationMedium2,
          child: Text(
            _getStatusDescription(l10n),
            key: ValueKey(_getStatusDescription(l10n)),
            style: textTheme.bodySmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }

  Widget _buildControlButton(
    ColorScheme colorScheme,
    TextTheme textTheme,
    AppLocalizations? l10n,
    double borderRadius,
  ) {
    final buttonColor = widget.isRunning
        ? colorScheme.error
        : colorScheme.primary;
    final buttonBgColor = widget.isRunning
        ? colorScheme.errorContainer
        : colorScheme.primaryContainer;
    final buttonTextColor = widget.isRunning
        ? colorScheme.onErrorContainer
        : colorScheme.onPrimaryContainer;

    return SizedBox(
      width: double.infinity,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: widget.isLoading
              ? null
              : () {
                  AnimationUtils.mediumHaptic();
                  widget.onStartStop();
                },
          borderRadius: BorderRadius.circular(borderRadius),
          child: AnimatedContainer(
            duration: AnimationUtils.stateChangeDuration,
            curve: AnimationUtils.curveEmphasized,
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
            decoration: BoxDecoration(
              color: widget.isLoading
                  ? colorScheme.surfaceContainerHighest
                  : buttonBgColor,
              borderRadius: BorderRadius.circular(borderRadius),
              boxShadow: widget.isLoading
                  ? null
                  : [
                      BoxShadow(
                        color: buttonColor.withValues(alpha: 0.2),
                        blurRadius: 8,
                        offset: const Offset(0, 2),
                      ),
                    ],
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                AnimatedSwitcher(
                  duration: AnimationUtils.iconMorphDuration,
                  transitionBuilder: (child, animation) {
                    return RotationTransition(
                      turns: Tween(begin: 0.5, end: 1.0).animate(animation),
                      child: ScaleTransition(scale: animation, child: child),
                    );
                  },
                  child: Icon(
                    widget.isLoading
                        ? Icons.hourglass_top_rounded
                        : widget.isRunning
                        ? Icons.stop_rounded
                        : Icons.play_arrow_rounded,
                    key: ValueKey(
                      'btn_${widget.isRunning}_${widget.isLoading}',
                    ),
                    size: 22,
                    color: widget.isLoading
                        ? colorScheme.onSurfaceVariant
                        : buttonTextColor,
                  ),
                ),
                const SizedBox(width: 10),
                Text(
                  widget.isLoading
                      ? (l10n?.loading ?? 'Loading...')
                      : widget.isRunning
                      ? (l10n?.stopService ?? 'Stop Service')
                      : (l10n?.startService ?? 'Start Service'),
                  style: textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600,
                    color: widget.isLoading
                        ? colorScheme.onSurfaceVariant
                        : buttonTextColor,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Color _getStatusColor(ColorScheme colorScheme) {
    if (widget.isLoading) {
      return colorScheme.tertiary;
    } else if (widget.isRunning) {
      return colorScheme.primary;
    } else {
      return colorScheme.error;
    }
  }

  IconData _getStatusIcon() {
    if (widget.isRunning) {
      return Icons.check_circle_rounded;
    } else {
      return Icons.cancel_rounded;
    }
  }

  String _getStatusText(AppLocalizations? l10n) {
    if (widget.isLoading) {
      return l10n?.starting ?? 'Starting...';
    } else if (widget.isRunning) {
      return l10n?.running ?? 'Running';
    } else {
      return l10n?.stopped ?? 'Stopped';
    }
  }

  String _getStatusDescription(AppLocalizations? l10n) {
    if (widget.isLoading) {
      return l10n?.startingService ?? 'Starting service...';
    } else if (widget.isRunning) {
      return l10n?.veloguardRunning ?? 'VeloGuard is running';
    } else {
      return l10n?.serviceNotRunning ?? 'Service not running';
    }
  }
}

/// 服务运行时的详细统计卡片（可选显示）
class ServiceStatsCard extends StatelessWidget {
  final ProxyStatus proxyStatus;

  const ServiceStatsCard({super.key, required this.proxyStatus});

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);
    final spacing = ResponsiveUtils.getSpacing(context);
    final borderRadius = ResponsiveUtils.getBorderRadius(context);

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: Padding(
        padding: EdgeInsets.all(spacing * 2),
        child: Row(
          children: [
            Expanded(
              child: _buildStatItem(
                context,
                Icons.link_rounded,
                l10n?.connections ?? 'Connections',
                proxyStatus.connectionCount.toString(),
                colorScheme.tertiary,
              ),
            ),
            _buildDivider(colorScheme),
            Expanded(
              child: _buildStatItem(
                context,
                Icons.timer_outlined,
                l10n?.uptime ?? 'Uptime',
                _formatUptime(proxyStatus.uptime),
                colorScheme.primary,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDivider(ColorScheme colorScheme) {
    return Container(
      width: 1,
      height: 40,
      color: colorScheme.outlineVariant.withValues(alpha: 0.3),
    );
  }

  Widget _buildStatItem(
    BuildContext context,
    IconData icon,
    String label,
    String value,
    Color color,
  ) {
    final textTheme = Theme.of(context).textTheme;
    final colorScheme = Theme.of(context).colorScheme;

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 20, color: color),
        const SizedBox(height: 6),
        Text(
          value,
          style: textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w700,
            color: colorScheme.onSurface,
          ),
        ),
        const SizedBox(height: 2),
        Text(
          label,
          style: textTheme.labelSmall?.copyWith(
            color: colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  String _formatUptime(BigInt uptimeBigInt) {
    final seconds = uptimeBigInt.toInt();
    final hours = seconds ~/ 3600;
    final minutes = (seconds % 3600) ~/ 60;

    if (hours > 0) {
      return '${hours}h ${minutes}m';
    } else if (minutes > 0) {
      return '${minutes}m';
    } else {
      return '${seconds}s';
    }
  }
}
