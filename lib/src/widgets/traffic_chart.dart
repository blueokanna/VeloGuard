import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:veloguard/src/rust/types.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';

/// Traffic history data point
class TrafficDataPoint {
  final DateTime timestamp;
  final double downloadSpeed;
  final double uploadSpeed;

  TrafficDataPoint({
    required this.timestamp,
    required this.downloadSpeed,
    required this.uploadSpeed,
  });
}

/// Traffic history manager - keeps last N data points
class TrafficHistoryManager {
  static const int maxDataPoints = 60;

  final Queue<TrafficDataPoint> _history = Queue<TrafficDataPoint>();

  void addDataPointWithSpeed(BigInt downloadSpeed, BigInt uploadSpeed) {
    _history.add(
      TrafficDataPoint(
        timestamp: DateTime.now(),
        downloadSpeed: downloadSpeed.toDouble(),
        uploadSpeed: uploadSpeed.toDouble(),
      ),
    );

    while (_history.length > maxDataPoints) {
      _history.removeFirst();
    }
  }

  void addDataPoint(TrafficStats stats) {
    addDataPointWithSpeed(stats.downloadSpeed, stats.uploadSpeed);
  }

  List<FlSpot> getDownloadSpots() {
    final historyList = _history.toList();
    return List.generate(historyList.length, (index) {
      final speed = historyList[index].downloadSpeed / 1024;
      return FlSpot(index.toDouble(), speed);
    });
  }

  List<FlSpot> getUploadSpots() {
    final historyList = _history.toList();
    return List.generate(historyList.length, (index) {
      final speed = historyList[index].uploadSpeed / 1024;
      return FlSpot(index.toDouble(), speed);
    });
  }

  double getMaxSpeed() {
    if (_history.isEmpty) return 100;
    double max = 0;
    for (final point in _history) {
      final downloadKb = point.downloadSpeed / 1024;
      final uploadKb = point.uploadSpeed / 1024;
      if (downloadKb > max) max = downloadKb;
      if (uploadKb > max) max = uploadKb;
    }
    return max < 10 ? 10 : max * 1.2;
  }

  void clear() {
    _history.clear();
  }
}

final trafficHistoryManager = TrafficHistoryManager();

/// 流量统计组件 - 包含下载、上传、IP 三列布局
class TrafficChart extends StatefulWidget {
  final TrafficStats trafficStats;
  final BigInt downloadSpeed;
  final BigInt uploadSpeed;
  final bool isProxyRunning;

  const TrafficChart({
    super.key,
    required this.trafficStats,
    required this.downloadSpeed,
    required this.uploadSpeed,
    this.isProxyRunning = false,
  });

  @override
  State<TrafficChart> createState() => _TrafficChartState();
}

class _TrafficChartState extends State<TrafficChart>
    with SingleTickerProviderStateMixin {
  late AnimationController _pulseController;
  String? _currentIp;
  bool _isLoadingIp = false;

  @override
  void initState() {
    super.initState();
    trafficHistoryManager.addDataPointWithSpeed(
      widget.downloadSpeed,
      widget.uploadSpeed,
    );
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    )..repeat(reverse: true);

    _fetchIp();
  }

  @override
  void didUpdateWidget(TrafficChart oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.downloadSpeed != oldWidget.downloadSpeed ||
        widget.uploadSpeed != oldWidget.uploadSpeed) {
      trafficHistoryManager.addDataPointWithSpeed(
        widget.downloadSpeed,
        widget.uploadSpeed,
      );
    }
    // 代理状态变化时刷新 IP
    if (widget.isProxyRunning != oldWidget.isProxyRunning) {
      Future.delayed(const Duration(milliseconds: 500), _fetchIp);
    }
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _fetchIp() async {
    if (_isLoadingIp) return;
    setState(() => _isLoadingIp = true);

    try {
      final client = HttpClient();
      client.connectionTimeout = const Duration(seconds: 8);

      final request = await client.getUrl(Uri.parse('https://api.ip.sb/ip'));
      request.headers.set('User-Agent', 'VeloGuard/1.0');
      final response = await request.close();

      if (response.statusCode == 200) {
        final body = await response.transform(utf8.decoder).join();
        if (mounted) {
          setState(() {
            _currentIp = body.trim();
            _isLoadingIp = false;
          });
        }
      }
      client.close();
    } catch (e) {
      // 备用 API
      try {
        final client = HttpClient();
        client.connectionTimeout = const Duration(seconds: 8);
        final request = await client.getUrl(Uri.parse('https://api.ipify.org'));
        final response = await request.close();
        if (response.statusCode == 200) {
          final body = await response.transform(utf8.decoder).join();
          if (mounted) {
            setState(() {
              _currentIp = body.trim();
              _isLoadingIp = false;
            });
          }
        }
        client.close();
      } catch (_) {
        if (mounted) {
          setState(() => _isLoadingIp = false);
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);
    final spacing = ResponsiveUtils.getSpacing(context);
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final cardPadding = ResponsiveUtils.getCardPadding(context);
    final chartHeight = ResponsiveUtils.getTrafficChartHeight(context);

    final downloadSpots = trafficHistoryManager.getDownloadSpots();
    final uploadSpots = trafficHistoryManager.getUploadSpots();
    final maxY = trafficHistoryManager.getMaxSpeed();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // 第一行：下载 | 上传
        Row(
          children: [
            // 下载卡片
            Expanded(
              child: _TrafficStatCard(
                icon: Icons.arrow_downward_rounded,
                label: l10n?.download ?? 'Download',
                speed: _formatSpeed(widget.downloadSpeed),
                total: _formatBytes(widget.trafficStats.download),
                color: colorScheme.primary,
                colorScheme: colorScheme,
                textTheme: textTheme,
                pulseController: _pulseController,
                isActive: widget.downloadSpeed > BigInt.zero,
              ),
            ),
            SizedBox(width: spacing),
            // 上传卡片
            Expanded(
              child: _TrafficStatCard(
                icon: Icons.arrow_upward_rounded,
                label: l10n?.upload ?? 'Upload',
                speed: _formatSpeed(widget.uploadSpeed),
                total: _formatBytes(widget.trafficStats.upload),
                color: colorScheme.tertiary,
                colorScheme: colorScheme,
                textTheme: textTheme,
                pulseController: _pulseController,
                isActive: widget.uploadSpeed > BigInt.zero,
              ),
            ),
          ],
        ),

        SizedBox(height: spacing),

        // 第二行：IP 卡片（全宽）
        _IpStatCard(
          ip: _currentIp,
          isLoading: _isLoadingIp,
          isProxyRunning: widget.isProxyRunning,
          onRefresh: _fetchIp,
          colorScheme: colorScheme,
          textTheme: textTheme,
        ),

        SizedBox(height: spacing * 2),

        // Traffic Chart Card
        Card(
          elevation: 0,
          color: colorScheme.surfaceContainerLow,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(borderRadius),
          ),
          child: Padding(
            padding: cardPadding,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Chart header
                Row(
                  children: [
                    Icon(
                      Icons.show_chart_rounded,
                      size: 18,
                      color: colorScheme.primary,
                    ),
                    SizedBox(width: spacing),
                    Text(
                      l10n?.realTimeTraffic ?? 'Real-time Traffic',
                      style: textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w600,
                        color: colorScheme.onSurface,
                      ),
                    ),
                    const Spacer(),
                    _ChartLegend(
                      downloadColor: colorScheme.primary,
                      uploadColor: colorScheme.tertiary,
                      downloadLabel: l10n?.download ?? 'Download',
                      uploadLabel: l10n?.upload ?? 'Upload',
                    ),
                  ],
                ),

                SizedBox(height: spacing * 2),

                // Chart
                SizedBox(
                  height: chartHeight - 60,
                  child: downloadSpots.isEmpty || uploadSpots.isEmpty
                      ? Center(
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Icon(
                                Icons.area_chart_rounded,
                                size: 32,
                                color: colorScheme.outlineVariant,
                              ),
                              SizedBox(height: spacing),
                              Text(
                                l10n?.noData ?? 'No data',
                                style: TextStyle(
                                  color: colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ],
                          ),
                        )
                      : LineChart(
                          LineChartData(
                            gridData: FlGridData(
                              show: true,
                              drawVerticalLine: false,
                              horizontalInterval: maxY / 4,
                              getDrawingHorizontalLine: (value) {
                                return FlLine(
                                  color: colorScheme.outlineVariant.withValues(
                                    alpha: 0.2,
                                  ),
                                  strokeWidth: 1,
                                  dashArray: [5, 5],
                                );
                              },
                            ),
                            titlesData: FlTitlesData(
                              show: true,
                              rightTitles: const AxisTitles(
                                sideTitles: SideTitles(showTitles: false),
                              ),
                              topTitles: const AxisTitles(
                                sideTitles: SideTitles(showTitles: false),
                              ),
                              bottomTitles: const AxisTitles(
                                sideTitles: SideTitles(showTitles: false),
                              ),
                              leftTitles: AxisTitles(
                                sideTitles: SideTitles(
                                  showTitles: true,
                                  reservedSize: 42,
                                  getTitlesWidget: (value, meta) {
                                    return Text(
                                      _formatSpeedShort(value),
                                      style: TextStyle(
                                        fontSize: 10,
                                        color: colorScheme.onSurfaceVariant,
                                      ),
                                    );
                                  },
                                ),
                              ),
                            ),
                            borderData: FlBorderData(show: false),
                            minX: 0,
                            maxX:
                                TrafficHistoryManager.maxDataPoints.toDouble() -
                                1,
                            minY: 0,
                            maxY: maxY,
                            lineTouchData: LineTouchData(
                              touchTooltipData: LineTouchTooltipData(
                                getTooltipItems: (touchedSpots) {
                                  return touchedSpots.map((spot) {
                                    final isDownload = spot.barIndex == 0;
                                    return LineTooltipItem(
                                      _formatSpeedValue(spot.y * 1024),
                                      TextStyle(
                                        color: isDownload
                                            ? colorScheme.primary
                                            : colorScheme.tertiary,
                                        fontWeight: FontWeight.w600,
                                        fontSize: 12,
                                      ),
                                    );
                                  }).toList();
                                },
                              ),
                            ),
                            lineBarsData: [
                              LineChartBarData(
                                spots: downloadSpots.length >= 2
                                    ? downloadSpots
                                    : [const FlSpot(0, 0), const FlSpot(1, 0)],
                                isCurved: true,
                                curveSmoothness: 0.35,
                                color: colorScheme.primary,
                                barWidth: 2.5,
                                isStrokeCapRound: true,
                                dotData: const FlDotData(show: false),
                                belowBarData: BarAreaData(
                                  show: true,
                                  gradient: LinearGradient(
                                    begin: Alignment.topCenter,
                                    end: Alignment.bottomCenter,
                                    colors: [
                                      colorScheme.primary.withValues(
                                        alpha: 0.3,
                                      ),
                                      colorScheme.primary.withValues(
                                        alpha: 0.0,
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                              LineChartBarData(
                                spots: uploadSpots.length >= 2
                                    ? uploadSpots
                                    : [const FlSpot(0, 0), const FlSpot(1, 0)],
                                isCurved: true,
                                curveSmoothness: 0.35,
                                color: colorScheme.tertiary,
                                barWidth: 2.5,
                                isStrokeCapRound: true,
                                dotData: const FlDotData(show: false),
                                belowBarData: BarAreaData(
                                  show: true,
                                  gradient: LinearGradient(
                                    begin: Alignment.topCenter,
                                    end: Alignment.bottomCenter,
                                    colors: [
                                      colorScheme.tertiary.withValues(
                                        alpha: 0.2,
                                      ),
                                      colorScheme.tertiary.withValues(
                                        alpha: 0.0,
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ],
                          ),
                          duration: const Duration(milliseconds: 300),
                        ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  String _formatBytes(BigInt bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var value = bytes.toDouble();
    var unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }
    return '${value.toStringAsFixed(value < 10 ? 1 : 0)} ${units[unitIndex]}';
  }

  String _formatSpeed(BigInt bytesPerSecond) {
    return '${_formatBytes(bytesPerSecond)}/s';
  }

  String _formatSpeedShort(double kbPerSecond) {
    if (kbPerSecond < 1024) {
      return '${kbPerSecond.toStringAsFixed(0)}K';
    } else {
      return '${(kbPerSecond / 1024).toStringAsFixed(1)}M';
    }
  }

  String _formatSpeedValue(double bytesPerSecond) {
    const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
    var value = bytesPerSecond;
    var unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }
    return '${value.toStringAsFixed(value < 10 ? 1 : 0)} ${units[unitIndex]}';
  }
}

/// 流量统计卡片
class _TrafficStatCard extends StatelessWidget {
  final IconData icon;
  final String label;
  final String speed;
  final String total;
  final Color color;
  final ColorScheme colorScheme;
  final TextTheme textTheme;
  final AnimationController pulseController;
  final bool isActive;

  const _TrafficStatCard({
    required this.icon,
    required this.label,
    required this.speed,
    required this.total,
    required this.color,
    required this.colorScheme,
    required this.textTheme,
    required this.pulseController,
    required this.isActive,
  });

  @override
  Widget build(BuildContext context) {
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final spacing = ResponsiveUtils.getSpacing(context);

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: Padding(
        padding: EdgeInsets.all(spacing * 1.5),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            // 图标和标题
            Row(
              children: [
                AnimatedBuilder(
                  animation: pulseController,
                  builder: (context, child) {
                    return Container(
                      padding: EdgeInsets.all(spacing * 0.8),
                      decoration: BoxDecoration(
                        color: isActive
                            ? color.withValues(
                                alpha: 0.12 + (pulseController.value * 0.08),
                              )
                            : color.withValues(alpha: 0.08),
                        borderRadius: BorderRadius.circular(borderRadius * 0.5),
                      ),
                      child: Icon(icon, size: 18, color: color),
                    );
                  },
                ),
                SizedBox(width: spacing),
                Text(
                  label,
                  style: textTheme.labelMedium?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),

            SizedBox(height: spacing),

            // 速度
            Text(
              speed,
              style: textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w700,
                color: color,
              ),
            ),

            SizedBox(height: spacing * 0.5),

            // 总计
            Row(
              children: [
                Icon(
                  Icons.data_usage_rounded,
                  size: 12,
                  color: colorScheme.onSurfaceVariant,
                ),
                SizedBox(width: spacing * 0.5),
                Expanded(
                  child: Text(
                    '${AppLocalizations.of(context)?.total ?? "Total"}: $total',
                    style: textTheme.labelSmall?.copyWith(
                      color: colorScheme.onSurfaceVariant,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// IP 统计卡片 - 全宽横向布局
class _IpStatCard extends StatelessWidget {
  final String? ip;
  final bool isLoading;
  final bool isProxyRunning;
  final VoidCallback onRefresh;
  final ColorScheme colorScheme;
  final TextTheme textTheme;

  const _IpStatCard({
    required this.ip,
    required this.isLoading,
    required this.isProxyRunning,
    required this.onRefresh,
    required this.colorScheme,
    required this.textTheme,
  });

  @override
  Widget build(BuildContext context) {
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final spacing = ResponsiveUtils.getSpacing(context);
    final statusColor = isProxyRunning ? Colors.green : colorScheme.outline;

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: InkWell(
        onTap: onRefresh,
        onLongPress: ip != null
            ? () {
                Clipboard.setData(ClipboardData(text: ip!));
                AnimationUtils.lightHaptic();
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(
                      AppLocalizations.of(context)?.ipCopied ?? 'IP copied',
                    ),
                    behavior: SnackBarBehavior.floating,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                    duration: const Duration(seconds: 2),
                  ),
                );
              }
            : null,
        borderRadius: BorderRadius.circular(borderRadius),
        child: Padding(
          padding: EdgeInsets.symmetric(
            horizontal: spacing * 1.5,
            vertical: spacing,
          ),
          child: Row(
            children: [
              // 左侧：图标
              Container(
                padding: EdgeInsets.all(spacing * 0.8),
                decoration: BoxDecoration(
                  color: isProxyRunning
                      ? Colors.green.withValues(alpha: 0.12)
                      : colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(borderRadius * 0.5),
                ),
                child: Icon(Icons.public_rounded, size: 18, color: statusColor),
              ),
              SizedBox(width: spacing),
              // 中间：IP 地址
              Expanded(
                child: AnimatedSwitcher(
                  duration: AnimationUtils.stateChangeDuration,
                  child: Text(
                    ip ?? '--',
                    key: ValueKey(ip),
                    style: textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                      fontFamily: 'monospace',
                      color: isProxyRunning
                          ? colorScheme.primary
                          : colorScheme.onSurface,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ),
              SizedBox(width: spacing),
              // 右侧：状态指示
              Container(
                padding: EdgeInsets.symmetric(
                  horizontal: spacing,
                  vertical: spacing * 0.5,
                ),
                decoration: BoxDecoration(
                  color: statusColor.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(borderRadius * 0.5),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 6,
                      height: 6,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: statusColor,
                      ),
                    ),
                    SizedBox(width: spacing * 0.5),
                    Text(
                      isProxyRunning
                          ? (AppLocalizations.of(context)?.proxy ?? 'Proxy')
                          : (AppLocalizations.of(context)?.direct ?? 'Direct'),
                      style: textTheme.labelSmall?.copyWith(
                        color: statusColor,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ),
              if (isLoading) ...[
                SizedBox(width: spacing),
                SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: colorScheme.primary,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

/// Chart legend widget
class _ChartLegend extends StatelessWidget {
  final Color downloadColor;
  final Color uploadColor;
  final String downloadLabel;
  final String uploadLabel;

  const _ChartLegend({
    required this.downloadColor,
    required this.uploadColor,
    required this.downloadLabel,
    required this.uploadLabel,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        _LegendDot(color: downloadColor, label: downloadLabel),
        const SizedBox(width: 12),
        _LegendDot(color: uploadColor, label: uploadLabel),
      ],
    );
  }
}

class _LegendDot extends StatelessWidget {
  final Color color;
  final String label;

  const _LegendDot({required this.color, required this.label});

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 4),
        Text(
          label,
          style: textTheme.labelSmall?.copyWith(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }
}
