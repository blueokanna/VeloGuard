import 'dart:async';
import 'dart:collection';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:veloguard/src/rust/types.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/providers/proxies_provider.dart'
    show proxySelectionChangedController;
import 'package:veloguard/src/services/storage_service.dart';

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

/// IP 信息数据类
class IpInfo {
  final String ip;
  final String? country;
  final String? countryCode;
  final String? city;
  final String? isp;
  final String? organization;
  final bool isIpv6;

  IpInfo({
    required this.ip,
    this.country,
    this.countryCode,
    this.city,
    this.isp,
    this.organization,
    this.isIpv6 = false,
  });

  String get location {
    final parts = <String>[];
    if (city != null && city!.isNotEmpty) parts.add(city!);
    if (country != null && country!.isNotEmpty) parts.add(country!);
    return parts.isEmpty ? 'Unknown' : parts.join(', ');
  }

  String get flag {
    if (countryCode == null || countryCode!.length != 2) return '🌐';
    // Convert country code to flag emoji
    final code = countryCode!.toUpperCase();
    final firstLetter = code.codeUnitAt(0) - 0x41 + 0x1F1E6;
    final secondLetter = code.codeUnitAt(1) - 0x41 + 0x1F1E6;
    return String.fromCharCodes([firstLetter, secondLetter]);
  }
}

/// Global IP info cache to avoid repeated requests
class _IpInfoCache {
  IpInfo? ipv4Info;
  IpInfo? ipv6Info;
  DateTime? lastFetchTime;
  bool? lastProxyState;

  /// Cache duration - 5 minutes
  static const cacheDuration = Duration(minutes: 5);

  bool shouldRefresh(bool isProxyRunning) {
    // Refresh if proxy state changed
    if (lastProxyState != null && lastProxyState != isProxyRunning) {
      return true;
    }
    // Refresh if cache expired
    if (lastFetchTime == null) {
      return true;
    }
    return DateTime.now().difference(lastFetchTime!) > cacheDuration;
  }

  void update({IpInfo? ipv4, IpInfo? ipv6, required bool proxyState}) {
    if (ipv4 != null) ipv4Info = ipv4;
    if (ipv6 != null) ipv6Info = ipv6;
    lastFetchTime = DateTime.now();
    lastProxyState = proxyState;
  }

  void clear() {
    ipv4Info = null;
    ipv6Info = null;
    lastFetchTime = null;
    lastProxyState = null;
  }
}

final _ipInfoCache = _IpInfoCache();

class _TrafficChartState extends State<TrafficChart>
    with SingleTickerProviderStateMixin {
  late AnimationController _pulseController;
  IpInfo? _ipv4Info;
  IpInfo? _ipv6Info;
  bool _isLoadingIp = false;
  String? _ipError;
  StreamSubscription<String>? _proxySelectionSubscription;
  int _proxyPort = 7890; // Default port, will be updated from settings

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

    // Load proxy port from settings
    _loadProxyPort();

    // Use cached data if available
    if (_ipInfoCache.ipv4Info != null || _ipInfoCache.ipv6Info != null) {
      _ipv4Info = _ipInfoCache.ipv4Info;
      _ipv6Info = _ipInfoCache.ipv6Info;
    }

    // Only fetch if cache needs refresh
    if (_ipInfoCache.shouldRefresh(widget.isProxyRunning)) {
      _fetchIpInfo();
    }

    // Listen for proxy selection changes
    _proxySelectionSubscription = proxySelectionChangedController.stream.listen(
      (_) {
        // Clear cache and refresh IP when proxy selection changes
        _ipInfoCache.clear();
        Future.delayed(const Duration(milliseconds: 800), () {
          if (mounted) _fetchIpInfo();
        });
      },
    );
  }

  /// Load proxy port from settings
  Future<void> _loadProxyPort() async {
    try {
      final settings = await StorageService.instance.getGeneralSettings();
      // Prefer mixedPort, fallback to httpPort
      final port = settings.mixedPort > 0
          ? settings.mixedPort
          : settings.httpPort;
      if (mounted && port > 0) {
        setState(() {
          _proxyPort = port;
        });
      }
    } catch (e) {
      debugPrint('Failed to load proxy port: $e');
    }
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
    // 代理状态变化时刷新 IP (only if state actually changed)
    if (widget.isProxyRunning != oldWidget.isProxyRunning) {
      // Clear cache when proxy state changes
      _ipInfoCache.clear();
      Future.delayed(const Duration(milliseconds: 500), _fetchIpInfo);
    }
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _proxySelectionSubscription?.cancel();
    super.dispose();
  }

  Future<void> _fetchIpInfo() async {
    if (_isLoadingIp) return;
    setState(() {
      _isLoadingIp = true;
      _ipError = null;
    });

    // Fetch IPv4 and IPv6 info in parallel
    await Future.wait([_fetchIpv4Info(), _fetchIpv6Info()]);

    // Update cache
    _ipInfoCache.update(
      ipv4: _ipv4Info,
      ipv6: _ipv6Info,
      proxyState: widget.isProxyRunning,
    );

    if (mounted) {
      setState(() => _isLoadingIp = false);
    }
  }

  /// Create Dio client with optional proxy support
  Dio _createDioClient({bool useProxy = false}) {
    final dio = Dio(
      BaseOptions(
        connectTimeout: const Duration(seconds: 8),
        receiveTimeout: const Duration(seconds: 8),
        headers: {'User-Agent': 'VeloGuard/1.0'},
      ),
    );

    if (useProxy) {
      // Route through local proxy to get exit IP
      dio.httpClientAdapter = IOHttpClientAdapter(
        createHttpClient: () {
          final client = HttpClient();
          // Use local HTTP proxy (mixed port)
          client.findProxy = (uri) => 'PROXY 127.0.0.1:$_proxyPort';
          client.badCertificateCallback = (cert, host, port) => true;
          return client;
        },
      );
    }

    return dio;
  }

  Future<void> _fetchIpv4Info() async {
    try {
      // Use proxy when proxy is running to get exit IP
      final dio = _createDioClient(useProxy: widget.isProxyRunning);

      // Use ip.sb API for detailed info
      final response = await dio.get('https://api.ip.sb/geoip');

      if (response.statusCode == 200) {
        final data = response.data as Map<String, dynamic>;

        if (mounted) {
          setState(() {
            _ipv4Info = IpInfo(
              ip: data['ip']?.toString() ?? '',
              country: data['country']?.toString(),
              countryCode: data['country_code']?.toString(),
              city: data['city']?.toString(),
              isp: data['isp']?.toString(),
              organization: data['organization']?.toString(),
              isIpv6: (data['ip']?.toString() ?? '').contains(':'),
            );
            _ipError = null;
          });
        }
      }
      dio.close();
    } on DioException catch (e) {
      if (e.type == DioExceptionType.connectionTimeout ||
          e.type == DioExceptionType.receiveTimeout ||
          e.type == DioExceptionType.sendTimeout) {
        if (mounted) {
          setState(() {
            _ipError = 'Connect Timeout';
          });
        }
        return;
      }
      // Fallback to simple IP API
      try {
        final dio = _createDioClient(useProxy: widget.isProxyRunning);
        final response = await dio.get('https://api.ip.sb/ip');
        if (response.statusCode == 200) {
          final body = response.data.toString().trim();
          if (mounted) {
            setState(() {
              _ipv4Info = IpInfo(ip: body);
              _ipError = null;
            });
          }
        }
        dio.close();
      } on DioException catch (e2) {
        if (e2.type == DioExceptionType.connectionTimeout ||
            e2.type == DioExceptionType.receiveTimeout ||
            e2.type == DioExceptionType.sendTimeout) {
          if (mounted) {
            setState(() {
              _ipError = 'Connect Timeout';
            });
          }
        } else {
          debugPrint('Failed to fetch IPv4 info: $e2');
          if (mounted) {
            setState(() {
              _ipError = 'Network Error';
            });
          }
        }
      } catch (_) {
        debugPrint('Failed to fetch IPv4 info: $e');
      }
    } catch (e) {
      debugPrint('Failed to fetch IPv4 info: $e');
      if (mounted) {
        setState(() {
          _ipError = 'Network Error';
        });
      }
    }
  }

  Future<void> _fetchIpv6Info() async {
    try {
      // Use proxy when proxy is running to get exit IP
      final dio = _createDioClient(useProxy: widget.isProxyRunning);

      // Try IPv6-only endpoint
      final response = await dio.get('https://api-ipv6.ip.sb/geoip');

      if (response.statusCode == 200) {
        final data = response.data as Map<String, dynamic>;
        final ip = data['ip']?.toString() ?? '';

        // Only set if it's actually IPv6
        if (ip.contains(':') && mounted) {
          setState(() {
            _ipv6Info = IpInfo(
              ip: ip,
              country: data['country']?.toString(),
              countryCode: data['country_code']?.toString(),
              city: data['city']?.toString(),
              isp: data['isp']?.toString(),
              organization: data['organization']?.toString(),
              isIpv6: true,
            );
          });
        }
      }
      dio.close();
    } catch (e) {
      // IPv6 not available, that's fine
      debugPrint('IPv6 not available: $e');
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

        // 第二行：IP 信息卡片（全宽）- 显示 IPv4/IPv6 和地理位置
        _IpInfoCard(
          ipv4Info: _ipv4Info,
          ipv6Info: _ipv6Info,
          isLoading: _isLoadingIp,
          isProxyRunning: widget.isProxyRunning,
          onRefresh: _fetchIpInfo,
          colorScheme: colorScheme,
          textTheme: textTheme,
          error: _ipError,
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

/// IP 信息卡片 - 显示 IPv4/IPv6 和地理位置
class _IpInfoCard extends StatelessWidget {
  final IpInfo? ipv4Info;
  final IpInfo? ipv6Info;
  final bool isLoading;
  final bool isProxyRunning;
  final VoidCallback onRefresh;
  final ColorScheme colorScheme;
  final TextTheme textTheme;
  final String? error;

  const _IpInfoCard({
    required this.ipv4Info,
    required this.ipv6Info,
    required this.isLoading,
    required this.isProxyRunning,
    required this.onRefresh,
    required this.colorScheme,
    required this.textTheme,
    this.error,
  });

  @override
  Widget build(BuildContext context) {
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final spacing = ResponsiveUtils.getSpacing(context);
    final statusColor = isProxyRunning ? Colors.green : colorScheme.outline;
    final l10n = AppLocalizations.of(context);

    // 主要显示的 IP 信息（优先 IPv4）
    final primaryInfo = ipv4Info ?? ipv6Info;

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: InkWell(
        onTap: onRefresh,
        onLongPress: primaryInfo != null
            ? () {
                Clipboard.setData(ClipboardData(text: primaryInfo.ip));
                AnimationUtils.lightHaptic();
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(l10n?.ipCopied ?? 'IP copied'),
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
          padding: EdgeInsets.all(spacing * 1.5),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // 顶部：状态和刷新
              Row(
                children: [
                  // 状态图标
                  Container(
                    padding: EdgeInsets.all(spacing * 0.8),
                    decoration: BoxDecoration(
                      color: isProxyRunning
                          ? Colors.green.withValues(alpha: 0.12)
                          : colorScheme.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(borderRadius * 0.5),
                    ),
                    child: Icon(
                      Icons.public_rounded,
                      size: 18,
                      color: statusColor,
                    ),
                  ),
                  SizedBox(width: spacing),
                  // 状态文字
                  Container(
                    padding: EdgeInsets.symmetric(
                      horizontal: spacing,
                      vertical: spacing * 0.4,
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
                              ? (l10n?.proxy ?? 'Proxy')
                              : (l10n?.direct ?? 'Direct'),
                          style: textTheme.labelSmall?.copyWith(
                            color: statusColor,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const Spacer(),
                  // 地理位置和国旗
                  if (primaryInfo != null) ...[
                    Text(
                      primaryInfo.flag,
                      style: const TextStyle(fontSize: 16),
                    ),
                    SizedBox(width: spacing * 0.5),
                    Flexible(
                      child: Text(
                        primaryInfo.location,
                        style: textTheme.labelMedium?.copyWith(
                          color: colorScheme.onSurfaceVariant,
                          fontWeight: FontWeight.w500,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
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

              SizedBox(height: spacing),

              // IPv4 信息
              if (ipv4Info != null)
                _buildIpRow(
                  context,
                  label: 'IPv4',
                  ip: ipv4Info!.ip,
                  isp: ipv4Info!.isp,
                  isProxyRunning: isProxyRunning,
                ),

              // IPv6 信息
              if (ipv6Info != null) ...[
                if (ipv4Info != null) SizedBox(height: spacing * 0.75),
                _buildIpRow(
                  context,
                  label: 'IPv6',
                  ip: ipv6Info!.ip,
                  isp: ipv6Info!.isp,
                  isProxyRunning: isProxyRunning,
                ),
              ],

              // 错误信息显示（支持滚动）
              if (error != null && ipv4Info == null && ipv6Info == null)
                _AutoScrollText(
                  text: error!,
                  isp: null,
                  isProxyRunning: false,
                  colorScheme: colorScheme,
                  textTheme: textTheme,
                  isError: true,
                ),

              // 无 IP 时显示占位
              if (ipv4Info == null && ipv6Info == null && error == null)
                Text(
                  '--',
                  style: textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                    fontFamily: 'monospace',
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildIpRow(
    BuildContext context, {
    required String label,
    required String ip,
    String? isp,
    required bool isProxyRunning,
  }) {
    final spacing = ResponsiveUtils.getSpacing(context);
    final isIpv6 = label == 'IPv6';

    return Row(
      children: [
        // IP 版本标签
        Container(
          padding: EdgeInsets.symmetric(
            horizontal: spacing * 0.75,
            vertical: spacing * 0.25,
          ),
          decoration: BoxDecoration(
            color: label == 'IPv4'
                ? colorScheme.primaryContainer
                : colorScheme.tertiaryContainer,
            borderRadius: BorderRadius.circular(4),
          ),
          child: Text(
            label,
            style: textTheme.labelSmall?.copyWith(
              color: label == 'IPv4'
                  ? colorScheme.onPrimaryContainer
                  : colorScheme.onTertiaryContainer,
              fontWeight: FontWeight.w600,
              fontSize: 10,
            ),
          ),
        ),
        SizedBox(width: spacing),
        // IP 地址 - IPv6 使用自动滚动
        Expanded(
          child: isIpv6
              ? _AutoScrollText(
                  text: ip,
                  isp: isp,
                  isProxyRunning: isProxyRunning,
                  colorScheme: colorScheme,
                  textTheme: textTheme,
                )
              : SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  physics: const BouncingScrollPhysics(),
                  child: Row(
                    children: [
                      Text(
                        ip,
                        style: textTheme.bodyMedium?.copyWith(
                          fontWeight: FontWeight.w600,
                          fontFamily: 'monospace',
                          color: isProxyRunning
                              ? colorScheme.primary
                              : colorScheme.onSurface,
                        ),
                      ),
                      if (isp != null && isp.isNotEmpty) ...[
                        SizedBox(width: spacing),
                        Text(
                          '($isp)',
                          style: textTheme.labelSmall?.copyWith(
                            color: colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
        ),
      ],
    );
  }
}

/// 自动滚动文本组件 - 用于长 IPv6 地址
class _AutoScrollText extends StatefulWidget {
  final String text;
  final String? isp;
  final bool isProxyRunning;
  final ColorScheme colorScheme;
  final TextTheme textTheme;
  final bool isError;

  const _AutoScrollText({
    required this.text,
    this.isp,
    required this.isProxyRunning,
    required this.colorScheme,
    required this.textTheme,
    this.isError = false,
  });

  @override
  State<_AutoScrollText> createState() => _AutoScrollTextState();
}

class _AutoScrollTextState extends State<_AutoScrollText>
    with SingleTickerProviderStateMixin {
  late ScrollController _scrollController;
  late AnimationController _animationController;
  bool _needsScroll = false;
  double _maxScrollExtent = 0;

  @override
  void initState() {
    super.initState();
    _scrollController = ScrollController();
    _animationController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 8),
    );

    WidgetsBinding.instance.addPostFrameCallback((_) {
      _checkScrollNeeded();
    });
  }

  void _checkScrollNeeded() {
    if (!mounted) return;

    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      if (_scrollController.hasClients) {
        final maxExtent = _scrollController.position.maxScrollExtent;
        if (maxExtent > 0) {
          setState(() {
            _needsScroll = true;
            _maxScrollExtent = maxExtent;
          });
          _startAutoScroll();
        }
      }
    });
  }

  void _startAutoScroll() {
    if (!_needsScroll || !mounted) return;

    _animationController.addListener(() {
      if (!mounted || !_scrollController.hasClients) return;

      // 使用正弦波实现来回滚动效果
      final progress = _animationController.value;

      // 简单的来回滚动
      if (progress < 0.45) {
        // 向右滚动
        _scrollController.jumpTo(_maxScrollExtent * (progress / 0.45));
      } else if (progress < 0.55) {
        // 停顿
        _scrollController.jumpTo(_maxScrollExtent);
      } else {
        // 向左滚动
        _scrollController.jumpTo(
          _maxScrollExtent * (1 - (progress - 0.55) / 0.45),
        );
      }
    });

    _animationController.repeat();
  }

  @override
  void didUpdateWidget(_AutoScrollText oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.text != oldWidget.text) {
      _animationController.stop();
      _animationController.reset();
      _needsScroll = false;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _checkScrollNeeded();
      });
    }
  }

  @override
  void dispose() {
    _animationController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final spacing = ResponsiveUtils.getSpacing(context);

    return SingleChildScrollView(
      controller: _scrollController,
      scrollDirection: Axis.horizontal,
      physics: const BouncingScrollPhysics(),
      child: Row(
        children: [
          Text(
            widget.text,
            style: widget.textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.w600,
              fontFamily: 'monospace',
              color: widget.isError
                  ? widget.colorScheme.error
                  : widget.isProxyRunning
                  ? widget.colorScheme.primary
                  : widget.colorScheme.onSurface,
            ),
          ),
          if (widget.isp != null && widget.isp!.isNotEmpty) ...[
            SizedBox(width: spacing),
            Text(
              '(${widget.isp})',
              style: widget.textTheme.labelSmall?.copyWith(
                color: widget.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ],
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
