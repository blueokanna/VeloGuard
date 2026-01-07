import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';

/// IP 信息数据模型
class IpInfo {
  final String ip;
  final String? country;
  final String? city;
  final String? isp;
  final String? org;

  IpInfo({required this.ip, this.country, this.city, this.isp, this.org});

  factory IpInfo.fromIpSb(String ip) {
    return IpInfo(ip: ip);
  }

  factory IpInfo.fromIpApi(Map<String, dynamic> json) {
    return IpInfo(
      ip: json['query'] ?? json['ip'] ?? '',
      country: json['country'],
      city: json['city'],
      isp: json['isp'],
      org: json['org'],
    );
  }
}

/// IP 检测卡片组件
class IpCheckCard extends StatefulWidget {
  final bool isProxyRunning;

  const IpCheckCard({super.key, required this.isProxyRunning});

  @override
  State<IpCheckCard> createState() => _IpCheckCardState();
}

/// Global IP info cache for IpCheckCard
class _IpCheckCache {
  IpInfo? ipInfo;
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

  void update({required IpInfo? info, required bool proxyState}) {
    ipInfo = info;
    lastFetchTime = DateTime.now();
    lastProxyState = proxyState;
  }

  void clear() {
    ipInfo = null;
    lastFetchTime = null;
    lastProxyState = null;
  }
}

final _ipCheckCache = _IpCheckCache();

class _IpCheckCardState extends State<IpCheckCard>
    with SingleTickerProviderStateMixin {
  IpInfo? _ipInfo;
  bool _isLoading = false;
  String? _error;
  late AnimationController _refreshController;

  @override
  void initState() {
    super.initState();
    _refreshController = AnimationController(
      duration: const Duration(milliseconds: 1000),
      vsync: this,
    );

    // Use cached data if available
    if (_ipCheckCache.ipInfo != null) {
      _ipInfo = _ipCheckCache.ipInfo;
    }

    // Only fetch if cache needs refresh
    if (_ipCheckCache.shouldRefresh(widget.isProxyRunning)) {
      _checkIp();
    }
  }

  @override
  void didUpdateWidget(IpCheckCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    // 代理状态变化时自动刷新
    if (widget.isProxyRunning != oldWidget.isProxyRunning) {
      // Clear cache when proxy state changes
      _ipCheckCache.clear();
      Future.delayed(const Duration(milliseconds: 500), () {
        if (mounted) _checkIp();
      });
    }
  }

  @override
  void dispose() {
    _refreshController.dispose();
    super.dispose();
  }

  Future<void> _checkIp() async {
    if (_isLoading) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    _refreshController.repeat();

    try {
      // 使用 ip.sb 获取 IP
      final ip = await _fetchIpFromIpSb();
      if (ip != null && mounted) {
        // 尝试获取更多 IP 信息
        final ipInfo = await _fetchIpDetails(ip);
        final result = ipInfo ?? IpInfo(ip: ip);

        // Update cache
        _ipCheckCache.update(info: result, proxyState: widget.isProxyRunning);

        setState(() {
          _ipInfo = result;
          _isLoading = false;
        });
      } else if (mounted) {
        setState(() {
          _error = 'networkRequestFailed';
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = 'networkRequestFailed';
          _isLoading = false;
        });
      }
    } finally {
      _refreshController.stop();
      _refreshController.reset();
    }
  }

  /// 从 ip.sb 获取 IP
  Future<String?> _fetchIpFromIpSb() async {
    try {
      final client = HttpClient();
      client.connectionTimeout = const Duration(seconds: 10);

      final request = await client.getUrl(Uri.parse('https://api.ip.sb/ip'));
      request.headers.set('User-Agent', 'VeloGuard/1.0');

      final response = await request.close();
      if (response.statusCode == 200) {
        final body = await response.transform(utf8.decoder).join();
        return body.trim();
      }
      client.close();
    } catch (e) {
      debugPrint('ip.sb request failed: $e');
    }

    // 备用方案：使用 ipify
    try {
      final client = HttpClient();
      client.connectionTimeout = const Duration(seconds: 10);

      final request = await client.getUrl(Uri.parse('https://api.ipify.org'));
      final response = await request.close();
      if (response.statusCode == 200) {
        final body = await response.transform(utf8.decoder).join();
        return body.trim();
      }
      client.close();
    } catch (e) {
      debugPrint('ipify request failed: $e');
    }

    return null;
  }

  /// 获取 IP 详细信息
  Future<IpInfo?> _fetchIpDetails(String ip) async {
    try {
      final client = HttpClient();
      client.connectionTimeout = const Duration(seconds: 5);

      // 使用 ip-api.com 获取详细信息
      final request = await client.getUrl(
        Uri.parse('http://ip-api.com/json/$ip?lang=zh-CN'),
      );

      final response = await request.close();
      if (response.statusCode == 200) {
        final body = await response.transform(utf8.decoder).join();
        final json = jsonDecode(body) as Map<String, dynamic>;
        if (json['status'] == 'success') {
          return IpInfo.fromIpApi(json);
        }
      }
      client.close();
    } catch (e) {
      debugPrint('IP details request failed: $e');
    }
    return null;
  }

  void _copyIp() {
    if (_ipInfo != null) {
      Clipboard.setData(ClipboardData(text: _ipInfo!.ip));
      AnimationUtils.lightHaptic();
      final l10n = AppLocalizations.of(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(l10n?.ipCopied ?? 'IP copied'),
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final borderRadius = ResponsiveUtils.getBorderRadius(context);
    final spacing = ResponsiveUtils.getSpacing(context);
    final l10n = AppLocalizations.of(context);

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: Padding(
        padding: ResponsiveUtils.getCardPadding(context),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 标题行
            Row(
              children: [
                Container(
                  padding: EdgeInsets.all(spacing),
                  decoration: BoxDecoration(
                    color: widget.isProxyRunning
                        ? colorScheme.primaryContainer
                        : colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(borderRadius * 0.6),
                  ),
                  child: Icon(
                    Icons.public_rounded,
                    size: 20,
                    color: widget.isProxyRunning
                        ? colorScheme.onPrimaryContainer
                        : colorScheme.onSurfaceVariant,
                  ),
                ),
                SizedBox(width: spacing * 1.5),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        l10n?.ipCheck ?? 'IP Check',
                        style: textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        widget.isProxyRunning
                            ? (l10n?.proxyConnection ?? 'Via proxy')
                            : (l10n?.directConnection ?? 'Direct connection'),
                        style: textTheme.bodySmall?.copyWith(
                          color: colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                // 刷新按钮
                RotationTransition(
                  turns: _refreshController,
                  child: IconButton(
                    icon: Icon(
                      Icons.refresh_rounded,
                      color: _isLoading
                          ? colorScheme.primary
                          : colorScheme.onSurfaceVariant,
                    ),
                    onPressed: _isLoading ? null : _checkIp,
                    tooltip: l10n?.refresh ?? 'Refresh',
                  ),
                ),
              ],
            ),

            SizedBox(height: spacing * 2),

            // IP 显示区域
            AnimatedSwitcher(
              duration: AnimationUtils.stateChangeDuration,
              child: _buildIpContent(
                colorScheme,
                textTheme,
                borderRadius,
                spacing,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildIpContent(
    ColorScheme colorScheme,
    TextTheme textTheme,
    double borderRadius,
    double spacing,
  ) {
    final l10n = AppLocalizations.of(context);
    if (_isLoading && _ipInfo == null) {
      return _buildLoadingState(
        colorScheme,
        textTheme,
        borderRadius,
        spacing,
        l10n,
      );
    }

    if (_error != null && _ipInfo == null) {
      return _buildErrorState(
        colorScheme,
        textTheme,
        borderRadius,
        spacing,
        l10n,
      );
    }

    if (_ipInfo != null) {
      return _buildIpInfoState(
        colorScheme,
        textTheme,
        borderRadius,
        spacing,
        l10n,
      );
    }

    return _buildEmptyState(
      colorScheme,
      textTheme,
      borderRadius,
      spacing,
      l10n,
    );
  }

  Widget _buildLoadingState(
    ColorScheme colorScheme,
    TextTheme textTheme,
    double borderRadius,
    double spacing,
    AppLocalizations? l10n,
  ) {
    return Container(
      key: const ValueKey('loading'),
      padding: EdgeInsets.all(spacing * 2),
      decoration: BoxDecoration(
        color: colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          SizedBox(
            width: 20,
            height: 20,
            child: CircularProgressIndicator(
              strokeWidth: 2,
              color: colorScheme.primary,
            ),
          ),
          SizedBox(width: spacing * 1.5),
          Text(
            l10n?.loading ?? 'Loading...',
            style: textTheme.bodyMedium?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorState(
    ColorScheme colorScheme,
    TextTheme textTheme,
    double borderRadius,
    double spacing,
    AppLocalizations? l10n,
  ) {
    return Container(
      key: const ValueKey('error'),
      padding: EdgeInsets.all(spacing * 2),
      decoration: BoxDecoration(
        color: colorScheme.errorContainer.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: Row(
        children: [
          Icon(Icons.error_outline_rounded, color: colorScheme.error, size: 20),
          SizedBox(width: spacing * 1.5),
          Expanded(
            child: Text(
              l10n?.networkRequestFailed ?? 'Network request failed',
              style: textTheme.bodyMedium?.copyWith(color: colorScheme.error),
            ),
          ),
          TextButton(
            onPressed: _checkIp,
            child: Text(l10n?.refresh ?? 'Retry'),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState(
    ColorScheme colorScheme,
    TextTheme textTheme,
    double borderRadius,
    double spacing,
    AppLocalizations? l10n,
  ) {
    return Container(
      key: const ValueKey('empty'),
      padding: EdgeInsets.all(spacing * 2),
      decoration: BoxDecoration(
        color: colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.help_outline_rounded,
            color: colorScheme.onSurfaceVariant,
            size: 20,
          ),
          SizedBox(width: spacing * 1.5),
          Text(
            l10n?.refresh ?? 'Tap to refresh',
            style: textTheme.bodyMedium?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildIpInfoState(
    ColorScheme colorScheme,
    TextTheme textTheme,
    double borderRadius,
    double spacing,
    AppLocalizations? l10n,
  ) {
    return Container(
      key: const ValueKey('ip_info'),
      padding: EdgeInsets.all(spacing * 2),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: widget.isProxyRunning
              ? [
                  colorScheme.primaryContainer.withValues(alpha: 0.5),
                  colorScheme.primaryContainer.withValues(alpha: 0.2),
                ]
              : [
                  colorScheme.surfaceContainerHighest.withValues(alpha: 0.7),
                  colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                ],
        ),
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(
          color: widget.isProxyRunning
              ? colorScheme.primary.withValues(alpha: 0.3)
              : colorScheme.outlineVariant.withValues(alpha: 0.5),
        ),
      ),
      child: Column(
        children: [
          // IP 地址主显示
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      l10n?.ipAddress ?? 'IP Address',
                      style: textTheme.bodySmall?.copyWith(
                        color: colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      _ipInfo!.ip,
                      style: textTheme.headlineSmall?.copyWith(
                        fontWeight: FontWeight.w700,
                        fontFamily: 'monospace',
                        color: widget.isProxyRunning
                            ? colorScheme.primary
                            : colorScheme.onSurface,
                      ),
                    ),
                  ],
                ),
              ),
              IconButton(
                icon: Icon(Icons.copy_rounded, color: colorScheme.primary),
                onPressed: _copyIp,
                tooltip: l10n?.copy ?? 'Copy IP',
              ),
            ],
          ),

          // 详细信息
          if (_ipInfo!.country != null || _ipInfo!.isp != null) ...[
            SizedBox(height: spacing * 1.5),
            Divider(color: colorScheme.outlineVariant.withValues(alpha: 0.5)),
            SizedBox(height: spacing * 1.5),
            Row(
              children: [
                if (_ipInfo!.country != null)
                  Expanded(
                    child: _buildInfoItem(
                      colorScheme,
                      textTheme,
                      Icons.location_on_outlined,
                      l10n?.source ?? 'Location',
                      _ipInfo!.city != null
                          ? '${_ipInfo!.country}, ${_ipInfo!.city}'
                          : _ipInfo!.country!,
                    ),
                  ),
                if (_ipInfo!.country != null && _ipInfo!.isp != null)
                  SizedBox(width: spacing * 2),
                if (_ipInfo!.isp != null)
                  Expanded(
                    child: _buildInfoItem(
                      colorScheme,
                      textTheme,
                      Icons.business_outlined,
                      'ISP',
                      _ipInfo!.isp!,
                    ),
                  ),
              ],
            ),
          ],

          // 代理状态指示
          SizedBox(height: spacing * 1.5),
          Container(
            padding: EdgeInsets.symmetric(
              horizontal: spacing * 1.5,
              vertical: spacing,
            ),
            decoration: BoxDecoration(
              color: widget.isProxyRunning
                  ? Colors.green.withValues(alpha: 0.15)
                  : colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(borderRadius * 0.5),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: widget.isProxyRunning
                        ? Colors.green
                        : colorScheme.outline,
                  ),
                ),
                SizedBox(width: spacing),
                Text(
                  widget.isProxyRunning
                      ? (l10n?.proxyConnection ?? 'Via proxy')
                      : (l10n?.directConnection ?? 'Direct connection'),
                  style: textTheme.bodySmall?.copyWith(
                    color: widget.isProxyRunning
                        ? Colors.green
                        : colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoItem(
    ColorScheme colorScheme,
    TextTheme textTheme,
    IconData icon,
    String label,
    String value,
  ) {
    return Row(
      children: [
        Icon(icon, size: 16, color: colorScheme.onSurfaceVariant),
        const SizedBox(width: 6),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: textTheme.labelSmall?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
              Text(
                value,
                style: textTheme.bodySmall?.copyWith(
                  fontWeight: FontWeight.w500,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ],
          ),
        ),
      ],
    );
  }
}
