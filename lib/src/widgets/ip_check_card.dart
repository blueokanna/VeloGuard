import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/utils/animation_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/src/services/platform_proxy_service.dart';
import 'package:veloguard/src/services/storage_service.dart';

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

class IpCheckCard extends StatefulWidget {
  final bool isProxyRunning;

  const IpCheckCard({super.key, required this.isProxyRunning});

  @override
  State<IpCheckCard> createState() => _IpCheckCardState();
}

class _IpCheckCardState extends State<IpCheckCard>
    with SingleTickerProviderStateMixin {
  IpInfo? _ipInfo;
  bool _isLoading = false;
  String? _error;
  int _proxyPort = 7890;
  late AnimationController _refreshController;
  Timer? _autoRefreshTimer;
  String? _lastKnownIp;
  bool _isVpnActive = false;

  @override
  void initState() {
    super.initState();
    _refreshController = AnimationController(
      duration: const Duration(milliseconds: 1000),
      vsync: this,
    );

    _loadProxyPort();
    _checkIp();
    _startAutoRefresh();
  }

  Future<void> _loadProxyPort() async {
    try {
      final settings = await StorageService.instance.getGeneralSettings();
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

  void _startAutoRefresh() {
    _autoRefreshTimer?.cancel();
    _autoRefreshTimer = Timer.periodic(const Duration(seconds: 30), (_) {
      _checkIpSilently();
      _checkVpnStatus();
    });
  }

  ///
  Future<void> _checkVpnStatus() async {
    try {
      final isVpnActive = await PlatformProxyService.instance.isAnyVpnActive();
      if (mounted && _isVpnActive != isVpnActive) {
        setState(() {
          _isVpnActive = isVpnActive;
        });
      }
    } catch (e) {
      debugPrint('Failed to check VPN status: $e');
    }
  }

  /// 静默检测 IP 变化（不显示 loading 状态）
  Future<void> _checkIpSilently() async {
    if (_isLoading) return;

    try {
      final ip = await _fetchIpFromIpSb();
      if (ip != null && mounted) {
        if (_lastKnownIp != null && _lastKnownIp != ip) {
          debugPrint('IP changed: $_lastKnownIp -> $ip');
          _checkIp();
        } else if (_lastKnownIp == null) {
          _lastKnownIp = ip;
        }
      }
    } catch (e) {
      debugPrint('Silent IP check failed: $e');
    }
  }

  @override
  void didUpdateWidget(IpCheckCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    // 代理状态变化时自动刷新
    if (widget.isProxyRunning != oldWidget.isProxyRunning) {
      Future.delayed(const Duration(milliseconds: 500), () {
        if (mounted) _checkIp();
      });
    }
  }

  @override
  void dispose() {
    _refreshController.dispose();
    _autoRefreshTimer?.cancel();
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
      // 同时检查VPN状态
      _checkVpnStatus();

      // 使用 ip.sb 获取 IP（不使用缓存）
      final ip = await _fetchIpFromIpSb();
      if (ip != null && mounted) {
        _lastKnownIp = ip;
        // 尝试获取更多 IP 信息
        final ipInfo = await _fetchIpDetails(ip);
        final result = ipInfo ?? IpInfo(ip: ip);

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
  /// 当代理运行时，请求会通过代理发出，获取的是代理出口 IP
  Future<String?> _fetchIpFromIpSb() async {
    // 尝试多个 IP 检测服务
    final services = [
      'https://api.ip.sb/ip',
      'https://api.ipify.org',
      'https://icanhazip.com',
      'https://ifconfig.me/ip',
    ];

    for (final url in services) {
      try {
        final client = HttpClient();
        client.connectionTimeout = const Duration(seconds: 10);

        // 当应用自身的代理运行时（非TUN模式），通过本地代理发送请求
        // 注意：如果是TUN模式或外部VPN，流量已经通过VPN隧道，不需要设置findProxy
        // _isVpnActive 表示系统级VPN（包括我们的TUN模式），此时流量自动走VPN
        // widget.isProxyRunning 表示应用的代理服务在运行
        // 只有当代理运行但不是VPN模式时，才需要手动设置代理
        if (widget.isProxyRunning && !_isVpnActive) {
          client.findProxy = (uri) => 'PROXY 127.0.0.1:$_proxyPort';
          // 允许自签名证书（某些代理可能使用）
          client.badCertificateCallback = (cert, host, port) => true;
        }

        final request = await client.getUrl(Uri.parse(url));
        request.headers.set('User-Agent', 'VeloGuard/1.0');

        final response = await request.close();
        if (response.statusCode == 200) {
          final body = await response.transform(utf8.decoder).join();
          final ip = body.trim();
          // 验证是否是有效的 IP 地址
          if (_isValidIp(ip)) {
            client.close();
            return ip;
          }
        }
        client.close();
      } catch (e) {
        debugPrint('$url request failed: $e');
      }
    }

    return null;
  }

  /// 验证 IP 地址格式
  bool _isValidIp(String ip) {
    // IPv4 验证
    final ipv4Regex = RegExp(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$');
    if (ipv4Regex.hasMatch(ip)) {
      final parts = ip.split('.').map(int.parse).toList();
      return parts.every((p) => p >= 0 && p <= 255);
    }

    // IPv6 验证 (简化版)
    final ipv6Regex = RegExp(r'^[0-9a-fA-F:]+$');
    if (ipv6Regex.hasMatch(ip) && ip.contains(':')) {
      return true;
    }

    return false;
  }

  /// 获取 IP 详细信息
  Future<IpInfo?> _fetchIpDetails(String ip) async {
    try {
      final client = HttpClient();
      client.connectionTimeout = const Duration(seconds: 5);

      // 当应用自身的代理运行时（非TUN模式），通过本地代理发送请求
      if (widget.isProxyRunning && !_isVpnActive) {
        client.findProxy = (uri) => 'PROXY 127.0.0.1:$_proxyPort';
        client.badCertificateCallback = (cert, host, port) => true;
      }

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

    // 使用系统VPN状态来判断是否通过代理
    final isUsingProxy = _isVpnActive || widget.isProxyRunning;

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
                    color: isUsingProxy
                        ? colorScheme.primaryContainer
                        : colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(borderRadius * 0.6),
                  ),
                  child: Icon(
                    Icons.public_rounded,
                    size: 20,
                    color: isUsingProxy
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
                        isUsingProxy
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
                isUsingProxy,
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
    bool isUsingProxy,
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
        isUsingProxy,
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
    bool isUsingProxy,
  ) {
    return Container(
      key: const ValueKey('ip_info'),
      padding: EdgeInsets.all(spacing * 2),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: isUsingProxy
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
          color: isUsingProxy
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
                        color: isUsingProxy
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
              color: isUsingProxy
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
                    color: isUsingProxy ? Colors.green : colorScheme.outline,
                  ),
                ),
                SizedBox(width: spacing),
                Text(
                  isUsingProxy
                      ? (l10n?.proxyConnection ?? 'Via proxy')
                      : (l10n?.directConnection ?? 'Direct connection'),
                  style: textTheme.bodySmall?.copyWith(
                    color: isUsingProxy
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
