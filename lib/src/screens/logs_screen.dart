import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:veloguard/src/rust/api.dart' as rust_api;
import 'package:veloguard/src/utils/platform_utils.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';
import 'package:veloguard/main.dart' show isRustLibInitialized;

class LogsScreen extends StatefulWidget {
  const LogsScreen({super.key});

  @override
  State<LogsScreen> createState() => _LogsScreenState();
}

class _LogsScreenState extends State<LogsScreen> {
  List<String> _logs = [];
  bool _isLoading = true;
  bool _autoRefresh = true;
  Timer? _refreshTimer;
  final ScrollController _scrollController = ScrollController();
  String _filterLevel = 'all';

  @override
  void initState() {
    super.initState();
    _loadLogs();
    _startAutoRefresh();
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _scrollController.dispose();
    super.dispose();
  }

  void _startAutoRefresh() {
    _refreshTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      if (_autoRefresh && mounted) {
        _loadLogs(scrollToBottom: false);
      }
    });
  }

  Future<void> _loadLogs({bool scrollToBottom = true}) async {
    try {
      // Check if RustLib is initialized
      if (!isRustLibInitialized) {
        if (mounted) {
          setState(() {
            _logs = ['Rust library not initialized. Please restart the app.'];
            _isLoading = false;
          });
        }
        return;
      }

      // Request more logs (up to 2000) to show more history
      final logs = await rust_api.getLogs(lines: 2000);
      if (mounted) {
        setState(() {
          _logs = logs;
          _isLoading = false;
        });
        if (scrollToBottom && _scrollController.hasClients) {
          WidgetsBinding.instance.addPostFrameCallback((_) {
            if (_scrollController.hasClients) {
              _scrollController.animateTo(
                _scrollController.position.maxScrollExtent,
                duration: const Duration(milliseconds: 300),
                curve: Curves.easeOut,
              );
            }
          });
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _logs = ['Error loading logs: $e'];
          _isLoading = false;
        });
      }
    }
  }

  List<String> get _filteredLogs {
    if (_filterLevel == 'all') return _logs;
    return _logs.where((log) {
      final upperLog = log.toUpperCase();
      switch (_filterLevel) {
        case 'error':
          return upperLog.contains('[ERROR]') || upperLog.contains('ERROR');
        case 'warn':
          return upperLog.contains('[WARN]') ||
              upperLog.contains('WARN') ||
              upperLog.contains('[ERROR]') ||
              upperLog.contains('ERROR');
        case 'info':
          return upperLog.contains('[INFO]') ||
              upperLog.contains('INFO') ||
              upperLog.contains('[WARN]') ||
              upperLog.contains('WARN') ||
              upperLog.contains('[ERROR]') ||
              upperLog.contains('ERROR');
        case 'debug':
          return true; // Show all for debug
        default:
          return true;
      }
    }).toList();
  }

  Color _getLogColor(String log, ColorScheme colorScheme) {
    final upperLog = log.toUpperCase();
    if (upperLog.contains('[ERROR]') || upperLog.contains('ERROR')) {
      return colorScheme.error;
    } else if (upperLog.contains('[WARN]') || upperLog.contains('WARN')) {
      return Colors.orange;
    } else if (upperLog.contains('[INFO]') || upperLog.contains('INFO')) {
      return colorScheme.primary;
    } else if (upperLog.contains('[DEBUG]') || upperLog.contains('DEBUG')) {
      return colorScheme.tertiary;
    }
    return colorScheme.onSurface;
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);
    final filteredLogs = _filteredLogs;

    return Scaffold(
      appBar: AppBar(
        title: Text(
          l10n?.logs ?? '日志',
          style: textTheme.headlineMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        actions: [
          // Filter dropdown
          PopupMenuButton<String>(
            icon: const Icon(Icons.filter_list),
            tooltip: '过滤日志',
            onSelected: (value) {
              setState(() {
                _filterLevel = value;
              });
            },
            itemBuilder: (context) => [
              PopupMenuItem(
                value: 'all',
                child: Row(
                  children: [
                    if (_filterLevel == 'all')
                      const Icon(Icons.check, size: 18),
                    const SizedBox(width: 8),
                    const Text('全部'),
                  ],
                ),
              ),
              PopupMenuItem(
                value: 'error',
                child: Row(
                  children: [
                    if (_filterLevel == 'error')
                      const Icon(Icons.check, size: 18),
                    const SizedBox(width: 8),
                    Text('ERROR', style: TextStyle(color: colorScheme.error)),
                  ],
                ),
              ),
              PopupMenuItem(
                value: 'warn',
                child: Row(
                  children: [
                    if (_filterLevel == 'warn')
                      const Icon(Icons.check, size: 18),
                    const SizedBox(width: 8),
                    const Text('WARN+', style: TextStyle(color: Colors.orange)),
                  ],
                ),
              ),
              PopupMenuItem(
                value: 'info',
                child: Row(
                  children: [
                    if (_filterLevel == 'info')
                      const Icon(Icons.check, size: 18),
                    const SizedBox(width: 8),
                    Text('INFO+', style: TextStyle(color: colorScheme.primary)),
                  ],
                ),
              ),
            ],
          ),
          // Auto refresh toggle
          IconButton(
            icon: Icon(_autoRefresh ? Icons.sync : Icons.sync_disabled),
            tooltip: _autoRefresh ? '自动刷新: 开' : '自动刷新: 关',
            onPressed: () {
              setState(() {
                _autoRefresh = !_autoRefresh;
              });
            },
          ),
          // Manual refresh
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: l10n?.refresh ?? '刷新',
            onPressed: () => _loadLogs(),
          ),
          // Clear logs
          IconButton(
            icon: const Icon(Icons.delete_outline),
            tooltip: l10n?.clearLogs ?? '清除日志',
            onPressed: () {
              setState(() {
                _logs = [];
              });
            },
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : Column(
              children: [
                // Status bar
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 8,
                  ),
                  color: colorScheme.surfaceContainerLow,
                  child: Row(
                    children: [
                      Icon(
                        _autoRefresh
                            ? Icons.fiber_manual_record
                            : Icons.pause_circle_outline,
                        size: 12,
                        color: _autoRefresh
                            ? Colors.green
                            : colorScheme.onSurfaceVariant,
                      ),
                      const SizedBox(width: 8),
                      Text(
                        '${filteredLogs.length} ${l10n?.logEntries ?? '条日志'}',
                        style: textTheme.bodySmall?.copyWith(
                          color: colorScheme.onSurfaceVariant,
                        ),
                      ),
                      const Spacer(),
                      if (Platform.isAndroid || PlatformUtils.isOHOS)
                        Text(
                          'VPN 模式',
                          style: textTheme.bodySmall?.copyWith(
                            color: colorScheme.primary,
                          ),
                        ),
                    ],
                  ),
                ),
                // Log list
                Expanded(
                  child: filteredLogs.isEmpty
                      ? Center(
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Icon(
                                Icons.description_outlined,
                                size: 64,
                                color: colorScheme.onSurfaceVariant.withValues(
                                  alpha: 0.5,
                                ),
                              ),
                              const SizedBox(height: 16),
                              Text(
                                l10n?.noLogs ?? '暂无日志',
                                style: textTheme.bodyLarge?.copyWith(
                                  color: colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ],
                          ),
                        )
                      : ListView.builder(
                          controller: _scrollController,
                          physics: PlatformUtils.getScrollPhysics(),
                          padding: const EdgeInsets.all(8),
                          itemCount: filteredLogs.length,
                          itemBuilder: (context, index) {
                            final log = filteredLogs[index];
                            return Container(
                              margin: const EdgeInsets.symmetric(vertical: 2),
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 6,
                              ),
                              decoration: BoxDecoration(
                                color: colorScheme.surfaceContainerLow,
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: SelectableText(
                                log,
                                style: textTheme.bodySmall?.copyWith(
                                  fontFamily: 'monospace',
                                  color: _getLogColor(log, colorScheme),
                                  height: 1.4,
                                ),
                              ),
                            );
                          },
                        ),
                ),
              ],
            ),
      floatingActionButton: FloatingActionButton.small(
        onPressed: () {
          if (_scrollController.hasClients) {
            _scrollController.animateTo(
              _scrollController.position.maxScrollExtent,
              duration: const Duration(milliseconds: 300),
              curve: Curves.easeOut,
            );
          }
        },
        tooltip: '滚动到底部',
        child: const Icon(Icons.arrow_downward),
      ),
    );
  }
}
