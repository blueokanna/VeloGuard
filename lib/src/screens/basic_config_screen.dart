import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:go_router/go_router.dart';
import 'package:veloguard/src/providers/general_settings_provider.dart';
import 'package:veloguard/src/widgets/adaptive_list_tile.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';

class BasicConfigScreen extends StatefulWidget {
  const BasicConfigScreen({super.key});

  @override
  State<BasicConfigScreen> createState() => _BasicConfigScreenState();
}

class _BasicConfigScreenState extends State<BasicConfigScreen> {
  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    return Consumer<GeneralSettingsProvider>(
      builder: (context, settings, child) {
        return Scaffold(
          appBar: AppBar(
            title: Text(l10n?.basicConfig ?? 'Basic Config'),
            leading: IconButton(
              icon: const Icon(Icons.arrow_back),
              onPressed: () => context.go('/settings'),
            ),
          ),
          body: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              // 端口设置
              _buildSectionHeader(
                context,
                l10n?.portSettings ?? 'Port Settings',
                Icons.settings_ethernet_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.httpPort ?? 'HTTP Port'),
                      subtitle: Text('${settings.httpPort}'),
                      leading: Icon(
                        Icons.http_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showPortDialog(
                        context,
                        l10n?.httpPort ?? 'HTTP Port',
                        settings.httpPort,
                        (v) => settings.setHttpPort(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.socksPort ?? 'SOCKS Port'),
                      subtitle: Text('${settings.socksPort}'),
                      leading: Icon(
                        Icons.security_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showPortDialog(
                        context,
                        l10n?.socksPort ?? 'SOCKS Port',
                        settings.socksPort,
                        (v) => settings.setSocksPort(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.mixedPort ?? 'Mixed Port'),
                      subtitle: Text('${settings.mixedPort}'),
                      leading: Icon(
                        Icons.merge_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showPortDialog(
                        context,
                        l10n?.mixedPort ?? 'Mixed Port',
                        settings.mixedPort,
                        (v) => settings.setMixedPort(v),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // 代理模式
              _buildSectionHeader(
                context,
                l10n?.proxyMode ?? 'Proxy Mode',
                Icons.route_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.mode ?? 'Mode'),
                      subtitle: Text(_getModeText(settings.mode, l10n)),
                      leading: Icon(
                        Icons.swap_horiz_outlined,
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
                        child: DropdownButton<String>(
                          value: settings.mode,
                          underline: const SizedBox.shrink(),
                          isDense: true,
                          borderRadius: BorderRadius.circular(12),
                          items: [
                            DropdownMenuItem(
                              value: 'rule',
                              child: Text(l10n?.ruleMode ?? 'Rule'),
                            ),
                            DropdownMenuItem(
                              value: 'global',
                              child: Text(l10n?.globalProxy ?? 'Global'),
                            ),
                            DropdownMenuItem(
                              value: 'direct',
                              child: Text(l10n?.direct ?? 'Direct'),
                            ),
                          ],
                          onChanged: (v) {
                            if (v != null) settings.setMode(v);
                          },
                        ),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.logLevel ?? 'Log Level'),
                      subtitle: Text(settings.logLevel.toUpperCase()),
                      leading: Icon(
                        Icons.description_outlined,
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
                        child: DropdownButton<String>(
                          value: settings.logLevel,
                          underline: const SizedBox.shrink(),
                          isDense: true,
                          borderRadius: BorderRadius.circular(12),
                          items: const [
                            DropdownMenuItem(
                              value: 'error',
                              child: Text('ERROR'),
                            ),
                            DropdownMenuItem(
                              value: 'warn',
                              child: Text('WARN'),
                            ),
                            DropdownMenuItem(
                              value: 'info',
                              child: Text('INFO'),
                            ),
                            DropdownMenuItem(
                              value: 'debug',
                              child: Text('DEBUG'),
                            ),
                            DropdownMenuItem(
                              value: 'trace',
                              child: Text('TRACE'),
                            ),
                          ],
                          onChanged: (v) {
                            if (v != null) settings.setLogLevel(v);
                          },
                        ),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // 网络设置
              _buildSectionHeader(
                context,
                l10n?.networkSettings ?? 'Network Settings',
                Icons.wifi_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.ipv6 ?? 'IPv6'),
                      subtitle: Text(
                        l10n?.ipv6Support ?? 'Enable IPv6 support',
                      ),
                      leading: Icon(
                        Icons.six_k_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: settings.ipv6,
                        onChanged: (v) => settings.setIpv6(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.allowLan ?? 'Allow LAN'),
                      subtitle: Text(
                        settings.allowLan
                            ? (l10n?.allowLanEnabled ??
                                  'Enabled - Other devices can connect')
                            : (l10n?.allowLanDisabled ??
                                  'Disabled - Local only'),
                      ),
                      leading: Icon(
                        Icons.lan_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: settings.allowLan,
                        onChanged: (v) => settings.setAllowLan(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.bindAddress ?? 'Bind Address'),
                      subtitle: Text(
                        _getBindAddressDescription(
                          settings.bindAddress,
                          settings.allowLan,
                          settings.ipv6,
                          l10n,
                        ),
                      ),
                      leading: Icon(
                        Icons.location_on_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.info_outline),
                      onTap: () =>
                          _showBindAddressInfo(context, settings, l10n),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // Hosts 映射
              _buildSectionHeader(
                context,
                l10n?.hostsMapping ?? 'Hosts Mapping',
                Icons.home_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.hosts ?? 'Hosts'),
                      subtitle: Text(
                        '${settings.hosts.length} ${l10n?.items ?? "items"}',
                      ),
                      leading: Icon(
                        Icons.list_alt_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showHostsEditor(context, settings, l10n),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // 外部控制
              _buildSectionHeader(
                context,
                l10n?.externalControl ?? 'External Control',
                Icons.api_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(
                        l10n?.externalController ?? 'External Controller',
                      ),
                      subtitle: Text(
                        settings.externalController ??
                            (l10n?.notSet ?? 'Not set'),
                      ),
                      leading: Icon(
                        Icons.settings_remote_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showTextDialog(
                        context,
                        l10n?.externalController ?? 'External Controller',
                        settings.externalController ?? '',
                        (v) => settings.setExternalController(
                          v.isEmpty ? null : v,
                        ),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.externalUi ?? 'External UI'),
                      subtitle: Text(
                        settings.externalUi ?? (l10n?.notSet ?? 'Not set'),
                      ),
                      leading: Icon(
                        Icons.web_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showTextDialog(
                        context,
                        l10n?.externalUi ?? 'External UI',
                        settings.externalUi ?? '',
                        (v) => settings.setExternalUi(v.isEmpty ? null : v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.secret ?? 'Secret'),
                      subtitle: Text(
                        settings.secret != null
                            ? '••••••••'
                            : (l10n?.notSet ?? 'Not set'),
                      ),
                      leading: Icon(
                        Icons.key_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showTextDialog(
                        context,
                        l10n?.secret ?? 'Secret',
                        settings.secret ?? '',
                        (v) => settings.setSecret(v.isEmpty ? null : v),
                        obscure: true,
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 32),
            ],
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

  String _getModeText(String mode, AppLocalizations? l10n) {
    switch (mode) {
      case 'rule':
        return l10n?.ruleModeName ?? 'Rule Mode';
      case 'global':
        return l10n?.globalModeName ?? 'Global Mode';
      case 'direct':
        return l10n?.directModeName ?? 'Direct Mode';
      default:
        return mode;
    }
  }

  String _getBindAddressDescription(
    String bindAddress,
    bool allowLan,
    bool ipv6,
    AppLocalizations? l10n,
  ) {
    if (bindAddress == '0.0.0.0') {
      return '0.0.0.0 (${l10n?.allIpv4Interfaces ?? "All IPv4 interfaces"})';
    } else if (bindAddress == '::') {
      return ':: (${l10n?.allIpv6Interfaces ?? "All IPv6 interfaces"})';
    } else if (bindAddress == '127.0.0.1') {
      return '127.0.0.1 (${l10n?.localhostIpv4 ?? "Localhost IPv4 only"})';
    } else if (bindAddress == '::1') {
      return '::1 (${l10n?.localhostIpv6 ?? "Localhost IPv6 only"})';
    }
    return bindAddress;
  }

  void _showBindAddressInfo(
    BuildContext context,
    GeneralSettingsProvider settings,
    AppLocalizations? l10n,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.info_outline, color: colorScheme.primary),
            const SizedBox(width: 12),
            Text(l10n?.bindAddressInfo ?? 'Bind Address Info'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildInfoRow(
              context,
              l10n?.currentAddress ?? 'Current Address',
              settings.bindAddress,
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: colorScheme.primaryContainer.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    l10n?.bindAddressAutoDesc ??
                        'Bind address is automatically determined by:',
                    style: textTheme.bodyMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 8),
                  _buildInfoRow(
                    context,
                    l10n?.allowLan ?? 'Allow LAN',
                    settings.allowLan
                        ? (l10n?.yes ?? 'Yes')
                        : (l10n?.no ?? 'No'),
                  ),
                  _buildInfoRow(
                    context,
                    l10n?.ipv6 ?? 'IPv6',
                    settings.ipv6 ? (l10n?.yes ?? 'Yes') : (l10n?.no ?? 'No'),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            Text(
              l10n?.addressTable ?? 'Address Table:',
              style: textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 8),
            _buildAddressTable(context, l10n),
          ],
        ),
        actions: [
          FilledButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n?.understand ?? 'Understand'),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoRow(BuildContext context, String label, String value) {
    final textTheme = Theme.of(context).textTheme;
    final colorScheme = Theme.of(context).colorScheme;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: textTheme.bodyMedium),
          Text(
            value,
            style: textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.w600,
              color: colorScheme.primary,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAddressTable(BuildContext context, AppLocalizations? l10n) {
    final colorScheme = Theme.of(context).colorScheme;

    return Table(
      border: TableBorder.all(
        color: colorScheme.outlineVariant,
        borderRadius: BorderRadius.circular(8),
      ),
      children: [
        TableRow(
          decoration: BoxDecoration(
            color: colorScheme.surfaceContainerHighest,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(8)),
          ),
          children: [
            _buildTableCell(context, l10n?.lan ?? 'LAN', isHeader: true),
            _buildTableCell(context, l10n?.ipv6 ?? 'IPv6', isHeader: true),
            _buildTableCell(
              context,
              l10n?.bindAddress ?? 'Address',
              isHeader: true,
            ),
          ],
        ),
        TableRow(
          children: [
            _buildTableCell(context, l10n?.no ?? 'No'),
            _buildTableCell(context, l10n?.no ?? 'No'),
            _buildTableCell(context, '127.0.0.1', isMono: true),
          ],
        ),
        TableRow(
          children: [
            _buildTableCell(context, l10n?.no ?? 'No'),
            _buildTableCell(context, l10n?.yes ?? 'Yes'),
            _buildTableCell(context, '::1', isMono: true),
          ],
        ),
        TableRow(
          children: [
            _buildTableCell(context, l10n?.yes ?? 'Yes'),
            _buildTableCell(context, l10n?.no ?? 'No'),
            _buildTableCell(context, '0.0.0.0', isMono: true),
          ],
        ),
        TableRow(
          children: [
            _buildTableCell(context, l10n?.yes ?? 'Yes'),
            _buildTableCell(context, l10n?.yes ?? 'Yes'),
            _buildTableCell(context, '::', isMono: true),
          ],
        ),
      ],
    );
  }

  Widget _buildTableCell(
    BuildContext context,
    String text, {
    bool isHeader = false,
    bool isMono = false,
  }) {
    final textTheme = Theme.of(context).textTheme;

    return Padding(
      padding: const EdgeInsets.all(8),
      child: Text(
        text,
        textAlign: TextAlign.center,
        style: textTheme.bodySmall?.copyWith(
          fontWeight: isHeader ? FontWeight.w600 : null,
          fontFamily: isMono ? 'monospace' : null,
        ),
      ),
    );
  }

  void _showPortDialog(
    BuildContext context,
    String title,
    int currentValue,
    Function(int) onSave,
  ) {
    final controller = TextEditingController(text: currentValue.toString());
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          keyboardType: TextInputType.number,
          decoration: InputDecoration(
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
            filled: true,
            fillColor: colorScheme.surfaceContainerHighest,
            hintText: '1-65535',
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n?.cancel ?? 'Cancel'),
          ),
          FilledButton(
            onPressed: () {
              final port = int.tryParse(controller.text);
              if (port != null && port > 0 && port <= 65535) {
                onSave(port);
                Navigator.pop(context);
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(
                      l10n?.validPortHint ??
                          'Please enter a valid port (1-65535)',
                    ),
                  ),
                );
              }
            },
            child: Text(l10n?.save ?? 'Save'),
          ),
        ],
      ),
    );
  }

  void _showTextDialog(
    BuildContext context,
    String title,
    String currentValue,
    Function(String) onSave, {
    bool obscure = false,
  }) {
    final controller = TextEditingController(text: currentValue);
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          obscureText: obscure,
          decoration: InputDecoration(
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
            filled: true,
            fillColor: colorScheme.surfaceContainerHighest,
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n?.cancel ?? 'Cancel'),
          ),
          FilledButton(
            onPressed: () {
              onSave(controller.text);
              Navigator.pop(context);
            },
            child: Text(l10n?.save ?? 'Save'),
          ),
        ],
      ),
    );
  }

  void _showHostsEditor(
    BuildContext context,
    GeneralSettingsProvider settings,
    AppLocalizations? l10n,
  ) {
    final colorScheme = Theme.of(context).colorScheme;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: colorScheme.surfaceContainerLow,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
      ),
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.7,
        minChildSize: 0.5,
        maxChildSize: 0.95,
        expand: false,
        builder: (context, scrollController) => _HostsEditorSheet(
          hosts: settings.hosts,
          onAdd: (domain, ip) => settings.addHost(domain, ip),
          onRemove: (domain) => settings.removeHost(domain),
          scrollController: scrollController,
        ),
      ),
    );
  }
}

class _HostsEditorSheet extends StatefulWidget {
  final Map<String, String> hosts;
  final Function(String, String) onAdd;
  final Function(String) onRemove;
  final ScrollController scrollController;

  const _HostsEditorSheet({
    required this.hosts,
    required this.onAdd,
    required this.onRemove,
    required this.scrollController,
  });

  @override
  State<_HostsEditorSheet> createState() => _HostsEditorSheetState();
}

class _HostsEditorSheetState extends State<_HostsEditorSheet> {
  final _domainController = TextEditingController();
  final _ipController = TextEditingController();
  late Map<String, String> _hosts;

  @override
  void initState() {
    super.initState();
    _hosts = Map.from(widget.hosts);
  }

  @override
  void dispose() {
    _domainController.dispose();
    _ipController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final l10n = AppLocalizations.of(context);

    return SafeArea(
      child: Column(
        children: [
          Container(
            margin: const EdgeInsets.only(top: 12, bottom: 8),
            width: 32,
            height: 4,
            decoration: BoxDecoration(
              color: colorScheme.onSurfaceVariant.withValues(alpha: 0.4),
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(24, 8, 24, 16),
            child: Row(
              children: [
                Icon(Icons.home_outlined, color: colorScheme.primary),
                const SizedBox(width: 12),
                Text(
                  l10n?.hostsMapping ?? 'Hosts Mapping',
                  style: textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _domainController,
                    decoration: InputDecoration(
                      hintText: l10n?.domain ?? 'Domain',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 10,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: TextField(
                    controller: _ipController,
                    decoration: InputDecoration(
                      hintText: l10n?.ipAddress ?? 'IP Address',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 10,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  onPressed: _addHost,
                  icon: const Icon(Icons.add),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          Expanded(
            child: _hosts.isEmpty
                ? Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.inbox_outlined,
                          size: 64,
                          color: colorScheme.onSurfaceVariant.withValues(
                            alpha: 0.5,
                          ),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          l10n?.noHostsMapping ?? 'No hosts mapping',
                          style: textTheme.bodyLarge?.copyWith(
                            color: colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    controller: widget.scrollController,
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    itemCount: _hosts.length,
                    itemBuilder: (context, index) {
                      final domain = _hosts.keys.elementAt(index);
                      final ip = _hosts[domain]!;
                      return Card(
                        elevation: 0,
                        color: colorScheme.surfaceContainerHigh,
                        margin: const EdgeInsets.only(bottom: 8),
                        child: ListTile(
                          title: Text(
                            domain,
                            style: const TextStyle(fontFamily: 'monospace'),
                          ),
                          subtitle: Text(
                            ip,
                            style: TextStyle(
                              fontFamily: 'monospace',
                              color: colorScheme.primary,
                            ),
                          ),
                          trailing: IconButton(
                            icon: Icon(
                              Icons.delete_outline,
                              color: colorScheme.error,
                            ),
                            onPressed: () => _removeHost(domain),
                          ),
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  void _addHost() {
    final domain = _domainController.text.trim();
    final ip = _ipController.text.trim();
    if (domain.isNotEmpty && ip.isNotEmpty) {
      widget.onAdd(domain, ip);
      setState(() {
        _hosts[domain] = ip;
      });
      _domainController.clear();
      _ipController.clear();
    }
  }

  void _removeHost(String domain) {
    widget.onRemove(domain);
    setState(() {
      _hosts.remove(domain);
    });
  }
}
