import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:go_router/go_router.dart';
import 'package:veloguard/src/providers/dns_settings_provider.dart';
import 'package:veloguard/src/widgets/adaptive_list_tile.dart';
import 'package:veloguard/src/l10n/app_localizations.dart';

class DnsSettingsScreen extends StatefulWidget {
  const DnsSettingsScreen({super.key});

  @override
  State<DnsSettingsScreen> createState() => _DnsSettingsScreenState();
}

class _DnsSettingsScreenState extends State<DnsSettingsScreen> {
  final _listenController = TextEditingController();
  final _fakeIpRangeController = TextEditingController();
  final _addItemController = TextEditingController();

  @override
  void dispose() {
    _listenController.dispose();
    _fakeIpRangeController.dispose();
    _addItemController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    return Consumer<DnsSettingsProvider>(
      builder: (context, dnsSettings, child) {
        _listenController.text = dnsSettings.listen;
        _fakeIpRangeController.text = dnsSettings.fakeIpRange;

        return Scaffold(
          appBar: AppBar(
            title: Text(l10n?.dnsSettings ?? 'DNS Settings'),
            leading: IconButton(
              icon: const Icon(Icons.arrow_back),
              onPressed: () => context.go('/settings'),
            ),
          ),
          body: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _buildSectionHeader(
                context,
                l10n?.basicSettings ?? 'Basic Settings',
                Icons.settings_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.overrideDns ?? 'Override DNS'),
                      subtitle: Text(
                        l10n?.overrideDnsDesc ??
                            'Override system DNS when enabled',
                      ),
                      leading: Icon(
                        Icons.dns_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: dnsSettings.overrideDns,
                        onChanged: (v) => dnsSettings.setOverrideDns(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.dnsStatus ?? 'DNS Status'),
                      subtitle: Text(
                        dnsSettings.enable
                            ? (l10n?.enabled ?? 'Enabled')
                            : (l10n?.disabled ?? 'Disabled'),
                      ),
                      leading: Icon(
                        dnsSettings.enable
                            ? Icons.check_circle_outline
                            : Icons.cancel_outlined,
                        color: dnsSettings.enable
                            ? colorScheme.primary
                            : colorScheme.error,
                      ),
                      trailing: Switch.adaptive(
                        value: dnsSettings.enable,
                        onChanged: (v) => dnsSettings.setEnable(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.listenAddress ?? 'Listen Address'),
                      subtitle: Text(dnsSettings.listen),
                      leading: Icon(
                        Icons.hearing_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.edit_outlined),
                      onTap: () => _showEditDialog(
                        context,
                        l10n?.listenAddress ?? 'Listen Address',
                        dnsSettings.listen,
                        (v) => dnsSettings.setListen(v),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // Hosts 设置
              _buildSectionHeader(
                context,
                l10n?.hostsSettings ?? 'Hosts Settings',
                Icons.home_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.useHosts ?? 'Use Hosts'),
                      subtitle: Text(
                        l10n?.useHostsDesc ?? 'Use custom hosts mapping',
                      ),
                      leading: Icon(
                        Icons.list_alt_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: dnsSettings.useHosts,
                        onChanged: (v) => dnsSettings.setUseHosts(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.useSystemHosts ?? 'Use System Hosts'),
                      subtitle: Text(
                        l10n?.useSystemHostsDesc ?? 'Read system hosts file',
                      ),
                      leading: Icon(
                        Icons.computer_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: dnsSettings.useSystemHosts,
                        onChanged: (v) => dnsSettings.setUseSystemHosts(v),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // 高级设置
              _buildSectionHeader(
                context,
                l10n?.advancedSettings ?? 'Advanced Settings',
                Icons.tune_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.ipv6 ?? 'IPv6'),
                      subtitle: Text(
                        l10n?.ipv6DnsDesc ?? 'Enable IPv6 DNS resolution',
                      ),
                      leading: Icon(
                        Icons.six_k_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: dnsSettings.ipv6,
                        onChanged: (v) => dnsSettings.setIpv6(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.followRules ?? 'Follow Rules'),
                      subtitle: Text(
                        l10n?.followRulesDesc ??
                            'DNS requests follow proxy rules',
                      ),
                      leading: Icon(
                        Icons.rule_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: dnsSettings.followRules,
                        onChanged: (v) => dnsSettings.setFollowRules(v),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.preferH3 ?? 'Prefer HTTP/3'),
                      subtitle: Text(
                        l10n?.preferH3Desc ?? 'DoH prefers HTTP/3',
                      ),
                      leading: Icon(
                        Icons.speed_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: dnsSettings.preferH3,
                        onChanged: (v) => dnsSettings.setPreferH3(v),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // DNS 模式
              _buildSectionHeader(
                context,
                l10n?.dnsMode ?? 'DNS Mode',
                Icons.dns_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.dnsMode ?? 'DNS Mode'),
                      subtitle: Text(
                        _getDnsModeText(dnsSettings.dnsMode, l10n),
                      ),
                      leading: Icon(
                        Icons.settings_input_component_outlined,
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
                          value: dnsSettings.dnsMode,
                          underline: const SizedBox.shrink(),
                          isDense: true,
                          borderRadius: BorderRadius.circular(12),
                          items: const [
                            DropdownMenuItem(
                              value: 'normal',
                              child: Text('Normal'),
                            ),
                            DropdownMenuItem(
                              value: 'fake-ip',
                              child: Text('Fake-IP'),
                            ),
                            DropdownMenuItem(
                              value: 'redir-host',
                              child: Text('Redir-Host'),
                            ),
                          ],
                          onChanged: (v) {
                            if (v != null) dnsSettings.setDnsMode(v);
                          },
                        ),
                      ),
                    ),
                    if (dnsSettings.dnsMode == 'fake-ip') ...[
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.fakeIpRange ?? 'Fake-IP Range'),
                        subtitle: Text(dnsSettings.fakeIpRange),
                        leading: Icon(
                          Icons.lan_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.edit_outlined),
                        onTap: () => _showEditDialog(
                          context,
                          l10n?.fakeIpRange ?? 'Fake-IP Range',
                          dnsSettings.fakeIpRange,
                          (v) => dnsSettings.setFakeIpRange(v),
                        ),
                      ),
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.fakeIpFilter ?? 'Fake-IP Filter'),
                        subtitle: Text(
                          '${dnsSettings.fakeIpFilter.length} ${l10n?.items ?? 'items'}',
                        ),
                        leading: Icon(
                          Icons.filter_list_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => _showListEditor(
                          context,
                          l10n?.fakeIpFilter ?? 'Fake-IP Filter',
                          dnsSettings.fakeIpFilter,
                          (item) => dnsSettings.addFakeIpFilter(item),
                          (item) => dnsSettings.removeFakeIpFilter(item),
                        ),
                      ),
                    ],
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // DNS 服务器
              _buildSectionHeader(
                context,
                l10n?.dnsServers ?? 'DNS Servers',
                Icons.cloud_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: Text(l10n?.defaultDns ?? 'Default DNS'),
                      subtitle: Text(
                        '${dnsSettings.defaultNameservers.length} ${l10n?.servers ?? 'servers'}',
                      ),
                      leading: Icon(
                        Icons.dns_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showListEditor(
                        context,
                        l10n?.defaultDns ?? 'Default DNS',
                        dnsSettings.defaultNameservers,
                        (item) => dnsSettings.addDefaultNameserver(item),
                        (item) => dnsSettings.removeDefaultNameserver(item),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.nameservers ?? 'Nameservers'),
                      subtitle: Text(
                        '${dnsSettings.nameservers.length} ${l10n?.servers ?? 'servers'}',
                      ),
                      leading: Icon(
                        Icons.public_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showListEditor(
                        context,
                        l10n?.nameservers ?? 'Nameservers',
                        dnsSettings.nameservers,
                        (item) => dnsSettings.addNameserver(item),
                        (item) => dnsSettings.removeNameserver(item),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.fallbackServers ?? 'Fallback Servers'),
                      subtitle: Text(
                        '${dnsSettings.fallback.length} ${l10n?.servers ?? 'servers'}',
                      ),
                      leading: Icon(
                        Icons.backup_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showListEditor(
                        context,
                        l10n?.fallbackServers ?? 'Fallback Servers',
                        dnsSettings.fallback,
                        (item) => dnsSettings.addFallback(item),
                        (item) => dnsSettings.removeFallback(item),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.proxyDns ?? 'Proxy DNS'),
                      subtitle: Text(
                        '${dnsSettings.proxyNameservers.length} ${l10n?.servers ?? 'servers'}',
                      ),
                      leading: Icon(
                        Icons.vpn_key_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showListEditor(
                        context,
                        l10n?.proxyDns ?? 'Proxy DNS',
                        dnsSettings.proxyNameservers,
                        (item) => dnsSettings.addProxyNameserver(item),
                        (item) => dnsSettings.removeProxyNameserver(item),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // Fallback 过滤器
              _buildSectionHeader(
                context,
                l10n?.fallbackFilter ?? 'Fallback Filter',
                Icons.filter_alt_outlined,
              ),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerLow,
                child: Column(
                  children: [
                    AdaptiveListTile(
                      title: const Text('GeoIP'),
                      subtitle: Text(
                        l10n?.enableGeoipFilter ?? 'Enable GeoIP filter',
                      ),
                      leading: Icon(
                        Icons.location_on_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: Switch.adaptive(
                        value: dnsSettings.fallbackFilter.geoip,
                        onChanged: (v) => dnsSettings.setFallbackFilterGeoip(v),
                      ),
                    ),
                    if (dnsSettings.fallbackFilter.geoip) ...[
                      const Divider(height: 1, indent: 16, endIndent: 16),
                      AdaptiveListTile(
                        title: Text(l10n?.geoipCode ?? 'GeoIP Code'),
                        subtitle: Text(dnsSettings.fallbackFilter.geoipCode),
                        leading: Icon(
                          Icons.flag_outlined,
                          color: colorScheme.primary,
                        ),
                        trailing: const Icon(Icons.edit_outlined),
                        onTap: () => _showEditDialog(
                          context,
                          l10n?.geoipCode ?? 'GeoIP Code',
                          dnsSettings.fallbackFilter.geoipCode,
                          (v) => dnsSettings.setFallbackFilterGeoipCode(v),
                        ),
                      ),
                    ],
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.geosite ?? 'Geosite'),
                      subtitle: Text(
                        '${dnsSettings.fallbackFilter.geosite.length} ${l10n?.items ?? 'items'}',
                      ),
                      leading: Icon(
                        Icons.language_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showListEditor(
                        context,
                        l10n?.geosite ?? 'Geosite',
                        dnsSettings.fallbackFilter.geosite,
                        (item) => dnsSettings.addFallbackFilterGeosite(item),
                        (item) => dnsSettings.removeFallbackFilterGeosite(item),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.ipCidr ?? 'IP/CIDR'),
                      subtitle: Text(
                        '${dnsSettings.fallbackFilter.ipCidr.length} ${l10n?.items ?? 'items'}',
                      ),
                      leading: Icon(
                        Icons.router_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showListEditor(
                        context,
                        l10n?.ipCidr ?? 'IP/CIDR',
                        dnsSettings.fallbackFilter.ipCidr,
                        (item) => dnsSettings.addFallbackFilterIpCidr(item),
                        (item) => dnsSettings.removeFallbackFilterIpCidr(item),
                      ),
                    ),
                    const Divider(height: 1, indent: 16, endIndent: 16),
                    AdaptiveListTile(
                      title: Text(l10n?.domain ?? 'Domain'),
                      subtitle: Text(
                        '${dnsSettings.fallbackFilter.domain.length} ${l10n?.items ?? 'items'}',
                      ),
                      leading: Icon(
                        Icons.domain_outlined,
                        color: colorScheme.primary,
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showListEditor(
                        context,
                        l10n?.domain ?? 'Domain',
                        dnsSettings.fallbackFilter.domain,
                        (item) => dnsSettings.addFallbackFilterDomain(item),
                        (item) => dnsSettings.removeFallbackFilterDomain(item),
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

  String _getDnsModeText(String mode, AppLocalizations? l10n) {
    switch (mode) {
      case 'normal':
        return l10n?.normalMode ?? 'Normal Mode';
      case 'fake-ip':
        return l10n?.fakeIpMode ?? 'Fake-IP Mode';
      case 'redir-host':
        return l10n?.redirHostMode ?? 'Redir-Host Mode';
      default:
        return mode;
    }
  }

  void _showEditDialog(
    BuildContext context,
    String title,
    String currentValue,
    Function(String) onSave,
  ) {
    final controller = TextEditingController(text: currentValue);
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
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

  void _showListEditor(
    BuildContext context,
    String title,
    List<String> items,
    Function(String) onAdd,
    Function(String) onRemove,
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
        builder: (context, scrollController) => _ListEditorSheet(
          title: title,
          items: items,
          onAdd: onAdd,
          onRemove: onRemove,
          scrollController: scrollController,
        ),
      ),
    );
  }
}

class _ListEditorSheet extends StatefulWidget {
  final String title;
  final List<String> items;
  final Function(String) onAdd;
  final Function(String) onRemove;
  final ScrollController scrollController;

  const _ListEditorSheet({
    required this.title,
    required this.items,
    required this.onAdd,
    required this.onRemove,
    required this.scrollController,
  });

  @override
  State<_ListEditorSheet> createState() => _ListEditorSheetState();
}

class _ListEditorSheetState extends State<_ListEditorSheet> {
  final _controller = TextEditingController();
  late List<String> _items;

  @override
  void initState() {
    super.initState();
    _items = List.from(widget.items);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

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
                Icon(Icons.list_outlined, color: colorScheme.primary),
                const SizedBox(width: 12),
                Text(
                  widget.title,
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
                    controller: _controller,
                    decoration: InputDecoration(
                      hintText:
                          AppLocalizations.of(context)?.addNewItem ??
                          'Add new item...',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 12,
                      ),
                    ),
                    onSubmitted: (value) => _addItem(),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  onPressed: _addItem,
                  icon: const Icon(Icons.add),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          Expanded(
            child: _items.isEmpty
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
                          AppLocalizations.of(context)?.noDataYet ??
                              'No data yet',
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
                    itemCount: _items.length,
                    itemBuilder: (context, index) {
                      final item = _items[index];
                      return Card(
                        elevation: 0,
                        color: colorScheme.surfaceContainerHigh,
                        margin: const EdgeInsets.only(bottom: 8),
                        child: ListTile(
                          title: Text(
                            item,
                            style: const TextStyle(fontFamily: 'monospace'),
                          ),
                          trailing: IconButton(
                            icon: Icon(
                              Icons.delete_outline,
                              color: colorScheme.error,
                            ),
                            onPressed: () => _removeItem(item),
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

  void _addItem() {
    final value = _controller.text.trim();
    if (value.isNotEmpty && !_items.contains(value)) {
      widget.onAdd(value);
      setState(() {
        _items.add(value);
      });
      _controller.clear();
    }
  }

  void _removeItem(String item) {
    widget.onRemove(item);
    setState(() {
      _items.remove(item);
    });
  }
}
