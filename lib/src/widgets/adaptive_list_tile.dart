import 'package:flutter/material.dart';
import 'package:veloguard/src/utils/platform_utils.dart';

class AdaptiveListTile extends StatelessWidget {
  final Widget? leading;
  final Widget? title;
  final Widget? subtitle;
  final Widget? trailing;
  final bool isThreeLine;
  final bool dense;
  final VisualDensity? visualDensity;
  final ShapeBorder? shape;
  final ListTileStyle? style;
  final Color? selectedColor;
  final Color? iconColor;
  final Color? textColor;
  final TextStyle? titleTextStyle;
  final TextStyle? subtitleTextStyle;
  final TextStyle? leadingAndTrailingTextStyle;
  final EdgeInsetsGeometry? contentPadding;
  final bool enabled;
  final GestureTapCallback? onTap;
  final GestureLongPressCallback? onLongPress;
  final MouseCursor? mouseCursor;
  final bool selected;
  final Color? focusColor;
  final Color? hoverColor;
  final Color? splashColor;
  final FocusNode? focusNode;
  final bool autofocus;
  final Color? tileColor;
  final Color? selectedTileColor;
  final bool? enableFeedback;
  final double? horizontalTitleGap;
  final double? minVerticalPadding;
  final double? minLeadingWidth;
  final bool? isAdaptive;

  const AdaptiveListTile({
    super.key,
    this.leading,
    this.title,
    this.subtitle,
    this.trailing,
    this.isThreeLine = false,
    this.dense = false,
    this.visualDensity,
    this.shape,
    this.style,
    this.selectedColor,
    this.iconColor,
    this.textColor,
    this.titleTextStyle,
    this.subtitleTextStyle,
    this.leadingAndTrailingTextStyle,
    this.contentPadding,
    this.enabled = true,
    this.onTap,
    this.onLongPress,
    this.mouseCursor,
    this.selected = false,
    this.focusColor,
    this.hoverColor,
    this.splashColor,
    this.focusNode,
    this.autofocus = false,
    this.tileColor,
    this.selectedTileColor,
    this.enableFeedback,
    this.horizontalTitleGap,
    this.minVerticalPadding,
    this.minLeadingWidth,
    this.isAdaptive = true,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    
    final adaptiveDensity = visualDensity ??
        (PlatformUtils.isDesktop
            ? VisualDensity.comfortable
            : VisualDensity.standard);

    final adaptivePadding = contentPadding ??
        EdgeInsets.symmetric(
          horizontal: PlatformUtils.isDesktop ? 16 : 12,
          vertical: PlatformUtils.isDesktop ? 8 : 4,
        );

    final adaptiveMinVerticalPadding =
        minVerticalPadding ?? (PlatformUtils.isDesktop ? 8 : 4);

    // Use transparent tile color to let Card background show through
    final effectiveTileColor = tileColor ?? Colors.transparent;
    
    // Selected tile color with proper opacity
    final effectiveSelectedTileColor = selectedTileColor ?? 
        colorScheme.primaryContainer.withValues(alpha: 0.3);

    // Hover color that works well with both dynamic and static themes
    final effectiveHoverColor = hoverColor ?? 
        colorScheme.onSurface.withValues(alpha: 0.04);

    return ListTile(
      leading: leading,
      title: title,
      subtitle: subtitle,
      trailing: trailing,
      isThreeLine: isThreeLine,
      dense: dense,
      visualDensity: isAdaptive == true ? adaptiveDensity : visualDensity,
      shape: shape ?? RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(PlatformUtils.isDesktop ? 8 : 12),
      ),
      style: style,
      selectedColor: selectedColor ?? colorScheme.primary,
      iconColor: iconColor ?? colorScheme.onSurfaceVariant,
      textColor: textColor ?? colorScheme.onSurface,
      titleTextStyle: titleTextStyle,
      subtitleTextStyle: subtitleTextStyle?.copyWith(
        color: colorScheme.onSurfaceVariant,
      ),
      leadingAndTrailingTextStyle: leadingAndTrailingTextStyle,
      contentPadding: isAdaptive == true ? adaptivePadding : contentPadding,
      enabled: enabled,
      onTap: onTap,
      onLongPress: PlatformUtils.shouldShowContextMenu() ? onLongPress : null,
      mouseCursor: mouseCursor ??
          (PlatformUtils.isDesktop
              ? SystemMouseCursors.click
              : MouseCursor.defer),
      selected: selected,
      focusColor: focusColor ?? colorScheme.primary.withValues(alpha: 0.12),
      hoverColor: effectiveHoverColor,
      splashColor: splashColor ?? colorScheme.primary.withValues(alpha: 0.08),
      focusNode: focusNode,
      autofocus: autofocus,
      tileColor: effectiveTileColor,
      selectedTileColor: effectiveSelectedTileColor,
      enableFeedback: enableFeedback ?? PlatformUtils.isMobile,
      horizontalTitleGap: horizontalTitleGap ?? (PlatformUtils.isDesktop ? 16 : 12),
      minVerticalPadding: isAdaptive == true ? adaptiveMinVerticalPadding : minVerticalPadding,
      minLeadingWidth: minLeadingWidth ?? (PlatformUtils.isDesktop ? 48 : 40),
    );
  }
}
