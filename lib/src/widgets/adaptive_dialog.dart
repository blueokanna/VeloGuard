import 'package:flutter/material.dart';
import 'package:veloguard/src/utils/platform_utils.dart';

class AdaptiveDialog extends StatelessWidget {
  final Widget? title;
  final Widget? content;
  final List<Widget>? actions;
  final EdgeInsetsGeometry? titlePadding;
  final EdgeInsetsGeometry? contentPadding;
  final EdgeInsetsGeometry? actionsPadding;
  final MainAxisAlignment? actionsAlignment;
  final VerticalDirection? actionsOverflowDirection;
  final double? actionsOverflowButtonSpacing;
  final EdgeInsetsGeometry? buttonPadding;
  final Color? backgroundColor;
  final double? elevation;
  final Color? shadowColor;
  final Color? surfaceTintColor;
  final String? semanticLabel;
  final EdgeInsets? insetPadding;
  final Clip? clipBehavior;
  final ShapeBorder? shape;
  final AlignmentGeometry? alignment;
  final bool scrollable;

  const AdaptiveDialog({
    super.key,
    this.title,
    this.content,
    this.actions,
    this.titlePadding,
    this.contentPadding,
    this.actionsPadding,
    this.actionsAlignment,
    this.actionsOverflowDirection,
    this.actionsOverflowButtonSpacing,
    this.buttonPadding,
    this.backgroundColor,
    this.elevation,
    this.shadowColor,
    this.surfaceTintColor,
    this.semanticLabel,
    this.insetPadding,
    this.clipBehavior,
    this.shape,
    this.alignment,
    this.scrollable = false,
  });

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: backgroundColor,
      elevation: elevation,
      shadowColor: shadowColor,
      surfaceTintColor: surfaceTintColor,
      insetPadding:
          insetPadding ??
          EdgeInsets.symmetric(
            horizontal: PlatformUtils.isDesktop ? 40 : 16,
            vertical: PlatformUtils.isDesktop ? 24 : 16,
          ),
      clipBehavior: clipBehavior,
      shape:
          shape ??
          RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(
              PlatformUtils.isDesktop ? 12 : 16,
            ),
          ),
      alignment: alignment,
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: PlatformUtils.getDialogWidth(context),
          maxHeight: PlatformUtils.getDialogHeight(context) ?? double.infinity,
        ),
        child: IntrinsicWidth(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (title != null) ...[
                Padding(
                  padding:
                      titlePadding ??
                      EdgeInsets.fromLTRB(
                        PlatformUtils.isDesktop ? 24 : 20,
                        PlatformUtils.isDesktop ? 24 : 20,
                        PlatformUtils.isDesktop ? 24 : 20,
                        PlatformUtils.isDesktop ? 16 : 12,
                      ),
                  child: DefaultTextStyle(
                    style: Theme.of(context).textTheme.headlineSmall!.copyWith(
                      fontSize: PlatformUtils.isDesktop ? 20 : 18,
                    ),
                    child: title!,
                  ),
                ),
              ],
              if (content != null) ...[
                Flexible(
                  child: Padding(
                    padding:
                        contentPadding ??
                        EdgeInsets.fromLTRB(
                          PlatformUtils.isDesktop ? 24 : 20,
                          0,
                          PlatformUtils.isDesktop ? 24 : 20,
                          PlatformUtils.isDesktop ? 20 : 16,
                        ),
                    child: scrollable
                        ? SingleChildScrollView(child: content!)
                        : content!,
                  ),
                ),
              ],
              if (actions != null && actions!.isNotEmpty) ...[
                Padding(
                  padding:
                      actionsPadding ??
                      EdgeInsets.fromLTRB(
                        PlatformUtils.isDesktop ? 16 : 12,
                        0,
                        PlatformUtils.isDesktop ? 16 : 12,
                        PlatformUtils.isDesktop ? 16 : 12,
                      ),
                  child: OverflowBar(
                    alignment: actionsAlignment ?? MainAxisAlignment.end,
                    overflowDirection:
                        actionsOverflowDirection ?? VerticalDirection.down,
                    overflowAlignment: OverflowBarAlignment.end,
                    spacing:
                        actionsOverflowButtonSpacing ??
                        (PlatformUtils.isDesktop ? 8 : 4),
                    children: actions!.map((action) {
                      return Padding(
                        padding:
                            buttonPadding ??
                            const EdgeInsets.symmetric(horizontal: 4),
                        child: action,
                      );
                    }).toList(),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  static Future<T?> show<T>({
    required BuildContext context,
    required WidgetBuilder builder,
    bool barrierDismissible = true,
    Color? barrierColor = Colors.black54,
    String? barrierLabel,
    bool useSafeArea = true,
    bool useRootNavigator = true,
    RouteSettings? routeSettings,
    Offset? anchorPoint,
  }) {
    return showDialog<T>(
      context: context,
      barrierDismissible: barrierDismissible,
      barrierColor: barrierColor,
      barrierLabel: barrierLabel,
      useSafeArea: useSafeArea,
      useRootNavigator: useRootNavigator,
      routeSettings: routeSettings,
      anchorPoint: anchorPoint,
      builder: builder,
    );
  }
}
