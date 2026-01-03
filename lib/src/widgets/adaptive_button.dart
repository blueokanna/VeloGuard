import 'package:flutter/material.dart';
import 'package:veloguard/src/utils/platform_utils.dart';

class AdaptiveButton extends StatelessWidget {
  final Widget child;
  final VoidCallback? onPressed;
  final VoidCallback? onLongPress;
  final ButtonStyle? style;
  final FocusNode? focusNode;
  final bool autofocus;
  final Clip clipBehavior;
  final WidgetStatesController? statesController;

  const AdaptiveButton({
    super.key,
    required this.child,
    this.onPressed,
    this.onLongPress,
    this.style,
    this.focusNode,
    this.autofocus = false,
    this.clipBehavior = Clip.none,
    this.statesController,
  });

  @override
  Widget build(BuildContext context) {
    final adaptiveStyle = style ?? ButtonStyle(
      padding: WidgetStateProperty.all(
        EdgeInsets.symmetric(
          horizontal: PlatformUtils.isDesktop ? 20 : 16,
          vertical: PlatformUtils.isDesktop ? 12 : 10,
        ),
      ),
      shape: WidgetStateProperty.all(
        RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(PlatformUtils.isDesktop ? 8 : 100),
        ),
      ),
      elevation: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.pressed)) {
          return PlatformUtils.isDesktop ? 2 : 0;
        }
        return PlatformUtils.isDesktop ? 1 : 0;
      }),
      mouseCursor: WidgetStateProperty.all(
        PlatformUtils.isDesktop ? SystemMouseCursors.click : MouseCursor.defer,
      ),
    );

    return FilledButton(
      onPressed: onPressed,
      onLongPress: PlatformUtils.shouldShowContextMenu() ? onLongPress : null,
      style: adaptiveStyle,
      focusNode: focusNode,
      autofocus: autofocus,
      clipBehavior: clipBehavior,
      statesController: statesController,
      child: child,
    );
  }
}

class AdaptiveOutlinedButton extends StatelessWidget {
  final Widget child;
  final VoidCallback? onPressed;
  final VoidCallback? onLongPress;
  final ButtonStyle? style;
  final FocusNode? focusNode;
  final bool autofocus;
  final Clip clipBehavior;
  final WidgetStatesController? statesController;

  const AdaptiveOutlinedButton({
    super.key,
    required this.child,
    this.onPressed,
    this.onLongPress,
    this.style,
    this.focusNode,
    this.autofocus = false,
    this.clipBehavior = Clip.none,
    this.statesController,
  });

  @override
  Widget build(BuildContext context) {
    final adaptiveStyle = style ?? ButtonStyle(
      padding: WidgetStateProperty.all(
        EdgeInsets.symmetric(
          horizontal: PlatformUtils.isDesktop ? 20 : 16,
          vertical: PlatformUtils.isDesktop ? 12 : 10,
        ),
      ),
      shape: WidgetStateProperty.all(
        RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(PlatformUtils.isDesktop ? 8 : 100),
        ),
      ),
      side: WidgetStateProperty.all(
        BorderSide(
          color: Theme.of(context).colorScheme.outline,
          width: 1,
        ),
      ),
      mouseCursor: WidgetStateProperty.all(
        PlatformUtils.isDesktop ? SystemMouseCursors.click : MouseCursor.defer,
      ),
    );

    return OutlinedButton(
      onPressed: onPressed,
      onLongPress: PlatformUtils.shouldShowContextMenu() ? onLongPress : null,
      style: adaptiveStyle,
      focusNode: focusNode,
      autofocus: autofocus,
      clipBehavior: clipBehavior,
      statesController: statesController,
      child: child,
    );
  }
}

class AdaptiveTextButton extends StatelessWidget {
  final Widget child;
  final VoidCallback? onPressed;
  final VoidCallback? onLongPress;
  final ButtonStyle? style;
  final FocusNode? focusNode;
  final bool autofocus;
  final Clip clipBehavior;
  final WidgetStatesController? statesController;

  const AdaptiveTextButton({
    super.key,
    required this.child,
    this.onPressed,
    this.onLongPress,
    this.style,
    this.focusNode,
    this.autofocus = false,
    this.clipBehavior = Clip.none,
    this.statesController,
  });

  @override
  Widget build(BuildContext context) {
    final adaptiveStyle = style ?? ButtonStyle(
      padding: WidgetStateProperty.all(
        EdgeInsets.symmetric(
          horizontal: PlatformUtils.isDesktop ? 16 : 12,
          vertical: PlatformUtils.isDesktop ? 12 : 8,
        ),
      ),
      shape: WidgetStateProperty.all(
        RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(PlatformUtils.isDesktop ? 6 : 8),
        ),
      ),
      mouseCursor: WidgetStateProperty.all(
        PlatformUtils.isDesktop ? SystemMouseCursors.click : MouseCursor.defer,
      ),
    );

    return TextButton(
      onPressed: onPressed,
      onLongPress: PlatformUtils.shouldShowContextMenu() ? onLongPress : null,
      style: adaptiveStyle,
      focusNode: focusNode,
      autofocus: autofocus,
      clipBehavior: clipBehavior,
      statesController: statesController,
      child: child,
    );
  }
}
