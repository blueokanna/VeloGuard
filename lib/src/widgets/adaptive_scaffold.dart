import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:veloguard/src/utils/platform_utils.dart';
import 'package:veloguard/src/utils/responsive_utils.dart';
import 'package:veloguard/src/widgets/navigation_bar.dart';

class AdaptiveScaffold extends StatelessWidget {
  final Widget body;
  final PreferredSizeWidget? appBar;
  final Widget? floatingActionButton;
  final FloatingActionButtonLocation? floatingActionButtonLocation;
  final FloatingActionButtonAnimator? floatingActionButtonAnimator;
  final List<Widget>? persistentFooterButtons;
  final Widget? drawer;
  final Widget? endDrawer;
  final Color? drawerScrimColor;
  final Color? backgroundColor;
  final bool? resizeToAvoidBottomInset;
  final bool primary;
  final DragStartBehavior drawerDragStartBehavior;
  final bool extendBody;
  final bool extendBodyBehindAppBar;
  final double? drawerEdgeDragWidth;
  final bool drawerEnableOpenDragGesture;
  final bool endDrawerEnableOpenDragGesture;

  const AdaptiveScaffold({
    super.key,
    required this.body,
    this.appBar,
    this.floatingActionButton,
    this.floatingActionButtonLocation,
    this.floatingActionButtonAnimator,
    this.persistentFooterButtons,
    this.drawer,
    this.endDrawer,
    this.drawerScrimColor,
    this.backgroundColor,
    this.resizeToAvoidBottomInset,
    this.primary = true,
    this.drawerDragStartBehavior = DragStartBehavior.start,
    this.extendBody = false,
    this.extendBodyBehindAppBar = false,
    this.drawerEdgeDragWidth,
    this.drawerEnableOpenDragGesture = true,
    this.endDrawerEnableOpenDragGesture = true,
  });

  @override
  Widget build(BuildContext context) {
    final screenType = ResponsiveUtils.getScreenSizeType(context);
    final safeArea = ResponsiveUtils.getSafeAreaPadding(context);

    // 根据屏幕类型决定导航方式
    final bool useSideNav =
        screenType != ScreenSizeType.compact &&
        PlatformUtils.shouldUseSideNavigation(context);

    if (useSideNav) {
      // Desktop/Tablet: Use side navigation
      return Scaffold(
        appBar: appBar,
        body: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const AppNavigationBar(),
            Expanded(child: _buildResponsiveBody(context, body)),
          ],
        ),
        floatingActionButton: floatingActionButton,
        floatingActionButtonLocation:
            floatingActionButtonLocation ?? PlatformUtils.getFabLocation(),
        floatingActionButtonAnimator: floatingActionButtonAnimator,
        persistentFooterButtons: persistentFooterButtons,
        drawer: drawer,
        endDrawer: endDrawer,
        drawerScrimColor: drawerScrimColor,
        backgroundColor: backgroundColor,
        resizeToAvoidBottomInset: resizeToAvoidBottomInset,
        primary: primary,
        drawerDragStartBehavior: drawerDragStartBehavior,
        extendBody: extendBody,
        extendBodyBehindAppBar: extendBodyBehindAppBar,
        drawerEdgeDragWidth: drawerEdgeDragWidth,
        drawerEnableOpenDragGesture: drawerEnableOpenDragGesture,
        endDrawerEnableOpenDragGesture: endDrawerEnableOpenDragGesture,
      );
    } else {
      // Mobile: Use bottom navigation with safe area handling
      return Scaffold(
        appBar: appBar,
        body: _buildResponsiveBody(context, body),
        floatingActionButton: floatingActionButton,
        floatingActionButtonLocation:
            floatingActionButtonLocation ?? PlatformUtils.getFabLocation(),
        floatingActionButtonAnimator: floatingActionButtonAnimator,
        persistentFooterButtons: persistentFooterButtons,
        drawer: drawer,
        endDrawer: endDrawer,
        drawerScrimColor: drawerScrimColor,
        backgroundColor: backgroundColor,
        resizeToAvoidBottomInset: resizeToAvoidBottomInset ?? true,
        primary: primary,
        drawerDragStartBehavior: drawerDragStartBehavior,
        extendBody: extendBody,
        extendBodyBehindAppBar: extendBodyBehindAppBar,
        drawerEdgeDragWidth: drawerEdgeDragWidth,
        drawerEnableOpenDragGesture: drawerEnableOpenDragGesture,
        endDrawerEnableOpenDragGesture: endDrawerEnableOpenDragGesture,
        bottomNavigationBar: _buildBottomNav(context, safeArea),
      );
    }
  }

  /// 构建响应式 body，处理安全区域
  Widget _buildResponsiveBody(BuildContext context, Widget child) {
    final viewPadding = ResponsiveUtils.getViewPadding(context);

    // 对于有刘海/挖孔屏的设备，确保内容不被遮挡
    return MediaQuery(
      data: MediaQuery.of(context).copyWith(
        // 保持原有的 padding，让子组件自行处理
        padding: viewPadding,
      ),
      child: child,
    );
  }

  /// 构建底部导航栏，处理安全区域
  Widget _buildBottomNav(BuildContext context, EdgeInsets safeArea) {
    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerLow,
        // 添加顶部分隔线
        border: Border(
          top: BorderSide(
            color: Theme.of(
              context,
            ).colorScheme.outlineVariant.withValues(alpha: 0.3),
            width: 0.5,
          ),
        ),
      ),
      child: SafeArea(top: false, child: const AppNavigationBar()),
    );
  }
}
