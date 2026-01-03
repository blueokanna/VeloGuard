import 'dart:io';
import 'dart:math' as math;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Material Design 3 Expressive 鍔ㄧ敾宸ュ叿绫?
/// 瀹炵幇鍩轰簬鐗╃悊鐨勯潪绾挎€у姩鐢绘晥鏋滐紝寮鸿皟鎺掔増鎵╁睍銆佸舰鐘跺彉鍖栧拰椴滆壋閰嶈壊
///
/// 鍙傝€? https://m3.material.io/styles/motion/overview
/// Expressive 璁捐寮鸿皟:
/// - Motion-physics: 鍩轰簬鐗╃悊鐨勫脊鎬у姩鐢?
/// - 鎺掔増鎵╁睍: 鏂囧瓧澶у皬鍜屾潈閲嶇殑鍔ㄦ€佸彉鍖?
/// - 褰㈢姸搴? 鍦嗚鍜屽舰鐘剁殑鍔ㄦ€佸彉鎹?
/// - 椴滆壋閰嶈壊: 棰滆壊杩囨浮鍜屽己璋冩晥鏋?
class AnimationUtils {
  AnimationUtils._();

  /// 鑾峰彇璁惧鍒锋柊鐜?
  static double getDeviceRefreshRate() {
    final window = WidgetsBinding.instance.platformDispatcher.views.first;
    return window.display.refreshRate;
  }

  /// 鑾峰彇鏈€浣冲姩鐢绘椂闀匡紙鍩轰簬鍒锋柊鐜囷級
  static Duration getOptimalDuration({
    Duration baseDuration = const Duration(milliseconds: 300),
  }) {
    final refreshRate = getDeviceRefreshRate();

    // 楂樺埛鏂扮巼璁惧鍙互浣跨敤鏇寸煭鐨勫姩鐢绘椂闀?
    if (refreshRate >= 120) {
      return Duration(
        milliseconds: (baseDuration.inMilliseconds * 0.75).round(),
      );
    } else if (refreshRate >= 90) {
      return Duration(
        milliseconds: (baseDuration.inMilliseconds * 0.85).round(),
      );
    }
    return baseDuration;
  }

  // ============================================
  // Material Design 3 Expressive 鍔ㄧ敾鏃堕暱
  // 鍩轰簬 Google 鏈€鏂?Expressive 瑙勮寖
  // ============================================

  // 鐭椂闀?- 鐢ㄤ簬寰氦浜?
  static const Duration durationShort1 = Duration(milliseconds: 50);
  static const Duration durationShort2 = Duration(milliseconds: 100);
  static const Duration durationShort3 = Duration(milliseconds: 150);
  static const Duration durationShort4 = Duration(milliseconds: 200);

  // 涓瓑鏃堕暱 - 鐢ㄤ簬涓€鑸繃娓?
  static const Duration durationMedium1 = Duration(milliseconds: 250);
  static const Duration durationMedium2 = Duration(milliseconds: 300);
  static const Duration durationMedium3 = Duration(milliseconds: 350);
  static const Duration durationMedium4 = Duration(milliseconds: 400);

  // 闀挎椂闀?- 鐢ㄤ簬澶嶆潅鍔ㄧ敾
  static const Duration durationLong1 = Duration(milliseconds: 450);
  static const Duration durationLong2 = Duration(milliseconds: 500);
  static const Duration durationLong3 = Duration(milliseconds: 550);
  static const Duration durationLong4 = Duration(milliseconds: 600);

  // 瓒呴暱鏃堕暱 - 鐢ㄤ簬鎴忓墽鎬ф晥鏋?
  static const Duration durationExtraLong1 = Duration(milliseconds: 700);
  static const Duration durationExtraLong2 = Duration(milliseconds: 800);
  static const Duration durationExtraLong3 = Duration(milliseconds: 900);
  static const Duration durationExtraLong4 = Duration(milliseconds: 1000);

  // ============================================
  // Material Design 3 Expressive 鐗╃悊鏇茬嚎
  // Motion-physics 绯荤粺鏍稿績
  // ============================================

  /// 寮鸿皟鏇茬嚎 - 鐢ㄤ簬閲嶈鐨勭姸鎬佸彉鍖栵紝甯︽湁杞诲井杩囧啿
  static const Curve curveEmphasized = Curves.easeInOutCubicEmphasized;

  /// 寮鸿皟鍔犻€熸洸绾?- 鐢ㄤ簬閫€鍑哄姩鐢?
  static const Curve curveEmphasizedAccelerate = Cubic(0.3, 0.0, 0.8, 0.15);

  /// 寮鸿皟鍑忛€熸洸绾?- 鐢ㄤ簬杩涘叆鍔ㄧ敾
  static const Curve curveEmphasizedDecelerate = Cubic(0.05, 0.7, 0.1, 1.0);

  /// 鏍囧噯鏇茬嚎 - 鐢ㄤ簬涓€鑸姩鐢?
  static const Curve curveStandard = Cubic(0.2, 0.0, 0.0, 1.0);

  /// 鏍囧噯鍔犻€熸洸绾?
  static const Curve curveStandardAccelerate = Cubic(0.3, 0.0, 1.0, 1.0);

  /// 鏍囧噯鍑忛€熸洸绾?
  static const Curve curveStandardDecelerate = Cubic(0.0, 0.0, 0.0, 1.0);

  // ============================================
  // Expressive 鐗╃悊寮规€ф洸绾?
  // 鍩轰簬鐪熷疄鐗╃悊妯℃嫙鐨勫脊绨х郴缁?
  // ============================================

  /// 寮规€ф洸绾?- 鐢ㄤ簬鏈夎叮鐨勪氦浜掞紝妯℃嫙鐪熷疄寮圭哀
  static const Curve curveSpring = _SpringCurve(damping: 0.7, stiffness: 200);

  /// 杞诲脊鎬ф洸绾?- 杈冨皯鎸崱
  static const Curve curveSpringLight = _SpringCurve(
    damping: 0.8,
    stiffness: 300,
  );

  /// 寮哄脊鎬ф洸绾?- 鏇村鎸崱锛屾洿鏈夋椿鍔?
  static const Curve curveSpringBouncy = _SpringCurve(
    damping: 0.5,
    stiffness: 150,
  );

  /// 瓒呭脊鎬ф洸绾?- 鐢ㄤ簬寮鸿皟鏁堟灉
  static const Curve curveSpringExpressive = _SpringCurve(
    damping: 0.4,
    stiffness: 120,
  );

  /// 杩囧啿鏇茬嚎 - 鐢ㄤ簬寮鸿皟鏁堟灉
  static const Curve curveOvershoot = _OvershootCurve(tension: 1.5);

  /// 杞昏繃鍐叉洸绾?
  static const Curve curveOvershootLight = _OvershootCurve(tension: 1.0);

  /// 寮鸿繃鍐叉洸绾?
  static const Curve curveOvershootStrong = _OvershootCurve(tension: 2.0);

  /// 棰勬湡鏇茬嚎 - 鍏堝悗閫€鍐嶅墠杩?
  static const Curve curveAnticipate = _AnticipateCurve(tension: 2.0);

  /// 棰勬湡杩囧啿鏇茬嚎 - 鍏堝悗閫€鍐嶅墠杩涘苟杩囧啿
  static const Curve curveAnticipateOvershoot = _AnticipateOvershootCurve(
    tension: 1.5,
  );

  /// 寮硅烦鏇茬嚎 - 妯℃嫙鐗╀綋钀藉湴寮硅烦
  static const Curve curveBounce = _BounceCurve();

  /// 寮规€у脊璺虫洸绾?- 鏇存湁寮规€х殑寮硅烦
  static const Curve curveElasticBounce = _ElasticCurve(period: 0.4);

  // ============================================
  // Expressive 鍔ㄧ敾棰勮
  // 閽堝涓嶅悓 UI 鍏冪礌鐨勪紭鍖栭厤缃?
  // ============================================

  /// 鎸夐挳鎸変笅鍔ㄧ敾
  static const buttonPressDuration = Duration(milliseconds: 80);
  static const buttonReleaseDuration = Duration(milliseconds: 200);
  static const buttonPressCurve = curveStandardAccelerate;
  static const buttonReleaseCurve = curveSpringLight;

  /// 鍗＄墖灞曞紑鍔ㄧ敾
  static const cardExpandDuration = Duration(milliseconds: 350);
  static const cardExpandCurve = curveEmphasizedDecelerate;
  static const cardCollapseDuration = Duration(milliseconds: 300);
  static const cardCollapseCurve = curveEmphasizedAccelerate;

  /// 椤甸潰杞満鍔ㄧ敾
  static const pageTransitionDuration = Duration(milliseconds: 400);
  static const pageTransitionCurve = curveEmphasized;

  /// 鍒楄〃椤瑰叆鍦哄姩鐢?
  static const listItemDuration = Duration(milliseconds: 300);
  static const listItemCurve = curveEmphasizedDecelerate;
  static const listItemStaggerDelay = Duration(milliseconds: 50);

  /// 鐘舵€佸垏鎹㈠姩鐢?
  static const stateChangeDuration = Duration(milliseconds: 250);
  static const stateChangeCurve = curveSpring;

  /// 鍥炬爣鍙樻崲鍔ㄧ敾
  static const iconMorphDuration = Duration(milliseconds: 200);
  static const iconMorphCurve = curveEmphasized;

  /// FAB 鍔ㄧ敾
  static const fabExpandDuration = Duration(milliseconds: 300);
  static const fabExpandCurve = curveSpringBouncy;

  /// 瀵硅瘽妗嗗姩鐢?
  static const dialogEnterDuration = Duration(milliseconds: 350);
  static const dialogExitDuration = Duration(milliseconds: 250);
  static const dialogEnterCurve = curveEmphasizedDecelerate;
  static const dialogExitCurve = curveEmphasizedAccelerate;

  /// 搴曢儴寮圭獥鍔ㄧ敾
  static const bottomSheetDuration = Duration(milliseconds: 400);
  static const bottomSheetCurve = curveEmphasized;

  /// 瀵艰埅鏍忓姩鐢?
  static const navBarDuration = Duration(milliseconds: 300);
  static const navBarCurve = curveSpring;

  /// 寮€鍏冲姩鐢?
  static const switchDuration = Duration(milliseconds: 200);
  static const switchCurve = curveSpringLight;

  /// 婊戝潡鍔ㄧ敾
  static const sliderDuration = Duration(milliseconds: 150);
  static const sliderCurve = curveStandard;

  // ============================================
  // 瑙﹁鍙嶉
  // ============================================

  /// 杞昏Е鍙嶉
  static void lightHaptic() {
    if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      HapticFeedback.lightImpact();
    }
  }

  /// 閫夋嫨鍙嶉
  static void selectionHaptic() {
    if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      HapticFeedback.selectionClick();
    }
  }

  /// 涓瓑鍙嶉
  static void mediumHaptic() {
    if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      HapticFeedback.mediumImpact();
    }
  }

  /// 閲嶅弽棣?
  static void heavyHaptic() {
    if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      HapticFeedback.heavyImpact();
    }
  }

  /// 鎸姩鍙嶉
  static void vibrateHaptic() {
    if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      HapticFeedback.vibrate();
    }
  }

  // ============================================
  // Expressive 褰㈢姸鍙樻崲宸ュ叿
  // 鏀寔鍔ㄦ€佸渾瑙掑拰褰㈢姸鍙樺寲
  // ============================================

  /// 鑾峰彇 Expressive 鍦嗚鍗婂緞
  /// 鏍规嵁鐘舵€佸姩鎬佽皟鏁村渾瑙掑ぇ灏?
  static double getExpressiveBorderRadius({
    required double baseRadius,
    bool isPressed = false,
    bool isHovered = false,
    bool isExpanded = false,
  }) {
    if (isExpanded) return baseRadius * 1.5;
    if (isPressed) return baseRadius * 0.8;
    if (isHovered) return baseRadius * 1.1;
    return baseRadius;
  }

  /// 鑾峰彇 Expressive 缂╂斁鍊?
  static double getExpressiveScale({
    bool isPressed = false,
    bool isHovered = false,
    bool isActive = false,
  }) {
    if (isPressed) return 0.95;
    if (isActive) return 1.02;
    if (isHovered) return 1.01;
    return 1.0;
  }

  /// 鑾峰彇 Expressive 闃村奖
  static List<BoxShadow> getExpressiveShadow({
    required Color color,
    bool isElevated = false,
    bool isPressed = false,
  }) {
    if (isPressed) {
      return [
        BoxShadow(
          color: color.withValues(alpha: 0.1),
          blurRadius: 4,
          offset: const Offset(0, 2),
        ),
      ];
    }
    if (isElevated) {
      return [
        BoxShadow(
          color: color.withValues(alpha: 0.15),
          blurRadius: 20,
          offset: const Offset(0, 8),
        ),
        BoxShadow(
          color: color.withValues(alpha: 0.1),
          blurRadius: 8,
          offset: const Offset(0, 4),
        ),
      ];
    }
    return [
      BoxShadow(
        color: color.withValues(alpha: 0.1),
        blurRadius: 12,
        offset: const Offset(0, 4),
      ),
    ];
  }
}

// ============================================
// 鑷畾涔夌墿鐞嗘洸绾垮疄鐜?
// 鍩轰簬鐪熷疄鐗╃悊妯℃嫙
// ============================================

/// 寮圭哀鏇茬嚎 - 鍩轰簬闃诲凹鎸崱鐗╃悊妯″瀷
class _SpringCurve extends Curve {
  final double damping;
  final double stiffness;

  const _SpringCurve({this.damping = 0.7, this.stiffness = 200});

  @override
  double transformInternal(double t) {
    final omega = math.sqrt(stiffness);
    final dampingRatio = damping;

    if (dampingRatio < 1) {
      // 娆犻樆灏?- 鏈夋尟鑽?
      final omegaD = omega * math.sqrt(1 - dampingRatio * dampingRatio);
      return 1 -
          math.exp(-dampingRatio * omega * t) *
              (math.cos(omegaD * t) +
                  (dampingRatio * omega / omegaD) * math.sin(omegaD * t));
    } else {
      // 涓寸晫闃诲凹鎴栬繃闃诲凹
      return 1 - (1 + omega * t) * math.exp(-omega * t);
    }
  }
}

/// 杩囧啿鏇茬嚎 - 瓒呰繃鐩爣鍊煎悗鍥炲脊
class _OvershootCurve extends Curve {
  final double tension;

  const _OvershootCurve({this.tension = 1.5});

  @override
  double transformInternal(double t) {
    final s = tension;
    return (t - 1) * (t - 1) * ((s + 1) * (t - 1) + s) + 1;
  }
}

/// 棰勬湡鏇茬嚎 - 鍏堝悗閫€鍐嶅墠杩?
class _AnticipateCurve extends Curve {
  final double tension;

  const _AnticipateCurve({this.tension = 2.0});

  @override
  double transformInternal(double t) {
    final s = tension;
    return t * t * ((s + 1) * t - s);
  }
}

/// 棰勬湡杩囧啿鏇茬嚎 - 鍏堝悗閫€鍐嶅墠杩涘苟杩囧啿
class _AnticipateOvershootCurve extends Curve {
  final double tension;

  const _AnticipateOvershootCurve({this.tension = 1.5});

  @override
  double transformInternal(double t) {
    final s = tension * 1.5;
    if (t < 0.5) {
      return 0.5 * (2 * t) * (2 * t) * ((s + 1) * 2 * t - s);
    } else {
      final t2 = 2 * t - 2;
      return 0.5 * (t2 * t2 * ((s + 1) * t2 + s) + 2);
    }
  }
}

/// 寮硅烦鏇茬嚎 - 妯℃嫙鐗╀綋钀藉湴寮硅烦
class _BounceCurve extends Curve {
  const _BounceCurve();

  @override
  double transformInternal(double t) {
    if (t < 1 / 2.75) {
      return 7.5625 * t * t;
    } else if (t < 2 / 2.75) {
      final t2 = t - 1.5 / 2.75;
      return 7.5625 * t2 * t2 + 0.75;
    } else if (t < 2.5 / 2.75) {
      final t2 = t - 2.25 / 2.75;
      return 7.5625 * t2 * t2 + 0.9375;
    } else {
      final t2 = t - 2.625 / 2.75;
      return 7.5625 * t2 * t2 + 0.984375;
    }
  }
}

/// 寮规€ф洸绾?- 绫讳技姗＄毊绛嬬殑寮规€ф晥鏋?
class _ElasticCurve extends Curve {
  final double period;

  const _ElasticCurve({this.period = 0.4});

  @override
  double transformInternal(double t) {
    final p = period;
    final s = p / 4;
    return math.pow(2, -10 * t) * math.sin((t - s) * (2 * math.pi) / p) + 1;
  }
}

// ============================================
// 楂樻€ц兘 Expressive 鍔ㄧ敾 Widgets
// ============================================

/// Expressive 娣″叆婊戝姩鍔ㄧ敾
class ExpressiveFadeSlide extends StatefulWidget {
  final Widget child;
  final Duration duration;
  final Duration delay;
  final Offset beginOffset;
  final Curve curve;
  final bool animate;

  const ExpressiveFadeSlide({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 300),
    this.delay = Duration.zero,
    this.beginOffset = const Offset(0, 0.05),
    this.curve = const Cubic(0.05, 0.7, 0.1, 1.0),
    this.animate = true,
  });

  @override
  State<ExpressiveFadeSlide> createState() => _ExpressiveFadeSlideState();
}

class _ExpressiveFadeSlideState extends State<ExpressiveFadeSlide>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _fadeAnimation;
  late Animation<Offset> _slideAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: widget.duration);

    _fadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _controller, curve: widget.curve));

    _slideAnimation = Tween<Offset>(
      begin: widget.beginOffset,
      end: Offset.zero,
    ).animate(CurvedAnimation(parent: _controller, curve: widget.curve));

    if (widget.animate) {
      if (widget.delay > Duration.zero) {
        Future.delayed(widget.delay, () {
          if (mounted) _controller.forward();
        });
      } else {
        _controller.forward();
      }
    }
  }

  @override
  void didUpdateWidget(ExpressiveFadeSlide oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.animate && !oldWidget.animate) {
      _controller.forward();
    } else if (!widget.animate && oldWidget.animate) {
      _controller.reverse();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return FadeTransition(
      opacity: _fadeAnimation,
      child: SlideTransition(position: _slideAnimation, child: widget.child),
    );
  }
}

/// Expressive 缂╂斁鍔ㄧ敾
class ExpressiveScale extends StatefulWidget {
  final Widget child;
  final Duration duration;
  final Duration delay;
  final double beginScale;
  final Curve curve;
  final bool animate;

  const ExpressiveScale({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 250),
    this.delay = Duration.zero,
    this.beginScale = 0.8,
    this.curve = const _SpringCurve(damping: 0.7, stiffness: 200),
    this.animate = true,
  });

  @override
  State<ExpressiveScale> createState() => _ExpressiveScaleState();
}

class _ExpressiveScaleState extends State<ExpressiveScale>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _scaleAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: widget.duration);

    _scaleAnimation = Tween<double>(
      begin: widget.beginScale,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _controller, curve: widget.curve));

    if (widget.animate) {
      if (widget.delay > Duration.zero) {
        Future.delayed(widget.delay, () {
          if (mounted) _controller.forward();
        });
      } else {
        _controller.forward();
      }
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ScaleTransition(scale: _scaleAnimation, child: widget.child);
  }
}

/// Expressive 鎸夐挳鏁堟灉 - 甯︾墿鐞嗗弽棣?
class ExpressiveButton extends StatefulWidget {
  final Widget child;
  final VoidCallback? onPressed;
  final VoidCallback? onLongPress;
  final double pressedScale;
  final bool enableHaptic;
  final Duration pressDuration;
  final Duration releaseDuration;

  const ExpressiveButton({
    super.key,
    required this.child,
    this.onPressed,
    this.onLongPress,
    this.pressedScale = 0.95,
    this.enableHaptic = true,
    this.pressDuration = const Duration(milliseconds: 80),
    this.releaseDuration = const Duration(milliseconds: 200),
  });

  @override
  State<ExpressiveButton> createState() => _ExpressiveButtonState();
}

class _ExpressiveButtonState extends State<ExpressiveButton>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _scaleAnimation;
  bool _isPressed = false;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: widget.pressDuration,
      reverseDuration: widget.releaseDuration,
    );

    _scaleAnimation = Tween<double>(begin: 1.0, end: widget.pressedScale)
        .animate(
          CurvedAnimation(
            parent: _controller,
            curve: AnimationUtils.buttonPressCurve,
            reverseCurve: AnimationUtils.buttonReleaseCurve,
          ),
        );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _handleTapDown(TapDownDetails details) {
    if (widget.onPressed != null) {
      setState(() => _isPressed = true);
      _controller.forward();
      if (widget.enableHaptic) {
        AnimationUtils.lightHaptic();
      }
    }
  }

  void _handleTapUp(TapUpDetails details) {
    if (_isPressed) {
      setState(() => _isPressed = false);
      _controller.reverse();
    }
  }

  void _handleTapCancel() {
    if (_isPressed) {
      setState(() => _isPressed = false);
      _controller.reverse();
    }
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTapDown: _handleTapDown,
      onTapUp: _handleTapUp,
      onTapCancel: _handleTapCancel,
      onTap: widget.onPressed,
      onLongPress: widget.onLongPress,
      child: ScaleTransition(scale: _scaleAnimation, child: widget.child),
    );
  }
}

/// 鍒楄〃椤逛氦閿欏叆鍦哄姩鐢?
class StaggeredListItem extends StatefulWidget {
  final Widget child;
  final int index;
  final Duration delay;
  final Duration duration;
  final Curve curve;
  final Offset slideOffset;

  const StaggeredListItem({
    super.key,
    required this.child,
    required this.index,
    this.delay = const Duration(milliseconds: 50),
    this.duration = const Duration(milliseconds: 300),
    this.curve = const Cubic(0.05, 0.7, 0.1, 1.0),
    this.slideOffset = const Offset(0, 0.1),
  });

  @override
  State<StaggeredListItem> createState() => _StaggeredListItemState();
}

class _StaggeredListItemState extends State<StaggeredListItem>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _fadeAnimation;
  late Animation<Offset> _slideAnimation;
  late Animation<double> _scaleAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: widget.duration);

    _fadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _controller, curve: widget.curve));

    _slideAnimation = Tween<Offset>(
      begin: widget.slideOffset,
      end: Offset.zero,
    ).animate(CurvedAnimation(parent: _controller, curve: widget.curve));

    _scaleAnimation = Tween<double>(
      begin: 0.95,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _controller, curve: widget.curve));

    // 寤惰繜鍚姩鍔ㄧ敾
    Future.delayed(widget.delay * widget.index, () {
      if (mounted) {
        _controller.forward();
      }
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return FadeTransition(
      opacity: _fadeAnimation,
      child: SlideTransition(
        position: _slideAnimation,
        child: ScaleTransition(scale: _scaleAnimation, child: widget.child),
      ),
    );
  }
}

/// 鑴夊啿鍔ㄧ敾 - 鐢ㄤ簬鐘舵€佹寚绀?
class PulseAnimation extends StatefulWidget {
  final Widget child;
  final bool isActive;
  final double minScale;
  final double maxScale;
  final Duration duration;

  const PulseAnimation({
    super.key,
    required this.child,
    this.isActive = true,
    this.minScale = 1.0,
    this.maxScale = 1.05,
    this.duration = const Duration(milliseconds: 1200),
  });

  @override
  State<PulseAnimation> createState() => _PulseAnimationState();
}

class _PulseAnimationState extends State<PulseAnimation>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _animation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: widget.duration);
    _animation = Tween<double>(
      begin: widget.minScale,
      end: widget.maxScale,
    ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeInOut));

    if (widget.isActive) {
      _controller.repeat(reverse: true);
    }
  }

  @override
  void didUpdateWidget(PulseAnimation oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.isActive && !oldWidget.isActive) {
      _controller.repeat(reverse: true);
    } else if (!widget.isActive && oldWidget.isActive) {
      _controller.stop();
      _controller.reset();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.isActive) {
      return widget.child;
    }

    return AnimatedBuilder(
      animation: _animation,
      builder: (context, child) {
        return Transform.scale(scale: _animation.value, child: child);
      },
      child: widget.child,
    );
  }
}

/// 鍛煎惛鐏姩鐢?- 鐢ㄤ簬鐘舵€佹寚绀?
class BreathingAnimation extends StatefulWidget {
  final Widget child;
  final bool isActive;
  final double minOpacity;
  final double maxOpacity;
  final Duration duration;

  const BreathingAnimation({
    super.key,
    required this.child,
    this.isActive = true,
    this.minOpacity = 0.4,
    this.maxOpacity = 1.0,
    this.duration = const Duration(milliseconds: 1500),
  });

  @override
  State<BreathingAnimation> createState() => _BreathingAnimationState();
}

class _BreathingAnimationState extends State<BreathingAnimation>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _animation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: widget.duration);
    _animation = Tween<double>(
      begin: widget.minOpacity,
      end: widget.maxOpacity,
    ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeInOut));

    if (widget.isActive) {
      _controller.repeat(reverse: true);
    }
  }

  @override
  void didUpdateWidget(BreathingAnimation oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.isActive && !oldWidget.isActive) {
      _controller.repeat(reverse: true);
    } else if (!widget.isActive && oldWidget.isActive) {
      _controller.stop();
      _controller.value = 1.0;
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.isActive) {
      return widget.child;
    }

    return FadeTransition(opacity: _animation, child: widget.child);
  }
}

/// 娑熸吉鎵╂暎鍔ㄧ敾 - 鐢ㄤ簬鐘舵€佸彉鍖栨寚绀?
class RippleAnimation extends StatefulWidget {
  final Widget child;
  final bool isActive;
  final Color rippleColor;
  final Duration duration;
  final int rippleCount;

  const RippleAnimation({
    super.key,
    required this.child,
    this.isActive = true,
    this.rippleColor = Colors.white,
    this.duration = const Duration(milliseconds: 1500),
    this.rippleCount = 1,
  });

  @override
  State<RippleAnimation> createState() => _RippleAnimationState();
}

class _RippleAnimationState extends State<RippleAnimation>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _scaleAnimation;
  late Animation<double> _opacityAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: widget.duration);

    _scaleAnimation = Tween<double>(
      begin: 0.8,
      end: 1.5,
    ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeOut));

    _opacityAnimation = Tween<double>(
      begin: 0.6,
      end: 0.0,
    ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeOut));

    if (widget.isActive) {
      _controller.repeat();
    }
  }

  @override
  void didUpdateWidget(RippleAnimation oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.isActive && !oldWidget.isActive) {
      _controller.repeat();
    } else if (!widget.isActive && oldWidget.isActive) {
      _controller.stop();
      _controller.reset();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      alignment: Alignment.center,
      children: [
        if (widget.isActive)
          AnimatedBuilder(
            animation: _controller,
            builder: (context, child) {
              return Transform.scale(
                scale: _scaleAnimation.value,
                child: Opacity(
                  opacity: _opacityAnimation.value,
                  child: Container(
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(color: widget.rippleColor, width: 2),
                    ),
                  ),
                ),
              );
            },
          ),
        widget.child,
      ],
    );
  }
}

/// 鏁板€煎姩鐢绘樉绀?- 鐢ㄤ簬缁熻鏁版嵁
class AnimatedNumber extends StatelessWidget {
  final double value;
  final String Function(double) formatter;
  final TextStyle? style;
  final Duration duration;
  final Curve curve;

  const AnimatedNumber({
    super.key,
    required this.value,
    required this.formatter,
    this.style,
    this.duration = const Duration(milliseconds: 300),
    this.curve = Curves.easeOutCubic,
  });

  @override
  Widget build(BuildContext context) {
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: value),
      duration: duration,
      curve: curve,
      builder: (context, animatedValue, child) {
        return Text(formatter(animatedValue), style: style);
      },
    );
  }
}

/// 娓愬彉鑳屾櫙鍔ㄧ敾
class AnimatedGradientBackground extends StatefulWidget {
  final List<Color> colors;
  final Duration duration;
  final Widget child;
  final BorderRadius? borderRadius;
  final AlignmentGeometry begin;
  final AlignmentGeometry end;

  const AnimatedGradientBackground({
    super.key,
    required this.colors,
    this.duration = const Duration(milliseconds: 500),
    required this.child,
    this.borderRadius,
    this.begin = Alignment.topLeft,
    this.end = Alignment.bottomRight,
  });

  @override
  State<AnimatedGradientBackground> createState() =>
      _AnimatedGradientBackgroundState();
}

class _AnimatedGradientBackgroundState
    extends State<AnimatedGradientBackground> {
  @override
  Widget build(BuildContext context) {
    return AnimatedContainer(
      duration: widget.duration,
      curve: AnimationUtils.curveEmphasized,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: widget.begin,
          end: widget.end,
          colors: widget.colors,
        ),
        borderRadius: widget.borderRadius,
      ),
      child: widget.child,
    );
  }
}

/// 鍥炬爣鍙樻崲鍔ㄧ敾 - 骞虫粦鐨勫浘鏍囧垏鎹?
class AnimatedIconMorph extends StatelessWidget {
  final IconData icon;
  final Color? color;
  final double? size;
  final Duration duration;

  const AnimatedIconMorph({
    super.key,
    required this.icon,
    this.color,
    this.size,
    this.duration = const Duration(milliseconds: 200),
  });

  @override
  Widget build(BuildContext context) {
    return AnimatedSwitcher(
      duration: duration,
      switchInCurve: AnimationUtils.curveEmphasizedDecelerate,
      switchOutCurve: AnimationUtils.curveEmphasizedAccelerate,
      transitionBuilder: (child, animation) {
        return ScaleTransition(
          scale: animation,
          child: FadeTransition(opacity: animation, child: child),
        );
      },
      child: Icon(icon, key: ValueKey(icon), color: color, size: size),
    );
  }
}

/// Expressive 褰㈢姸鍙樻崲瀹瑰櫒
class ExpressiveShapeContainer extends StatelessWidget {
  final Widget child;
  final bool isExpanded;
  final bool isPressed;
  final double baseRadius;
  final Color backgroundColor;
  final Color? borderColor;
  final Duration duration;
  final List<BoxShadow>? shadows;

  const ExpressiveShapeContainer({
    super.key,
    required this.child,
    this.isExpanded = false,
    this.isPressed = false,
    this.baseRadius = 16,
    required this.backgroundColor,
    this.borderColor,
    this.duration = const Duration(milliseconds: 250),
    this.shadows,
  });

  @override
  Widget build(BuildContext context) {
    final radius = AnimationUtils.getExpressiveBorderRadius(
      baseRadius: baseRadius,
      isPressed: isPressed,
      isExpanded: isExpanded,
    );

    return AnimatedContainer(
      duration: duration,
      curve: AnimationUtils.curveSpring,
      decoration: BoxDecoration(
        color: backgroundColor,
        borderRadius: BorderRadius.circular(radius),
        border: borderColor != null
            ? Border.all(color: borderColor!, width: isExpanded ? 2 : 1)
            : null,
        boxShadow: shadows,
      ),
      child: child,
    );
  }
}

/// Expressive 鎺掔増鍔ㄧ敾 - 鏂囧瓧澶у皬鍜屾潈閲嶇殑鍔ㄦ€佸彉鍖?
class ExpressiveText extends StatelessWidget {
  final String text;
  final TextStyle baseStyle;
  final bool isEmphasized;
  final Duration duration;

  const ExpressiveText({
    super.key,
    required this.text,
    required this.baseStyle,
    this.isEmphasized = false,
    this.duration = const Duration(milliseconds: 200),
  });

  @override
  Widget build(BuildContext context) {
    return AnimatedDefaultTextStyle(
      duration: duration,
      curve: AnimationUtils.curveEmphasized,
      style: isEmphasized
          ? baseStyle.copyWith(
              fontSize: (baseStyle.fontSize ?? 14) * 1.1,
              fontWeight: FontWeight.w600,
            )
          : baseStyle,
      child: Text(text),
    );
  }
}

/// 椤甸潰杞満鍔ㄧ敾鏋勫缓鍣?
class ExpressivePageTransition extends StatelessWidget {
  final Animation<double> animation;
  final Widget child;
  final bool isEntering;

  const ExpressivePageTransition({
    super.key,
    required this.animation,
    required this.child,
    this.isEntering = true,
  });

  @override
  Widget build(BuildContext context) {
    final curve = isEntering
        ? AnimationUtils.curveEmphasizedDecelerate
        : AnimationUtils.curveEmphasizedAccelerate;

    final fadeAnimation = CurvedAnimation(parent: animation, curve: curve);

    final slideAnimation = Tween<Offset>(
      begin: isEntering ? const Offset(0.05, 0) : const Offset(-0.05, 0),
      end: Offset.zero,
    ).animate(CurvedAnimation(parent: animation, curve: curve));

    final scaleAnimation = Tween<double>(
      begin: isEntering ? 0.95 : 1.05,
      end: 1.0,
    ).animate(CurvedAnimation(parent: animation, curve: curve));

    return FadeTransition(
      opacity: fadeAnimation,
      child: SlideTransition(
        position: slideAnimation,
        child: ScaleTransition(scale: scaleAnimation, child: child),
      ),
    );
  }
}

/// Expressive 棰滆壊杩囨浮鍔ㄧ敾
class ExpressiveColorTransition extends StatelessWidget {
  final Color color;
  final Duration duration;
  final Widget Function(Color) builder;

  const ExpressiveColorTransition({
    super.key,
    required this.color,
    this.duration = const Duration(milliseconds: 300),
    required this.builder,
  });

  @override
  Widget build(BuildContext context) {
    return TweenAnimationBuilder<Color?>(
      tween: ColorTween(end: color),
      duration: duration,
      curve: AnimationUtils.curveEmphasized,
      builder: (context, animatedColor, child) {
        return builder(animatedColor ?? color);
      },
    );
  }
}

/// 寮规€ф粴鍔ㄧ墿鐞嗘晥鏋?
class ExpressiveScrollPhysics extends ScrollPhysics {
  final double springStiffness;
  final double springDamping;

  const ExpressiveScrollPhysics({
    super.parent,
    this.springStiffness = 200,
    this.springDamping = 0.8,
  });

  @override
  ExpressiveScrollPhysics applyTo(ScrollPhysics? ancestor) {
    return ExpressiveScrollPhysics(
      parent: buildParent(ancestor),
      springStiffness: springStiffness,
      springDamping: springDamping,
    );
  }

  @override
  SpringDescription get spring => SpringDescription(
    mass: 1,
    stiffness: springStiffness,
    damping: springDamping * 2 * math.sqrt(springStiffness),
  );
}

/// 鍏变韩鍏冪礌鍔ㄧ敾 Hero 鍖呰鍣?
class ExpressiveHero extends StatelessWidget {
  final String tag;
  final Widget child;
  final bool enabled;

  const ExpressiveHero({
    super.key,
    required this.tag,
    required this.child,
    this.enabled = true,
  });

  @override
  Widget build(BuildContext context) {
    if (!enabled) return child;

    return Hero(
      tag: tag,
      flightShuttleBuilder:
          (
            BuildContext flightContext,
            Animation<double> animation,
            HeroFlightDirection flightDirection,
            BuildContext fromHeroContext,
            BuildContext toHeroContext,
          ) {
            return AnimatedBuilder(
              animation: animation,
              builder: (context, _) {
                return Material(
                  color: Colors.transparent,
                  child: ScaleTransition(
                    scale: Tween<double>(begin: 0.9, end: 1.0).animate(
                      CurvedAnimation(
                        parent: animation,
                        curve: AnimationUtils.curveSpring,
                      ),
                    ),
                    child: child,
                  ),
                );
              },
            );
          },
      child: child,
    );
  }
}
