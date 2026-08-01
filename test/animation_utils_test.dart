import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:veloguard/src/utils/animation_utils.dart';

void main() {
  test('state change curve never overshoots decoration tween bounds', () {
    const selected = BoxDecoration(
      boxShadow: [
        BoxShadow(
          color: Color(0x33000000),
          blurRadius: 12,
          offset: Offset(0, 4),
        ),
      ],
    );
    const unselected = BoxDecoration();

    for (var frame = 0; frame <= 240; frame++) {
      final progress = frame / 240;
      final curvedProgress = AnimationUtils.stateChangeCurve.transform(
        progress,
      );

      expect(curvedProgress, inInclusiveRange(0.0, 1.0));
      final decoration = BoxDecoration.lerp(
        selected,
        unselected,
        curvedProgress,
      );
      for (final shadow in decoration?.boxShadow ?? const <BoxShadow>[]) {
        expect(shadow.blurRadius, greaterThanOrEqualTo(0.0));
      }
    }
  });
}
