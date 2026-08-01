import 'package:flutter/material.dart';

abstract final class AppShapes {
  static const BorderRadius extraSmall = BorderRadius.all(Radius.circular(4));
  static const BorderRadius small = BorderRadius.all(Radius.circular(8));
  static const BorderRadius medium = BorderRadius.all(Radius.circular(12));
  static const BorderRadius large = BorderRadius.all(Radius.circular(16));
  static const BorderRadius extraLarge = BorderRadius.all(Radius.circular(28));

  static const RoundedRectangleBorder card = RoundedRectangleBorder(
    borderRadius: small,
  );
  static const RoundedRectangleBorder control = RoundedRectangleBorder(
    borderRadius: medium,
  );
  static const RoundedRectangleBorder floatingAction = RoundedRectangleBorder(
    borderRadius: large,
  );
  static const RoundedRectangleBorder dialog = RoundedRectangleBorder(
    borderRadius: extraLarge,
  );
  static const RoundedRectangleBorder bottomSheet = RoundedRectangleBorder(
    borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
  );
  static const StadiumBorder pill = StadiumBorder();
  static const CircleBorder circle = CircleBorder();
}
