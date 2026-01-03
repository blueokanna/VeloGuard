import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';

/// 璁惧绫诲瀷鏋氫妇
enum DeviceType {
  phone, // 鎵嬫満
  tablet, // 骞虫澘
  desktop, // 妗岄潰
}

/// 灞忓箷灏哄绫诲瀷
enum ScreenSizeType {
  compact, // 绱у噾鍨?(< 600dp)
  medium, // 涓瓑鍨?(600-840dp)
  expanded, // 鎵╁睍鍨?(> 840dp)
}

/// 璁惧淇℃伅绫?- 鍖呭惈鎵€鏈夌洰鏍囪澶囩殑瑙勬牸
class DeviceSpecs {
  final String name;
  final double width;
  final double height;
  final double dpi;
  final double refreshRate;
  final double aspectRatio;

  const DeviceSpecs({
    required this.name,
    required this.width,
    required this.height,
    required this.dpi,
    required this.refreshRate,
    required this.aspectRatio,
  });

  // ============================================
  // 鍗庝负 Mate 绯诲垪 (Mate 9 - Mate 40 Pro)
  // ============================================
  static const huaweiMate9 = DeviceSpecs(
    name: 'HUAWEI Mate 9',
    width: 1080,
    height: 1920,
    dpi: 373,
    refreshRate: 60,
    aspectRatio: 16 / 9,
  );
  static const huaweiMate9Pro = DeviceSpecs(
    name: 'HUAWEI Mate 9 Pro',
    width: 1440,
    height: 2560,
    dpi: 534,
    refreshRate: 60,
    aspectRatio: 16 / 9,
  );
  static const huaweiMate10 = DeviceSpecs(
    name: 'HUAWEI Mate 10',
    width: 1440,
    height: 2560,
    dpi: 498,
    refreshRate: 60,
    aspectRatio: 16 / 9,
  );
  static const huaweiMate10Pro = DeviceSpecs(
    name: 'HUAWEI Mate 10 Pro',
    width: 1080,
    height: 2160,
    dpi: 402,
    refreshRate: 60,
    aspectRatio: 18 / 9,
  );
  static const huaweiMate10Lite = DeviceSpecs(
    name: 'HUAWEI Mate 10 Lite',
    width: 1080,
    height: 2160,
    dpi: 409,
    refreshRate: 60,
    aspectRatio: 18 / 9,
  );
  static const huaweiMate20 = DeviceSpecs(
    name: 'HUAWEI Mate 20',
    width: 1080,
    height: 2244,
    dpi: 381,
    refreshRate: 60,
    aspectRatio: 18.7 / 9,
  );
  static const huaweiMate20Pro = DeviceSpecs(
    name: 'HUAWEI Mate 20 Pro',
    width: 1440,
    height: 3120,
    dpi: 538,
    refreshRate: 60,
    aspectRatio: 19.5 / 9,
  );
  static const huaweiMate20X = DeviceSpecs(
    name: 'HUAWEI Mate 20 X',
    width: 1080,
    height: 2244,
    dpi: 346,
    refreshRate: 60,
    aspectRatio: 18.7 / 9,
  );
  static const huaweiMate20Lite = DeviceSpecs(
    name: 'HUAWEI Mate 20 Lite',
    width: 1080,
    height: 2340,
    dpi: 409,
    refreshRate: 60,
    aspectRatio: 19.5 / 9,
  );
  static const huaweiMate30 = DeviceSpecs(
    name: 'HUAWEI Mate 30',
    width: 1080,
    height: 2400,
    dpi: 409,
    refreshRate: 60,
    aspectRatio: 20 / 9,
  );
  static const huaweiMate30Pro = DeviceSpecs(
    name: 'HUAWEI Mate 30 Pro',
    width: 1176,
    height: 2400,
    dpi: 409,
    refreshRate: 60,
    aspectRatio: 18.4 / 9,
  );
  static const huaweiMate30Pro5G = DeviceSpecs(
    name: 'HUAWEI Mate 30 Pro 5G',
    width: 1176,
    height: 2400,
    dpi: 409,
    refreshRate: 60,
    aspectRatio: 18.4 / 9,
  );
  static const huaweiMate40 = DeviceSpecs(
    name: 'HUAWEI Mate 40',
    width: 1080,
    height: 2376,
    dpi: 409,
    refreshRate: 90,
    aspectRatio: 19.8 / 9,
  );
  static const huaweiMate40Pro = DeviceSpecs(
    name: 'HUAWEI Mate 40 Pro',
    width: 1200,
    height: 2640,
    dpi: 456,
    refreshRate: 90,
    aspectRatio: 19.8 / 9,
  );
  static const huaweiMate40ProPlus = DeviceSpecs(
    name: 'HUAWEI Mate 40 Pro+',
    width: 1200,
    height: 2640,
    dpi: 456,
    refreshRate: 90,
    aspectRatio: 19.8 / 9,
  );
  static const huaweiNova12Pro = DeviceSpecs(
    name: 'Huawei nova 12 Pro',
    width: 1200,
    height: 2676,
    dpi: 460,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );

  // ============================================
  // 灏忕背绯诲垪 (Xiaomi 10 - Xiaomi 17 Ultra)
  // ============================================
  static const xiaomi10 = DeviceSpecs(
    name: 'Xiaomi Mi 10',
    width: 1080,
    height: 2340,
    dpi: 386,
    refreshRate: 90,
    aspectRatio: 19.5 / 9,
  );
  static const xiaomi10Pro = DeviceSpecs(
    name: 'Xiaomi Mi 10 Pro',
    width: 1080,
    height: 2340,
    dpi: 386,
    refreshRate: 90,
    aspectRatio: 19.5 / 9,
  );
  static const xiaomi10Ultra = DeviceSpecs(
    name: 'Xiaomi Mi 10 Ultra',
    width: 1080,
    height: 2340,
    dpi: 386,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const xiaomi10Lite = DeviceSpecs(
    name: 'Xiaomi Mi 10 Lite',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 60,
    aspectRatio: 20 / 9,
  );
  static const xiaomi11 = DeviceSpecs(
    name: 'Xiaomi Mi 11',
    width: 1440,
    height: 3200,
    dpi: 515,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi11Pro = DeviceSpecs(
    name: 'Xiaomi Mi 11 Pro',
    width: 1440,
    height: 3200,
    dpi: 515,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi11Ultra = DeviceSpecs(
    name: 'Xiaomi Mi 11 Ultra',
    width: 1440,
    height: 3200,
    dpi: 515,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi11Lite = DeviceSpecs(
    name: 'Xiaomi Mi 11 Lite',
    width: 1080,
    height: 2400,
    dpi: 402,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const xiaomi12 = DeviceSpecs(
    name: 'Xiaomi 12',
    width: 1080,
    height: 2400,
    dpi: 419,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi12Pro = DeviceSpecs(
    name: 'Xiaomi 12 Pro',
    width: 1440,
    height: 3200,
    dpi: 522,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi12Ultra = DeviceSpecs(
    name: 'Xiaomi 12S Ultra',
    width: 1440,
    height: 3200,
    dpi: 522,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi12Lite = DeviceSpecs(
    name: 'Xiaomi 12 Lite',
    width: 1080,
    height: 2400,
    dpi: 402,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi13 = DeviceSpecs(
    name: 'Xiaomi 13',
    width: 1080,
    height: 2400,
    dpi: 401,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi13Pro = DeviceSpecs(
    name: 'Xiaomi 13 Pro',
    width: 1440,
    height: 3200,
    dpi: 522,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi13Ultra = DeviceSpecs(
    name: 'Xiaomi 13 Ultra',
    width: 1440,
    height: 3200,
    dpi: 522,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi13Lite = DeviceSpecs(
    name: 'Xiaomi 13 Lite',
    width: 1080,
    height: 2400,
    dpi: 402,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi14 = DeviceSpecs(
    name: 'Xiaomi 14',
    width: 1200,
    height: 2670,
    dpi: 460,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi14Pro = DeviceSpecs(
    name: 'Xiaomi 14 Pro',
    width: 1440,
    height: 3200,
    dpi: 522,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi14Ultra = DeviceSpecs(
    name: 'Xiaomi 14 Ultra',
    width: 1440,
    height: 3200,
    dpi: 522,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi15 = DeviceSpecs(
    name: 'Xiaomi 15',
    width: 1200,
    height: 2670,
    dpi: 460,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi15Pro = DeviceSpecs(
    name: 'Xiaomi 15 Pro',
    width: 1440,
    height: 3200,
    dpi: 522,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi15Ultra = DeviceSpecs(
    name: 'Xiaomi 15 Ultra',
    width: 1440,
    height: 3200,
    dpi: 525,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi17 = DeviceSpecs(
    name: 'Xiaomi 17',
    width: 1260,
    height: 2800,
    dpi: 470,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const xiaomi17Pro = DeviceSpecs(
    name: 'Xiaomi 17 Pro',
    width: 1440,
    height: 3200,
    dpi: 530,
    refreshRate: 144,
    aspectRatio: 20 / 9,
  );
  static const xiaomi17Ultra = DeviceSpecs(
    name: 'Xiaomi 17 Ultra',
    width: 1440,
    height: 3200,
    dpi: 535,
    refreshRate: 144,
    aspectRatio: 20 / 9,
  );

  // ============================================
  // OnePlus 绯诲垪 (OnePlus 12 - Ace 6T)
  // ============================================
  static const onePlus12 = DeviceSpecs(
    name: 'OnePlus 12',
    width: 1440,
    height: 3168,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlus12R = DeviceSpecs(
    name: 'OnePlus 12R',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlus13 = DeviceSpecs(
    name: 'OnePlus 13',
    width: 1440,
    height: 3168,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlus13R = DeviceSpecs(
    name: 'OnePlus 13R',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlus14 = DeviceSpecs(
    name: 'OnePlus 14',
    width: 1440,
    height: 3200,
    dpi: 520,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const onePlus15 = DeviceSpecs(
    name: 'OnePlus 15',
    width: 1440,
    height: 3216,
    dpi: 525,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const onePlusAce3 = DeviceSpecs(
    name: 'OnePlus Ace 3',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlusAce3Pro = DeviceSpecs(
    name: 'OnePlus Ace 3 Pro',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlusAce3V = DeviceSpecs(
    name: 'OnePlus Ace 3V',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const onePlusAce5 = DeviceSpecs(
    name: 'OnePlus Ace 5',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlusAce5Pro = DeviceSpecs(
    name: 'OnePlus Ace 5 Pro',
    width: 1440,
    height: 3168,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlusAce6 = DeviceSpecs(
    name: 'OnePlus Ace 6',
    width: 1264,
    height: 2780,
    dpi: 452,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const onePlusAce6T = DeviceSpecs(
    name: 'OnePlus Ace 6T',
    width: 1264,
    height: 2780,
    dpi: 455,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );

  // ============================================
  // Vivo X 绯诲垪 (X100 - 鏈€鏂?
  // ============================================
  static const vivoX100 = DeviceSpecs(
    name: 'Vivo X100',
    width: 1260,
    height: 2800,
    dpi: 452,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const vivoX100Pro = DeviceSpecs(
    name: 'Vivo X100 Pro',
    width: 1440,
    height: 3200,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const vivoX100Ultra = DeviceSpecs(
    name: 'Vivo X100 Ultra',
    width: 1440,
    height: 3200,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const vivoX100s = DeviceSpecs(
    name: 'Vivo X100s',
    width: 1260,
    height: 2800,
    dpi: 452,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const vivoX100sPro = DeviceSpecs(
    name: 'Vivo X100s Pro',
    width: 1440,
    height: 3200,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const vivoX200 = DeviceSpecs(
    name: 'Vivo X200',
    width: 1260,
    height: 2800,
    dpi: 452,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const vivoX200Pro = DeviceSpecs(
    name: 'Vivo X200 Pro',
    width: 1440,
    height: 3200,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const vivoX200ProMini = DeviceSpecs(
    name: 'Vivo X200 Pro Mini',
    width: 1260,
    height: 2800,
    dpi: 460,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const vivoX200Ultra = DeviceSpecs(
    name: 'Vivo X200 Ultra',
    width: 1440,
    height: 3200,
    dpi: 515,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );

  // ============================================
  // OPPO Find X 绯诲垪 (Find X7 - 鏈€鏂?
  // ============================================
  static const oppoFindX7 = DeviceSpecs(
    name: 'OPPO Find X7',
    width: 1264,
    height: 2780,
    dpi: 452,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const oppoFindX7Ultra = DeviceSpecs(
    name: 'OPPO Find X7 Ultra',
    width: 1440,
    height: 3168,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const oppoFindX8 = DeviceSpecs(
    name: 'OPPO Find X8',
    width: 1264,
    height: 2780,
    dpi: 452,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const oppoFindX8Pro = DeviceSpecs(
    name: 'OPPO Find X8 Pro',
    width: 1440,
    height: 3168,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const oppoFindN3 = DeviceSpecs(
    name: 'OPPO Find N3',
    width: 1440,
    height: 2120,
    dpi: 426,
    refreshRate: 120,
    aspectRatio: 20.4 / 9,
  );
  static const oppoFindN3Flip = DeviceSpecs(
    name: 'OPPO Find N3 Flip',
    width: 1080,
    height: 2520,
    dpi: 403,
    refreshRate: 120,
    aspectRatio: 21 / 9,
  );

  // ============================================
  // Samsung Galaxy S 绯诲垪 (S20 - S25)
  // ============================================
  static const samsungS20 = DeviceSpecs(
    name: 'Samsung Galaxy S20',
    width: 1440,
    height: 3200,
    dpi: 563,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const samsungS20Plus = DeviceSpecs(
    name: 'Samsung Galaxy S20+',
    width: 1440,
    height: 3200,
    dpi: 525,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const samsungS20Ultra = DeviceSpecs(
    name: 'Samsung Galaxy S20 Ultra',
    width: 1440,
    height: 3200,
    dpi: 511,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const samsungS20FE = DeviceSpecs(
    name: 'Samsung Galaxy S20 FE',
    width: 1080,
    height: 2400,
    dpi: 407,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const samsungS21 = DeviceSpecs(
    name: 'Samsung Galaxy S21',
    width: 1080,
    height: 2400,
    dpi: 421,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const samsungS21Plus = DeviceSpecs(
    name: 'Samsung Galaxy S21+',
    width: 1080,
    height: 2400,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const samsungS21Ultra = DeviceSpecs(
    name: 'Samsung Galaxy S21 Ultra',
    width: 1440,
    height: 3200,
    dpi: 515,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const samsungS21FE = DeviceSpecs(
    name: 'Samsung Galaxy S21 FE',
    width: 1080,
    height: 2340,
    dpi: 401,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS22 = DeviceSpecs(
    name: 'Samsung Galaxy S22',
    width: 1080,
    height: 2340,
    dpi: 425,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS22Plus = DeviceSpecs(
    name: 'Samsung Galaxy S22+',
    width: 1080,
    height: 2340,
    dpi: 393,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS22Ultra = DeviceSpecs(
    name: 'Samsung Galaxy S22 Ultra',
    width: 1440,
    height: 3088,
    dpi: 500,
    refreshRate: 120,
    aspectRatio: 19.3 / 9,
  );
  static const samsungS23 = DeviceSpecs(
    name: 'Samsung Galaxy S23',
    width: 1080,
    height: 2340,
    dpi: 425,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS23Plus = DeviceSpecs(
    name: 'Samsung Galaxy S23+',
    width: 1080,
    height: 2340,
    dpi: 393,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS23Ultra = DeviceSpecs(
    name: 'Samsung Galaxy S23 Ultra',
    width: 1440,
    height: 3088,
    dpi: 500,
    refreshRate: 120,
    aspectRatio: 19.3 / 9,
  );
  static const samsungS23FE = DeviceSpecs(
    name: 'Samsung Galaxy S23 FE',
    width: 1080,
    height: 2340,
    dpi: 401,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS24 = DeviceSpecs(
    name: 'Samsung Galaxy S24',
    width: 1080,
    height: 2340,
    dpi: 416,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS24Plus = DeviceSpecs(
    name: 'Samsung Galaxy S24+',
    width: 1440,
    height: 3120,
    dpi: 513,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS24Ultra = DeviceSpecs(
    name: 'Samsung Galaxy S24 Ultra',
    width: 1440,
    height: 3120,
    dpi: 505,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS24FE = DeviceSpecs(
    name: 'Samsung Galaxy S24 FE',
    width: 1080,
    height: 2340,
    dpi: 385,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS25 = DeviceSpecs(
    name: 'Samsung Galaxy S25',
    width: 1080,
    height: 2340,
    dpi: 416,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS25Plus = DeviceSpecs(
    name: 'Samsung Galaxy S25+',
    width: 1440,
    height: 3120,
    dpi: 513,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS25Ultra = DeviceSpecs(
    name: 'Samsung Galaxy S25 Ultra',
    width: 1440,
    height: 3120,
    dpi: 498,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const samsungS25Edge = DeviceSpecs(
    name: 'Samsung Galaxy S25 Edge',
    width: 1440,
    height: 3120,
    dpi: 513,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );

  // ============================================
  // Samsung Galaxy Note 绯诲垪 (Note 20 绯诲垪)
  // ============================================
  static const samsungNote20 = DeviceSpecs(
    name: 'Samsung Galaxy Note 20',
    width: 1080,
    height: 2400,
    dpi: 393,
    refreshRate: 60,
    aspectRatio: 20 / 9,
  );
  static const samsungNote20Ultra = DeviceSpecs(
    name: 'Samsung Galaxy Note 20 Ultra',
    width: 1440,
    height: 3088,
    dpi: 496,
    refreshRate: 120,
    aspectRatio: 19.3 / 9,
  );

  // ============================================
  // Nothing Phone 绯诲垪 (鍏ㄧ郴鍒?
  // ============================================
  static const nothingPhone1 = DeviceSpecs(
    name: 'Nothing Phone (1)',
    width: 1080,
    height: 2400,
    dpi: 402,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const nothingPhone2 = DeviceSpecs(
    name: 'Nothing Phone (2)',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const nothingPhone2a = DeviceSpecs(
    name: 'Nothing Phone (2a)',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const nothingPhone2aPlus = DeviceSpecs(
    name: 'Nothing Phone (2a) Plus',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const nothingPhone3 = DeviceSpecs(
    name: 'Nothing Phone (3)',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const nothingPhone3a = DeviceSpecs(
    name: 'Nothing Phone (3a)',
    width: 1080,
    height: 2412,
    dpi: 398,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const nothingPhone3aPro = DeviceSpecs(
    name: 'Nothing Phone (3a) Pro',
    width: 1080,
    height: 2412,
    dpi: 398,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );

  // ============================================
  // Realme 绯诲垪 (Realme 8 - 鏈€鏂?
  // ============================================
  static const realme8 = DeviceSpecs(
    name: 'Realme 8',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 60,
    aspectRatio: 20 / 9,
  );
  static const realme8Pro = DeviceSpecs(
    name: 'Realme 8 Pro',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 60,
    aspectRatio: 20 / 9,
  );
  static const realme85G = DeviceSpecs(
    name: 'Realme 8 5G',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const realme8i = DeviceSpecs(
    name: 'Realme 8i',
    width: 1080,
    height: 2400,
    dpi: 400,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realme8s5G = DeviceSpecs(
    name: 'Realme 8s 5G',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const realme9 = DeviceSpecs(
    name: 'Realme 9',
    width: 1080,
    height: 2400,
    dpi: 409,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const realme9Pro = DeviceSpecs(
    name: 'Realme 9 Pro',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realme9ProPlus = DeviceSpecs(
    name: 'Realme 9 Pro+',
    width: 1080,
    height: 2400,
    dpi: 409,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const realme95G = DeviceSpecs(
    name: 'Realme 9 5G',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const realme9i = DeviceSpecs(
    name: 'Realme 9i',
    width: 1080,
    height: 2412,
    dpi: 409,
    refreshRate: 90,
    aspectRatio: 20.1 / 9,
  );
  static const realme10 = DeviceSpecs(
    name: 'Realme 10',
    width: 1080,
    height: 2400,
    dpi: 409,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const realme10Pro = DeviceSpecs(
    name: 'Realme 10 Pro',
    width: 1080,
    height: 2400,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realme10ProPlus = DeviceSpecs(
    name: 'Realme 10 Pro+',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const realme11 = DeviceSpecs(
    name: 'Realme 11',
    width: 1080,
    height: 2400,
    dpi: 409,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const realme11Pro = DeviceSpecs(
    name: 'Realme 11 Pro',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const realme11ProPlus = DeviceSpecs(
    name: 'Realme 11 Pro+',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const realme11x = DeviceSpecs(
    name: 'Realme 11x',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realme12 = DeviceSpecs(
    name: 'Realme 12',
    width: 1080,
    height: 2400,
    dpi: 409,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const realme12Pro = DeviceSpecs(
    name: 'Realme 12 Pro',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const realme12ProPlus = DeviceSpecs(
    name: 'Realme 12 Pro+',
    width: 1220,
    height: 2712,
    dpi: 448,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realme12x = DeviceSpecs(
    name: 'Realme 12x',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realme125G = DeviceSpecs(
    name: 'Realme 12 5G',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realme13 = DeviceSpecs(
    name: 'Realme 13',
    width: 1080,
    height: 2400,
    dpi: 409,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realme13Pro = DeviceSpecs(
    name: 'Realme 13 Pro',
    width: 1080,
    height: 2412,
    dpi: 394,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const realme13ProPlus = DeviceSpecs(
    name: 'Realme 13 Pro+',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const realme135G = DeviceSpecs(
    name: 'Realme 13 5G',
    width: 1080,
    height: 2400,
    dpi: 405,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const realmeGT5 = DeviceSpecs(
    name: 'Realme GT 5',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 144,
    aspectRatio: 19.8 / 9,
  );
  static const realmeGT5Pro = DeviceSpecs(
    name: 'Realme GT 5 Pro',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 144,
    aspectRatio: 19.8 / 9,
  );
  static const realmeGT6 = DeviceSpecs(
    name: 'Realme GT 6',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );
  static const realmeGT6T = DeviceSpecs(
    name: 'Realme GT 6T',
    width: 1264,
    height: 2780,
    dpi: 450,
    refreshRate: 120,
    aspectRatio: 19.8 / 9,
  );

  // ============================================
  // Google Pixel 璁惧 (淇濈暀鍘熸湁)
  // ============================================
  static const pixel5 = DeviceSpecs(
    name: 'Pixel 5',
    width: 1080,
    height: 2340,
    dpi: 432,
    refreshRate: 90,
    aspectRatio: 19.5 / 9,
  );
  static const pixel6 = DeviceSpecs(
    name: 'Pixel 6',
    width: 1080,
    height: 2400,
    dpi: 411,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const pixel6Pro = DeviceSpecs(
    name: 'Pixel 6 Pro',
    width: 1440,
    height: 3120,
    dpi: 512,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const pixel7 = DeviceSpecs(
    name: 'Pixel 7',
    width: 1080,
    height: 2400,
    dpi: 416,
    refreshRate: 90,
    aspectRatio: 20 / 9,
  );
  static const pixel7Pro = DeviceSpecs(
    name: 'Pixel 7 Pro',
    width: 1440,
    height: 3120,
    dpi: 512,
    refreshRate: 120,
    aspectRatio: 19.5 / 9,
  );
  static const pixel8 = DeviceSpecs(
    name: 'Pixel 8',
    width: 1080,
    height: 2400,
    dpi: 428,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const pixel8Pro = DeviceSpecs(
    name: 'Pixel 8 Pro',
    width: 1344,
    height: 2992,
    dpi: 489,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const pixel9 = DeviceSpecs(
    name: 'Pixel 9',
    width: 1080,
    height: 2424,
    dpi: 422,
    refreshRate: 120,
    aspectRatio: 20.2 / 9,
  );
  static const pixel9Pro = DeviceSpecs(
    name: 'Pixel 9 Pro',
    width: 1280,
    height: 2856,
    dpi: 495,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const pixel9ProXL = DeviceSpecs(
    name: 'Pixel 9 Pro XL',
    width: 1344,
    height: 2992,
    dpi: 486,
    refreshRate: 120,
    aspectRatio: 20.1 / 9,
  );
  static const pixel10 = DeviceSpecs(
    name: 'Pixel 10',
    width: 1080,
    height: 2400,
    dpi: 420,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );
  static const pixel10Pro = DeviceSpecs(
    name: 'Pixel 10 Pro',
    width: 1344,
    height: 3024,
    dpi: 500,
    refreshRate: 120,
    aspectRatio: 20.3 / 9,
  );
  static const pixel10ProXL = DeviceSpecs(
    name: 'Pixel 10 Pro XL',
    width: 1440,
    height: 3200,
    dpi: 510,
    refreshRate: 120,
    aspectRatio: 20 / 9,
  );

  /// 鑾峰彇鎵€鏈夎澶囪鏍煎垪琛?
  static List<DeviceSpecs> get allDevices => [
    // 鍗庝负 Mate 绯诲垪
    huaweiMate9,
    huaweiMate9Pro,
    huaweiMate10,
    huaweiMate10Pro,
    huaweiMate10Lite,
    huaweiMate20, huaweiMate20Pro, huaweiMate20X, huaweiMate20Lite,
    huaweiMate30, huaweiMate30Pro, huaweiMate30Pro5G,
    huaweiMate40, huaweiMate40Pro, huaweiMate40ProPlus, huaweiNova12Pro,
    // 灏忕背绯诲垪
    xiaomi10, xiaomi10Pro, xiaomi10Ultra, xiaomi10Lite,
    xiaomi11, xiaomi11Pro, xiaomi11Ultra, xiaomi11Lite,
    xiaomi12, xiaomi12Pro, xiaomi12Ultra, xiaomi12Lite,
    xiaomi13, xiaomi13Pro, xiaomi13Ultra, xiaomi13Lite,
    xiaomi14, xiaomi14Pro, xiaomi14Ultra,
    xiaomi15, xiaomi15Pro, xiaomi15Ultra,
    xiaomi17, xiaomi17Pro, xiaomi17Ultra,
    // OnePlus 绯诲垪
    onePlus12, onePlus12R, onePlus13, onePlus13R, onePlus14, onePlus15,
    onePlusAce3, onePlusAce3Pro, onePlusAce3V,
    onePlusAce5, onePlusAce5Pro, onePlusAce6, onePlusAce6T,
    // Vivo X 绯诲垪
    vivoX100, vivoX100Pro, vivoX100Ultra, vivoX100s, vivoX100sPro,
    vivoX200, vivoX200Pro, vivoX200ProMini, vivoX200Ultra,
    // OPPO Find X 绯诲垪
    oppoFindX7, oppoFindX7Ultra, oppoFindX8, oppoFindX8Pro,
    oppoFindN3, oppoFindN3Flip,
    // Samsung Galaxy S 绯诲垪
    samsungS20, samsungS20Plus, samsungS20Ultra, samsungS20FE,
    samsungS21, samsungS21Plus, samsungS21Ultra, samsungS21FE,
    samsungS22, samsungS22Plus, samsungS22Ultra,
    samsungS23, samsungS23Plus, samsungS23Ultra, samsungS23FE,
    samsungS24, samsungS24Plus, samsungS24Ultra, samsungS24FE,
    samsungS25, samsungS25Plus, samsungS25Ultra, samsungS25Edge,
    // Samsung Galaxy Note 绯诲垪
    samsungNote20, samsungNote20Ultra,
    // Nothing Phone 绯诲垪
    nothingPhone1, nothingPhone2, nothingPhone2a, nothingPhone2aPlus,
    nothingPhone3, nothingPhone3a, nothingPhone3aPro,
    // Realme 绯诲垪
    realme8, realme8Pro, realme85G, realme8i, realme8s5G,
    realme9, realme9Pro, realme9ProPlus, realme95G, realme9i,
    realme10, realme10Pro, realme10ProPlus,
    realme11, realme11Pro, realme11ProPlus, realme11x,
    realme12, realme12Pro, realme12ProPlus, realme12x, realme125G,
    realme13, realme13Pro, realme13ProPlus, realme135G,
    realmeGT5, realmeGT5Pro, realmeGT6, realmeGT6T,
    // Google Pixel 绯诲垪
    pixel5, pixel6, pixel6Pro, pixel7, pixel7Pro, pixel8, pixel8Pro,
    pixel9, pixel9Pro, pixel9ProXL, pixel10, pixel10Pro, pixel10ProXL,
  ];
}

/// 鍝嶅簲寮忓伐鍏风被 - 鏍稿績閫傞厤閫昏緫
class ResponsiveUtils {
  ResponsiveUtils._();

  /// 鑾峰彇璁惧绫诲瀷
  static DeviceType getDeviceType(BuildContext context) {
    final width = MediaQuery.of(context).size.shortestSide;
    if (width < 600) return DeviceType.phone;
    if (width < 900) return DeviceType.tablet;
    return DeviceType.desktop;
  }

  /// 鑾峰彇灞忓箷灏哄绫诲瀷 (Material 3 鏂偣)
  static ScreenSizeType getScreenSizeType(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 600) return ScreenSizeType.compact;
    if (width < 840) return ScreenSizeType.medium;
    return ScreenSizeType.expanded;
  }

  /// 鏄惁涓洪珮 DPI 璁惧 (> 400 dpi)
  static bool isHighDpiDevice(BuildContext context) {
    return MediaQuery.of(context).devicePixelRatio > 2.5;
  }

  /// 鏄惁涓鸿秴楂?DPI 璁惧 (> 500 dpi)
  static bool isUltraHighDpiDevice(BuildContext context) {
    return MediaQuery.of(context).devicePixelRatio > 3.0;
  }

  /// 鑾峰彇瀹夊叏鍖哄煙鍐呰竟璺?
  static EdgeInsets getSafeAreaPadding(BuildContext context) {
    return MediaQuery.of(context).padding;
  }

  /// 鑾峰彇瑙嗗浘鍐呰竟璺?(鍖呭惈绯荤粺 UI)
  static EdgeInsets getViewPadding(BuildContext context) {
    return MediaQuery.of(context).viewPadding;
  }

  /// 鑾峰彇灞忓箷瀹介珮姣?
  static double getAspectRatio(BuildContext context) {
    final size = MediaQuery.of(context).size;
    return size.height / size.width;
  }

  /// 鏄惁涓洪暱灞忓箷璁惧 (瀹介珮姣?> 2.0)
  static bool isTallScreen(BuildContext context) {
    return getAspectRatio(context) > 2.0;
  }

  /// 鏄惁涓鸿秴闀垮睆骞曡澶?(瀹介珮姣?> 2.1)
  static bool isExtraTallScreen(BuildContext context) {
    return getAspectRatio(context) > 2.1;
  }

  /// 鑾峰彇鍝嶅簲寮忓唴杈硅窛
  static EdgeInsets getResponsivePadding(BuildContext context) {
    final screenType = getScreenSizeType(context);
    final safeArea = getSafeAreaPadding(context);

    switch (screenType) {
      case ScreenSizeType.compact:
        return EdgeInsets.fromLTRB(
          16 + safeArea.left,
          8,
          16 + safeArea.right,
          8 + safeArea.bottom,
        );
      case ScreenSizeType.medium:
        return EdgeInsets.fromLTRB(
          24 + safeArea.left,
          12,
          24 + safeArea.right,
          12 + safeArea.bottom,
        );
      case ScreenSizeType.expanded:
        return EdgeInsets.fromLTRB(
          32 + safeArea.left,
          16,
          32 + safeArea.right,
          16 + safeArea.bottom,
        );
    }
  }

  /// 鑾峰彇鍗＄墖鍐呰竟璺?
  static EdgeInsets getCardPadding(BuildContext context) {
    final screenType = getScreenSizeType(context);
    switch (screenType) {
      case ScreenSizeType.compact:
        return const EdgeInsets.all(12);
      case ScreenSizeType.medium:
        return const EdgeInsets.all(16);
      case ScreenSizeType.expanded:
        return const EdgeInsets.all(20);
    }
  }

  /// 鑾峰彇鍒楄〃椤归珮搴?
  static double getListItemHeight(BuildContext context) {
    final screenType = getScreenSizeType(context);
    final textScale = MediaQuery.textScalerOf(context).scale(1.0);

    double baseHeight;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseHeight = 56;
        break;
      case ScreenSizeType.medium:
        baseHeight = 64;
        break;
      case ScreenSizeType.expanded:
        baseHeight = 72;
        break;
    }

    // 鏍规嵁鏂囧瓧缂╂斁璋冩暣
    return baseHeight * (textScale > 1.0 ? (1 + (textScale - 1) * 0.5) : 1.0);
  }

  /// 鑾峰彇鍥炬爣澶у皬
  static double getIconSize(BuildContext context, {bool large = false}) {
    final screenType = getScreenSizeType(context);
    final dpr = MediaQuery.of(context).devicePixelRatio;

    double baseSize;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseSize = large ? 28 : 22;
        break;
      case ScreenSizeType.medium:
        baseSize = large ? 32 : 24;
        break;
      case ScreenSizeType.expanded:
        baseSize = large ? 36 : 28;
        break;
    }

    // 楂?DPI 璁惧绋嶅井澧炲ぇ鍥炬爣
    if (dpr > 3.0) {
      baseSize *= 1.05;
    }

    return baseSize;
  }

  /// 鑾峰彇瀛椾綋澶у皬缂╂斁鍥犲瓙
  static double getFontScaleFactor(BuildContext context) {
    final screenType = getScreenSizeType(context);
    final textScale = MediaQuery.textScalerOf(context).scale(1.0);

    double baseFactor;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseFactor = 1.0;
        break;
      case ScreenSizeType.medium:
        baseFactor = 1.05;
        break;
      case ScreenSizeType.expanded:
        baseFactor = 1.1;
        break;
    }

    // 闄愬埗鏈€澶х缉鏀撅紝闃叉甯冨眬婧㈠嚭
    return (baseFactor * textScale).clamp(0.8, 1.5);
  }

  /// 鑾峰彇缃戞牸鍒楁暟
  static int getGridColumnCount(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 400) return 1;
    if (width < 600) return 2;
    if (width < 900) return 3;
    if (width < 1200) return 4;
    return 5;
  }

  /// 鑾峰彇鍗＄墖缃戞牸鍒楁暟
  static int getCardGridColumnCount(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 500) return 1;
    if (width < 800) return 2;
    if (width < 1100) return 3;
    return 4;
  }

  /// 鑾峰彇鍦嗚鍗婂緞
  static double getBorderRadius(BuildContext context) {
    final screenType = getScreenSizeType(context);
    switch (screenType) {
      case ScreenSizeType.compact:
        return 12;
      case ScreenSizeType.medium:
        return 16;
      case ScreenSizeType.expanded:
        return 20;
    }
  }

  /// 鑾峰彇鍗＄墖鍦嗚鍗婂緞
  static BorderRadius getCardBorderRadius(BuildContext context) {
    return BorderRadius.circular(getBorderRadius(context));
  }

  /// 鑾峰彇鎸夐挳楂樺害
  static double getButtonHeight(BuildContext context) {
    final screenType = getScreenSizeType(context);
    switch (screenType) {
      case ScreenSizeType.compact:
        return 44;
      case ScreenSizeType.medium:
        return 48;
      case ScreenSizeType.expanded:
        return 52;
    }
  }

  /// 鑾峰彇杈撳叆妗嗛珮搴?
  static double getInputHeight(BuildContext context) {
    final screenType = getScreenSizeType(context);
    final textScale = MediaQuery.textScalerOf(context).scale(1.0);

    double baseHeight;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseHeight = 48;
        break;
      case ScreenSizeType.medium:
        baseHeight = 52;
        break;
      case ScreenSizeType.expanded:
        baseHeight = 56;
        break;
    }

    return baseHeight * (textScale > 1.0 ? (1 + (textScale - 1) * 0.3) : 1.0);
  }

  /// 鑾峰彇搴曢儴瀵艰埅鏍忛珮搴?
  static double getBottomNavHeight(BuildContext context) {
    final safeArea = getSafeAreaPadding(context);
    final screenType = getScreenSizeType(context);

    double baseHeight;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseHeight = 64;
        break;
      case ScreenSizeType.medium:
        baseHeight = 72;
        break;
      case ScreenSizeType.expanded:
        baseHeight = 80;
        break;
    }

    return baseHeight + safeArea.bottom;
  }

  /// 鑾峰彇 AppBar 楂樺害
  static double getAppBarHeight(BuildContext context) {
    final safeArea = getSafeAreaPadding(context);
    final screenType = getScreenSizeType(context);

    double baseHeight;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseHeight = 56;
        break;
      case ScreenSizeType.medium:
        baseHeight = 60;
        break;
      case ScreenSizeType.expanded:
        baseHeight = 64;
        break;
    }

    return baseHeight + safeArea.top;
  }

  /// 鑾峰彇瀵硅瘽妗嗘渶澶у搴?
  static double getDialogMaxWidth(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    final screenType = getScreenSizeType(context);

    switch (screenType) {
      case ScreenSizeType.compact:
        return width * 0.92;
      case ScreenSizeType.medium:
        return width * 0.75;
      case ScreenSizeType.expanded:
        return 560;
    }
  }

  /// 鑾峰彇搴曢儴寮圭獥鏈€澶ч珮搴︽瘮渚?
  static double getBottomSheetMaxHeightRatio(BuildContext context) {
    final aspectRatio = getAspectRatio(context);

    // 闀垮睆骞曡澶囧彲浠ヤ娇鐢ㄦ洿澶氶珮搴?
    if (aspectRatio > 2.1) return 0.85;
    if (aspectRatio > 2.0) return 0.80;
    if (aspectRatio > 1.8) return 0.75;
    return 0.70;
  }

  /// 鑾峰彇闂磋窛
  static double getSpacing(BuildContext context, {double multiplier = 1.0}) {
    final screenType = getScreenSizeType(context);

    double baseSpacing;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseSpacing = 8;
        break;
      case ScreenSizeType.medium:
        baseSpacing = 12;
        break;
      case ScreenSizeType.expanded:
        baseSpacing = 16;
        break;
    }

    return baseSpacing * multiplier;
  }

  /// 鑾峰彇瑙︽懜鐩爣鏈€灏忓昂瀵?(Material 3 瑙勮寖: 48dp)
  static double getMinTouchTargetSize(BuildContext context) {
    return 48.0;
  }

  /// 鑾峰彇婊氬姩鐗╃悊鏁堟灉
  static ScrollPhysics getScrollPhysics(BuildContext context) {
    if (!kIsWeb && Platform.isAndroid) {
      return const ClampingScrollPhysics();
    }
    return const BouncingScrollPhysics();
  }

  /// 鏄惁搴旇鏄剧ず搴曢儴瀵艰埅
  static bool shouldShowBottomNav(BuildContext context) {
    final screenType = getScreenSizeType(context);
    return screenType == ScreenSizeType.compact;
  }

  /// 鏄惁搴旇鏄剧ず渚ц竟瀵艰埅
  static bool shouldShowSideNav(BuildContext context) {
    final screenType = getScreenSizeType(context);
    return screenType != ScreenSizeType.compact;
  }

  /// 鏄惁搴旇鏄剧ず NavigationRail
  static bool shouldShowNavigationRail(BuildContext context) {
    final screenType = getScreenSizeType(context);
    return screenType == ScreenSizeType.medium;
  }

  /// 鏄惁搴旇鏄剧ず NavigationDrawer
  static bool shouldShowNavigationDrawer(BuildContext context) {
    final screenType = getScreenSizeType(context);
    return screenType == ScreenSizeType.expanded;
  }

  /// 鑾峰彇鐘舵€佸崱鐗囬珮搴?
  static double getStatusCardHeight(BuildContext context) {
    final screenType = getScreenSizeType(context);
    final isTall = isTallScreen(context);

    double baseHeight;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseHeight = isTall ? 200 : 180;
        break;
      case ScreenSizeType.medium:
        baseHeight = 220;
        break;
      case ScreenSizeType.expanded:
        baseHeight = 240;
        break;
    }

    return baseHeight;
  }

  /// 鑾峰彇娴侀噺鍥捐〃楂樺害
  static double getTrafficChartHeight(BuildContext context) {
    final screenType = getScreenSizeType(context);
    final isTall = isTallScreen(context);

    double baseHeight;
    switch (screenType) {
      case ScreenSizeType.compact:
        baseHeight = isTall ? 180 : 160;
        break;
      case ScreenSizeType.medium:
        baseHeight = 200;
        break;
      case ScreenSizeType.expanded:
        baseHeight = 220;
        break;
    }

    return baseHeight;
  }
}

/// 鍝嶅簲寮忔瀯寤哄櫒 Widget
class ResponsiveBuilder extends StatelessWidget {
  final Widget Function(
    BuildContext context,
    ScreenSizeType screenType,
    DeviceType deviceType,
  )
  builder;

  const ResponsiveBuilder({super.key, required this.builder});

  @override
  Widget build(BuildContext context) {
    return builder(
      context,
      ResponsiveUtils.getScreenSizeType(context),
      ResponsiveUtils.getDeviceType(context),
    );
  }
}

/// 鍝嶅簲寮忓竷灞€ Widget
class ResponsiveLayout extends StatelessWidget {
  final Widget compact;
  final Widget? medium;
  final Widget? expanded;

  const ResponsiveLayout({
    super.key,
    required this.compact,
    this.medium,
    this.expanded,
  });

  @override
  Widget build(BuildContext context) {
    final screenType = ResponsiveUtils.getScreenSizeType(context);

    switch (screenType) {
      case ScreenSizeType.expanded:
        return expanded ?? medium ?? compact;
      case ScreenSizeType.medium:
        return medium ?? compact;
      case ScreenSizeType.compact:
        return compact;
    }
  }
}

/// 鍝嶅簲寮忛棿璺?Widget
class ResponsiveSpacing extends StatelessWidget {
  final double multiplier;
  final Axis axis;

  const ResponsiveSpacing({
    super.key,
    this.multiplier = 1.0,
    this.axis = Axis.vertical,
  });

  @override
  Widget build(BuildContext context) {
    final spacing = ResponsiveUtils.getSpacing(context, multiplier: multiplier);

    if (axis == Axis.vertical) {
      return SizedBox(height: spacing);
    } else {
      return SizedBox(width: spacing);
    }
  }
}

/// 鍝嶅簲寮忓唴杈硅窛 Widget
class ResponsivePadding extends StatelessWidget {
  final Widget child;
  final double? horizontal;
  final double? vertical;

  const ResponsivePadding({
    super.key,
    required this.child,
    this.horizontal,
    this.vertical,
  });

  @override
  Widget build(BuildContext context) {
    final basePadding = ResponsiveUtils.getResponsivePadding(context);

    return Padding(
      padding: EdgeInsets.symmetric(
        horizontal: horizontal ?? basePadding.left,
        vertical: vertical ?? basePadding.top,
      ),
      child: child,
    );
  }
}

/// 瀹夊叏鍖哄煙鍖呰鍣?
class SafeAreaWrapper extends StatelessWidget {
  final Widget child;
  final bool top;
  final bool bottom;
  final bool left;
  final bool right;

  const SafeAreaWrapper({
    super.key,
    required this.child,
    this.top = true,
    this.bottom = true,
    this.left = true,
    this.right = true,
  });

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      top: top,
      bottom: bottom,
      left: left,
      right: right,
      minimum: EdgeInsets.only(bottom: ResponsiveUtils.getSpacing(context)),
      child: child,
    );
  }
}

/// 璁惧鐗瑰畾 UI 浼樺寲宸ュ叿
class DeviceOptimizedUI {
  DeviceOptimizedUI._();
  
  /// 鏍规嵁璁惧鍝佺墝鑾峰彇浼樺寲鐨勫渾瑙掑崐寰?
  static double getBorderRadiusForBrand(BuildContext context, String brand) {
    final baseBorderRadius = ResponsiveUtils.getBorderRadius(context);
    
    switch (brand.toUpperCase()) {
      case 'SAMSUNG':
        // Samsung One UI 椋庢牸 - 鏇村ぇ鐨勫渾瑙?
        return baseBorderRadius * 1.25;
      case 'XIAOMI':
      case 'REDMI':
      case 'POCO':
        // MIUI 椋庢牸
        return baseBorderRadius;
      case 'HUAWEI':
      case 'HONOR':
        // EMUI/HarmonyOS 椋庢牸 - 绋嶅ぇ鐨勫渾瑙?
        return baseBorderRadius * 1.1;
      case 'ONEPLUS':
        // OxygenOS 椋庢牸
        return baseBorderRadius;
      case 'VIVO':
      case 'IQOO':
        // OriginOS 椋庢牸 - 绋嶅皬鐨勫渾瑙?
        return baseBorderRadius * 0.9;
      case 'OPPO':
      case 'REALME':
        // ColorOS 椋庢牸
        return baseBorderRadius * 0.9;
      case 'NOTHING':
        // Nothing OS 椋庢牸 - 鏇存柟姝?
        return baseBorderRadius * 0.75;
      case 'GOOGLE':
        // Material You 椋庢牸
        return baseBorderRadius;
      default:
        return baseBorderRadius;
    }
  }
  
  /// 鏍规嵁璁惧鍝佺墝鑾峰彇浼樺寲鐨勫崱鐗囬槾褰?
  static List<BoxShadow> getCardShadowForBrand(
    BuildContext context, 
    String brand,
    ColorScheme colorScheme,
  ) {
    switch (brand.toUpperCase()) {
      case 'SAMSUNG':
        // Samsung 椋庢牸 - 鏇存煍鍜岀殑闃村奖
        return [
          BoxShadow(
            color: colorScheme.shadow.withValues(alpha: 0.08),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ];
      case 'XIAOMI':
      case 'REDMI':
        // MIUI 椋庢牸 - 杈冩槑鏄剧殑闃村奖
        return [
          BoxShadow(
            color: colorScheme.shadow.withValues(alpha: 0.12),
            blurRadius: 12,
            offset: const Offset(0, 3),
          ),
        ];
      case 'NOTHING':
        // Nothing 椋庢牸 - 鍑犱箮鏃犻槾褰?
        return [
          BoxShadow(
            color: colorScheme.shadow.withValues(alpha: 0.04),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ];
      default:
        return [
          BoxShadow(
            color: colorScheme.shadow.withValues(alpha: 0.1),
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ];
    }
  }
  
  /// 鏍规嵁璁惧鍝佺墝鑾峰彇浼樺寲鐨勫姩鐢绘椂闀?
  static Duration getAnimationDurationForBrand(String brand) {
    switch (brand.toUpperCase()) {
      case 'SAMSUNG':
        // Samsung 鍔ㄧ敾杈冩參
        return const Duration(milliseconds: 350);
      case 'ONEPLUS':
        // OnePlus 鍔ㄧ敾杈冨揩
        return const Duration(milliseconds: 250);
      case 'NOTHING':
        // Nothing 鍔ㄧ敾绠€娲?
        return const Duration(milliseconds: 200);
      default:
        return const Duration(milliseconds: 300);
    }
  }
  
  /// 鏍规嵁璁惧鍝佺墝鑾峰彇浼樺寲鐨勫浘鏍囧ぇ灏?
  static double getIconSizeForBrand(BuildContext context, String brand) {
    final baseIconSize = ResponsiveUtils.getIconSize(context);
    
    switch (brand.toUpperCase()) {
      case 'SAMSUNG':
        return baseIconSize * 1.1;
      case 'NOTHING':
        return baseIconSize * 0.95;
      default:
        return baseIconSize;
    }
  }
  
  /// 鏍规嵁璁惧鍝佺墝鑾峰彇浼樺寲鐨勫瓧浣撴潈閲?
  static FontWeight getTitleFontWeightForBrand(String brand) {
    switch (brand.toUpperCase()) {
      case 'SAMSUNG':
        return FontWeight.w600;
      case 'XIAOMI':
        return FontWeight.w500;
      case 'NOTHING':
        return FontWeight.w400;
      default:
        return FontWeight.w600;
    }
  }
}
