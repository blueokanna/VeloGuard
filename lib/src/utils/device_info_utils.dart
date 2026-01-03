import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:device_info_plus/device_info_plus.dart';

/// 设备信息工具类 - 用于识别手机型号并优化 UI
class DeviceInfoUtils {
  DeviceInfoUtils._();

  static final DeviceInfoPlugin _deviceInfo = DeviceInfoPlugin();
  static AndroidDeviceInfo? _androidInfo;
  static IosDeviceInfo? _iosInfo;
  static bool _initialized = false;
  static bool _isHarmonyOS = false;

  /// 初始化设备信息
  static Future<void> initialize() async {
    if (_initialized) return;

    try {
      if (Platform.isAndroid) {
        _androidInfo = await _deviceInfo.androidInfo;
        debugPrint(
          'Device Info: brand=${_androidInfo?.brand}, model=${_androidInfo?.model}, device=${_androidInfo?.device}',
        );

        // 检测是否为鸿蒙系统
        _isHarmonyOS = _checkHarmonyOS();
        if (_isHarmonyOS) {
          debugPrint('Detected HarmonyOS device');
        }
      } else if (Platform.isIOS) {
        _iosInfo = await _deviceInfo.iosInfo;
      }
      _initialized = true;
    } catch (e) {
      debugPrint('Failed to get device info: $e');
    }
  }

  /// 检测是否为鸿蒙系统
  static bool _checkHarmonyOS() {
    if (_androidInfo == null) return false;

    // 检查 display 字段是否包含 HarmonyOS 标识
    final display = _androidInfo!.display.toLowerCase();
    if (display.contains('harmonyos') || display.contains('hmos')) {
      return true;
    }

    // 检查 fingerprint 是否包含鸿蒙标识
    final fingerprint = _androidInfo!.fingerprint.toLowerCase();
    if (fingerprint.contains('harmonyos') || fingerprint.contains('hmos')) {
      return true;
    }

    return false;
  }

  /// 是否为鸿蒙系统
  static bool get isHarmonyOS => _isHarmonyOS;

  /// 获取设备品牌（标准化大写）
  static String get brand {
    if (Platform.isAndroid && _androidInfo != null) {
      return _androidInfo!.brand.toUpperCase();
    } else if (Platform.isIOS) {
      return 'APPLE';
    }
    return 'UNKNOWN';
  }

  /// 获取原始设备型号
  static String get rawModel {
    if (Platform.isAndroid && _androidInfo != null) {
      return _androidInfo!.model;
    } else if (Platform.isIOS && _iosInfo != null) {
      return _iosInfo!.model;
    }
    return 'Unknown';
  }

  /// 获取设备代号（device）
  static String get deviceCode {
    if (Platform.isAndroid && _androidInfo != null) {
      return _androidInfo!.device;
    }
    return '';
  }

  /// 获取产品名称
  static String get product {
    if (Platform.isAndroid && _androidInfo != null) {
      return _androidInfo!.product;
    }
    return '';
  }

  /// 获取友好的设备型号名称
  static String get model {
    if (Platform.isAndroid && _androidInfo != null) {
      final rawModel = _androidInfo!.model;
      final brand = _androidInfo!.brand.toUpperCase();
      final device = _androidInfo!.device.toLowerCase();

      // 尝试从型号映射表获取友好名称
      final friendlyName = _getDeviceFriendlyName(brand, rawModel, device);
      if (friendlyName != null) {
        return friendlyName;
      }

      // 如果没有映射，返回原始型号
      return rawModel;
    } else if (Platform.isIOS && _iosInfo != null) {
      return _iosInfo!.model;
    }
    return 'Unknown';
  }

  /// 获取设备完整名称
  static String get deviceName {
    if (Platform.isAndroid && _androidInfo != null) {
      return '${_androidInfo!.brand} $model';
    } else if (Platform.isIOS && _iosInfo != null) {
      return _iosInfo!.name;
    }
    return 'Unknown Device';
  }

  /// 获取 Android SDK 版本
  static int get androidSdkVersion {
    if (Platform.isAndroid && _androidInfo != null) {
      return _androidInfo!.version.sdkInt;
    }
    return 0;
  }

  /// 根据品牌、型号、设备代号获取友好名称
  static String? _getDeviceFriendlyName(
    String brand,
    String model,
    String device,
  ) {
    final modelUpper = model.toUpperCase();
    final deviceLower = device.toLowerCase();

    // OnePlus 设备映射
    if (brand == 'ONEPLUS') {
      return _onePlusModelMap[modelUpper] ??
          _onePlusDeviceMap[deviceLower] ??
          _matchOnePlusPattern(model, device);
    }

    // 小米设备映射
    if (brand == 'XIAOMI' || brand == 'REDMI' || brand == 'POCO') {
      return _xiaomiModelMap[modelUpper] ??
          _xiaomiDeviceMap[deviceLower] ??
          _matchXiaomiPattern(model, device);
    }

    // 华为设备映射
    if (brand == 'HUAWEI' || brand == 'HONOR') {
      return _huaweiModelMap[modelUpper] ??
          _huaweiDeviceMap[deviceLower] ??
          _matchHuaweiPattern(model, device);
    }

    // 三星设备映射
    if (brand == 'SAMSUNG') {
      return _samsungModelMap[modelUpper] ?? _matchSamsungPattern(model);
    }

    // Vivo 设备映射
    if (brand == 'VIVO' || brand == 'IQOO') {
      return _vivoModelMap[modelUpper] ?? _matchVivoPattern(model);
    }

    // OPPO 设备映射
    if (brand == 'OPPO') {
      return _oppoModelMap[modelUpper] ?? _matchOppoPattern(model);
    }

    // Realme 设备映射
    if (brand == 'REALME') {
      return _realmeModelMap[modelUpper] ?? _matchRealmePattern(model);
    }

    // Nothing 设备映射
    if (brand == 'NOTHING') {
      return _nothingModelMap[modelUpper] ?? _matchNothingPattern(model);
    }

    // Google Pixel 设备映射
    if (brand == 'GOOGLE') {
      return _pixelModelMap[modelUpper] ?? _matchPixelPattern(model);
    }

    return null;
  }

  // ============================================
  // OnePlus 型号映射
  // ============================================
  static const _onePlusModelMap = <String, String>{
    // OnePlus 12 系列
    'CPH2573': 'OnePlus 12',
    'CPH2575': 'OnePlus 12',
    'PHB110': 'OnePlus 12',
    // OnePlus 12R
    'CPH2609': 'OnePlus 12R',
    // OnePlus 13 系列
    'PJZ110': 'OnePlus 13',
    'CPH2653': 'OnePlus 13',
    'CPH2655': 'OnePlus 13',
    // OnePlus 13R
    'CPH2667': 'OnePlus 13R',
    // OnePlus Ace 系列
    'PGP110': 'OnePlus Ace 3',
    'PHQ110': 'OnePlus Ace 3 Pro',
    'PJD110': 'OnePlus Ace 3V',
    'PKL110': 'OnePlus Ace 5',
    'PKM110': 'OnePlus Ace 5 Pro',
    'PLA110': 'OnePlus Ace 6',
    'PLB110': 'OnePlus Ace 6T',
    // OnePlus Nord 系列
    'CPH2493': 'OnePlus Nord 3',
    'CPH2557': 'OnePlus Nord CE 3',
    'CPH2625': 'OnePlus Nord 4',
  };

  static const _onePlusDeviceMap = <String, String>{
    'op5958l1': 'OnePlus 12',
    'op5961l1': 'OnePlus 12R',
    'op5973l1': 'OnePlus 13',
  };

  static String? _matchOnePlusPattern(String model, String device) {
    final modelUpper = model.toUpperCase();
    // 匹配 PJZ110 这种格式 -> OnePlus 13
    if (modelUpper.startsWith('PJZ')) return 'OnePlus 13';
    if (modelUpper.startsWith('PHB')) return 'OnePlus 12';
    if (modelUpper.startsWith('PGP')) return 'OnePlus Ace 3';
    if (modelUpper.startsWith('PHQ')) return 'OnePlus Ace 3 Pro';
    if (modelUpper.startsWith('PJD')) return 'OnePlus Ace 3V';
    if (modelUpper.startsWith('PKL')) return 'OnePlus Ace 5';
    if (modelUpper.startsWith('PKM')) return 'OnePlus Ace 5 Pro';
    if (modelUpper.startsWith('PLA')) return 'OnePlus Ace 6';
    if (modelUpper.startsWith('PLB')) return 'OnePlus Ace 6T';
    if (modelUpper.startsWith('CPH26')) return 'OnePlus 13 Series';
    if (modelUpper.startsWith('CPH25')) return 'OnePlus 12 Series';
    return null;
  }

  // ============================================
  // 小米型号映射
  // ============================================
  static const _xiaomiModelMap = <String, String>{
    // Xiaomi 14 系列
    '23127PN0CC': 'Xiaomi 14',
    '23116PN5BC': 'Xiaomi 14 Pro',
    '24030PN60G': 'Xiaomi 14 Ultra',
    // Xiaomi 15 系列
    '24129PN74C': 'Xiaomi 15',
    '2412DPN60C': 'Xiaomi 15 Pro',
    '2501CPN6DC': 'Xiaomi 15 Ultra',
    // Xiaomi 13 系列
    '2211133C': 'Xiaomi 13',
    '2210132C': 'Xiaomi 13 Pro',
    '2304FPN6DC': 'Xiaomi 13 Ultra',
    // Xiaomi 12 系列
    '2201123C': 'Xiaomi 12',
    '2201122C': 'Xiaomi 12 Pro',
    '2206123SC': 'Xiaomi 12S Ultra',
    // Redmi 系列
    '23078RKD5C': 'Redmi K60',
    '23013RK75C': 'Redmi K60 Pro',
    '23078PND5G': 'Redmi K60 Ultra',
    '24069PC21G': 'Redmi K70',
    '23117RK66C': 'Redmi K70 Pro',
    '24078PK75C': 'Redmi K70 Ultra',
    '2409FPN8DC': 'Redmi K80',
    '24108PN74C': 'Redmi K80 Pro',
  };

  static const _xiaomiDeviceMap = <String, String>{
    'shennong': 'Xiaomi 14',
    'houji': 'Xiaomi 14 Pro',
    'aurora': 'Xiaomi 14 Ultra',
    'manet': 'Xiaomi 15',
    'haotian': 'Xiaomi 15 Pro',
  };

  static String? _matchXiaomiPattern(String model, String device) {
    final modelUpper = model.toUpperCase();
    // 匹配小米型号模式
    if (modelUpper.contains('2412') && modelUpper.contains('PN')) {
      return 'Xiaomi 15 Series';
    }
    if (modelUpper.contains('2411') && modelUpper.contains('PN')) {
      return 'Xiaomi 15 Series';
    }
    if (modelUpper.contains('2312') && modelUpper.contains('PN')) {
      return 'Xiaomi 14 Series';
    }
    if (modelUpper.contains('2211') && modelUpper.contains('C')) {
      return 'Xiaomi 13 Series';
    }
    if (modelUpper.contains('2201') && modelUpper.contains('C')) {
      return 'Xiaomi 12 Series';
    }
    // Redmi K 系列
    if (modelUpper.contains('RK') && modelUpper.contains('C')) {
      return 'Redmi K Series';
    }
    return null;
  }

  // ============================================
  // 华为型号映射（包含鸿蒙设备）
  // ============================================
  static const _huaweiModelMap = <String, String>{
    // Mate 70 系列 (HarmonyOS NEXT)
    'BRQ-AN00': 'HUAWEI Mate 70',
    'BRQ-AN10': 'HUAWEI Mate 70 Pro',
    'BRQ-AN20': 'HUAWEI Mate 70 Pro+',
    'BRQ-AN30': 'HUAWEI Mate 70 RS',
    // Mate 60 系列 (HarmonyOS)
    'BRA-AL00': 'HUAWEI Mate 60',
    'ALN-AL00': 'HUAWEI Mate 60 Pro',
    'ALN-AL10': 'HUAWEI Mate 60 Pro+',
    'GGS-AN00': 'HUAWEI Mate 60 RS',
    // Mate X 系列
    'PAL-AL00': 'HUAWEI Mate X5',
    'PAL-AL10': 'HUAWEI Mate X5 典藏版',
    'ALT-AL10': 'HUAWEI Mate X3',
    // Mate 50 系列
    'CET-AL00': 'HUAWEI Mate 50',
    'DCO-AL00': 'HUAWEI Mate 50 Pro',
    'DCO-AL10': 'HUAWEI Mate 50 RS',
    // Mate 40 系列
    'ALT-AL00': 'HUAWEI Mate 40',
    'NOH-AN00': 'HUAWEI Mate 40 Pro',
    'NOH-AN01': 'HUAWEI Mate 40 Pro+',
    'NOP-AN00': 'HUAWEI Mate 40 RS',
    // Mate 30 系列
    'TAS-AN00': 'HUAWEI Mate 30',
    'LIO-AN00': 'HUAWEI Mate 30 Pro',
    // Mate 20 系列
    'HMA-AL00': 'HUAWEI Mate 20',
    'LYA-AL00': 'HUAWEI Mate 20 Pro',
    // Mate 10 系列
    'ALP-AL00': 'HUAWEI Mate 10',
    'BLA-AL00': 'HUAWEI Mate 10 Pro',
    // Pura 系列 (原 P 系列)
    'HBN-AL00': 'HUAWEI Pura 70',
    'HBN-AL10': 'HUAWEI Pura 70 Pro',
    'HBN-AL20': 'HUAWEI Pura 70 Pro+',
    'HBN-LX9': 'HUAWEI Pura 70 Ultra',
    // P60 系列
    'MNA-AL00': 'HUAWEI P60',
    'MNA-AL10': 'HUAWEI P60 Pro',
    'LNA-AL00': 'HUAWEI P60 Art',
    // P50 系列
    'ABR-AL00': 'HUAWEI P50',
    'JAD-AL00': 'HUAWEI P50 Pro',
    'JAD-AL50': 'HUAWEI P50 Pocket',
    // P40 系列
    'ANA-AN00': 'HUAWEI P40',
    'ELS-AN00': 'HUAWEI P40 Pro',
    'ELS-AN10': 'HUAWEI P40 Pro+',
    // P30 系列
    'ELE-AL00': 'HUAWEI P30',
    'VOG-AL00': 'HUAWEI P30 Pro',
    // Nova 系列
    'FMG-AN00': 'HUAWEI nova 13',
    'FMG-AN10': 'HUAWEI nova 13 Pro',
    'BNE-AL00': 'HUAWEI nova 12',
    'FOA-AL00': 'HUAWEI nova 12 Pro',
    // 荣耀系列 (HONOR)
    'REP-AN00': 'HONOR Magic7',
    'REP-AN10': 'HONOR Magic7 Pro',
    'REP-AN20': 'HONOR Magic7 RSR',
    'PGT-AN00': 'HONOR Magic6',
    'PGT-AN10': 'HONOR Magic6 Pro',
    'PGT-AN20': 'HONOR Magic6 RSR',
  };

  static const _huaweiDeviceMap = <String, String>{
    'noah': 'HUAWEI Mate 40 Pro',
    'elsa': 'HUAWEI P40 Pro',
    'bale': 'HUAWEI Mate 60',
    'aln': 'HUAWEI Mate 60 Pro',
    'brq': 'HUAWEI Mate 70',
  };

  static String? _matchHuaweiPattern(String model, String device) {
    final modelUpper = model.toUpperCase();
    // Mate 70 系列
    if (modelUpper.contains('BRQ')) {
      return 'HUAWEI Mate 70 Series';
    }
    // Mate 60 系列
    if (modelUpper.contains('BRA') ||
        modelUpper.contains('ALN') ||
        modelUpper.contains('GGS')) {
      return 'HUAWEI Mate 60 Series';
    }
    // Mate X 系列
    if (modelUpper.contains('PAL')) {
      return 'HUAWEI Mate X5';
    }
    // Mate 50 系列
    if (modelUpper.contains('CET') || modelUpper.contains('DCO')) {
      return 'HUAWEI Mate 50 Series';
    }
    // Mate 40 系列
    if (modelUpper.contains('NOH') || modelUpper.contains('NOP')) {
      return 'HUAWEI Mate 40 Series';
    }
    if (modelUpper.contains('TAS') || modelUpper.contains('LIO')) {
      return 'HUAWEI Mate 30 Series';
    }
    if (modelUpper.contains('HMA') || modelUpper.contains('LYA')) {
      return 'HUAWEI Mate 20 Series';
    }
    // Pura 系列
    if (modelUpper.contains('HBN')) {
      return 'HUAWEI Pura 70 Series';
    }
    // P60 系列
    if (modelUpper.contains('MNA') || modelUpper.contains('LNA')) {
      return 'HUAWEI P60 Series';
    }
    // P50 系列
    if (modelUpper.contains('ABR') || modelUpper.contains('JAD')) {
      return 'HUAWEI P50 Series';
    }
    if (modelUpper.contains('ANA') || modelUpper.contains('ELS')) {
      return 'HUAWEI P40 Series';
    }
    if (modelUpper.contains('ELE') || modelUpper.contains('VOG')) {
      return 'HUAWEI P30 Series';
    }
    // Nova 系列
    if (modelUpper.contains('FMG')) {
      return 'HUAWEI nova 13 Series';
    }
    // HONOR Magic 系列
    if (modelUpper.contains('REP')) {
      return 'HONOR Magic7 Series';
    }
    if (modelUpper.contains('PGT')) {
      return 'HONOR Magic6 Series';
    }
    return null;
  }

  // ============================================
  // 三星型号映射
  // ============================================
  static const _samsungModelMap = <String, String>{
    // S25 系列
    'SM-S931B': 'Galaxy S25',
    'SM-S936B': 'Galaxy S25+',
    'SM-S938B': 'Galaxy S25 Ultra',
    // S24 系列
    'SM-S921B': 'Galaxy S24',
    'SM-S926B': 'Galaxy S24+',
    'SM-S928B': 'Galaxy S24 Ultra',
    // S23 系列
    'SM-S911B': 'Galaxy S23',
    'SM-S916B': 'Galaxy S23+',
    'SM-S918B': 'Galaxy S23 Ultra',
    // S22 系列
    'SM-S901B': 'Galaxy S22',
    'SM-S906B': 'Galaxy S22+',
    'SM-S908B': 'Galaxy S22 Ultra',
    // S21 系列
    'SM-G991B': 'Galaxy S21',
    'SM-G996B': 'Galaxy S21+',
    'SM-G998B': 'Galaxy S21 Ultra',
    // S20 系列
    'SM-G981B': 'Galaxy S20',
    'SM-G986B': 'Galaxy S20+',
    'SM-G988B': 'Galaxy S20 Ultra',
    // Note 系列
    'SM-N986B': 'Galaxy Note 20 Ultra',
    'SM-N981B': 'Galaxy Note 20',
    // Fold 系列
    'SM-F956B': 'Galaxy Z Fold 6',
    'SM-F946B': 'Galaxy Z Fold 5',
    // Flip 系列
    'SM-F741B': 'Galaxy Z Flip 6',
    'SM-F731B': 'Galaxy Z Flip 5',
  };

  static String? _matchSamsungPattern(String model) {
    final modelUpper = model.toUpperCase();
    // S 系列匹配
    if (modelUpper.startsWith('SM-S93')) return 'Galaxy S25 Series';
    if (modelUpper.startsWith('SM-S92')) return 'Galaxy S24 Series';
    if (modelUpper.startsWith('SM-S91')) return 'Galaxy S23 Series';
    if (modelUpper.startsWith('SM-S90')) return 'Galaxy S22 Series';
    if (modelUpper.startsWith('SM-G99')) return 'Galaxy S21 Series';
    if (modelUpper.startsWith('SM-G98')) return 'Galaxy S20 Series';
    // Note 系列
    if (modelUpper.startsWith('SM-N98')) return 'Galaxy Note 20 Series';
    // Fold 系列
    if (modelUpper.startsWith('SM-F9')) return 'Galaxy Z Fold Series';
    // Flip 系列
    if (modelUpper.startsWith('SM-F7')) return 'Galaxy Z Flip Series';
    return null;
  }

  // ============================================
  // Vivo 型号映射
  // ============================================
  static const _vivoModelMap = <String, String>{
    // X 系列
    'V2309A': 'vivo X100',
    'V2314A': 'vivo X100 Pro',
    'V2316A': 'vivo X100 Ultra',
    'V2318A': 'vivo X100s',
    'V2324A': 'vivo X200',
    'V2325A': 'vivo X200 Pro',
    'V2326A': 'vivo X200 Pro Mini',
    // iQOO 系列
    'V2254A': 'iQOO 12',
    'V2255A': 'iQOO 12 Pro',
    'V2302A': 'iQOO Neo 9',
    'V2303A': 'iQOO Neo 9 Pro',
  };

  static String? _matchVivoPattern(String model) {
    final modelUpper = model.toUpperCase();
    if (modelUpper.startsWith('V232')) return 'vivo X200 Series';
    if (modelUpper.startsWith('V231')) return 'vivo X100 Series';
    if (modelUpper.startsWith('V230')) return 'vivo X100 Series';
    if (modelUpper.startsWith('V225')) return 'iQOO 12 Series';
    return null;
  }

  // ============================================
  // OPPO 型号映射
  // ============================================
  static const _oppoModelMap = <String, String>{
    // Find X 系列
    'PHY110': 'OPPO Find X7',
    'PHZ110': 'OPPO Find X7 Ultra',
    'PKG110': 'OPPO Find X8',
    'PKH110': 'OPPO Find X8 Pro',
    // Find N 系列
    'PHN110': 'OPPO Find N3',
    'PGU110': 'OPPO Find N3 Flip',
    // Reno 系列
    'PJC110': 'OPPO Reno 12',
    'PJD110': 'OPPO Reno 12 Pro',
  };

  static String? _matchOppoPattern(String model) {
    final modelUpper = model.toUpperCase();
    if (modelUpper.startsWith('PKG') || modelUpper.startsWith('PKH')) {
      return 'OPPO Find X8 Series';
    }
    if (modelUpper.startsWith('PHY') || modelUpper.startsWith('PHZ')) {
      return 'OPPO Find X7 Series';
    }
    if (modelUpper.startsWith('PHN') || modelUpper.startsWith('PGU')) {
      return 'OPPO Find N3 Series';
    }
    return null;
  }

  // ============================================
  // Realme 型号映射
  // ============================================
  static const _realmeModelMap = <String, String>{
    // GT 系列
    'RMX3888': 'realme GT 5 Pro',
    'RMX3820': 'realme GT 5',
    'RMX3800': 'realme GT 6',
    'RMX3851': 'realme GT 6T',
    // 数字系列
    'RMX3761': 'realme 12 Pro+',
    'RMX3760': 'realme 12 Pro',
    'RMX3840': 'realme 13 Pro+',
    'RMX3841': 'realme 13 Pro',
  };

  static String? _matchRealmePattern(String model) {
    final modelUpper = model.toUpperCase();
    if (modelUpper.startsWith('RMX38')) return 'realme GT/13 Series';
    if (modelUpper.startsWith('RMX37')) return 'realme 12 Series';
    if (modelUpper.startsWith('RMX36')) return 'realme 11 Series';
    return null;
  }

  // ============================================
  // Nothing 型号映射
  // ============================================
  static const _nothingModelMap = <String, String>{
    'A063': 'Nothing Phone (1)',
    'A065': 'Nothing Phone (2)',
    'A142': 'Nothing Phone (2a)',
    'A143': 'Nothing Phone (2a) Plus',
    'A059': 'Nothing Phone (3)',
    'A155': 'Nothing Phone (3a)',
    'A156': 'Nothing Phone (3a) Pro',
  };

  static String? _matchNothingPattern(String model) {
    final modelUpper = model.toUpperCase();
    if (modelUpper.startsWith('A06')) return 'Nothing Phone Series';
    if (modelUpper.startsWith('A14')) return 'Nothing Phone (2a) Series';
    if (modelUpper.startsWith('A15')) return 'Nothing Phone (3a) Series';
    return null;
  }

  // ============================================
  // Google Pixel 型号映射
  // ============================================
  static const _pixelModelMap = <String, String>{
    'GVU6C': 'Pixel 9',
    'GWKK3': 'Pixel 9 Pro',
    'G1MNW': 'Pixel 9 Pro XL',
    'GP4BC': 'Pixel 8',
    'GC3VE': 'Pixel 8 Pro',
    'GKWS6': 'Pixel 7',
    'GE2AE': 'Pixel 7 Pro',
    'GR1YH': 'Pixel 6',
    'G8VOU': 'Pixel 6 Pro',
  };

  static String? _matchPixelPattern(String model) {
    final modelUpper = model.toUpperCase();
    if (modelUpper.contains('PIXEL 9')) return 'Pixel 9 Series';
    if (modelUpper.contains('PIXEL 8')) return 'Pixel 8 Series';
    if (modelUpper.contains('PIXEL 7')) return 'Pixel 7 Series';
    if (modelUpper.contains('PIXEL 6')) return 'Pixel 6 Series';
    return null;
  }

  // ============================================
  // 品牌检测方法
  // ============================================

  /// 是否为华为设备
  static bool get isHuawei {
    return brand == 'HUAWEI' || brand == 'HONOR';
  }

  /// 是否为小米设备
  static bool get isXiaomi {
    return brand == 'XIAOMI' || brand == 'REDMI' || brand == 'POCO';
  }

  /// 是否为 OnePlus 设备
  static bool get isOnePlus {
    return brand == 'ONEPLUS';
  }

  /// 是否为 Vivo 设备
  static bool get isVivo {
    return brand == 'VIVO' || brand == 'IQOO';
  }

  /// 是否为 OPPO 设备
  static bool get isOppo {
    return brand == 'OPPO';
  }

  /// 是否为三星设备
  static bool get isSamsung {
    return brand == 'SAMSUNG';
  }

  /// 是否为 Nothing 设备
  static bool get isNothing {
    return brand == 'NOTHING';
  }

  /// 是否为 Realme 设备
  static bool get isRealme {
    return brand == 'REALME';
  }

  /// 是否为 Google Pixel 设备
  static bool get isPixel {
    return brand == 'GOOGLE';
  }

  /// 获取设备制造商类型
  static DeviceManufacturer get manufacturer {
    if (isHuawei) return DeviceManufacturer.huawei;
    if (isXiaomi) return DeviceManufacturer.xiaomi;
    if (isOnePlus) return DeviceManufacturer.onePlus;
    if (isVivo) return DeviceManufacturer.vivo;
    if (isOppo) return DeviceManufacturer.oppo;
    if (isSamsung) return DeviceManufacturer.samsung;
    if (isNothing) return DeviceManufacturer.nothing;
    if (isRealme) return DeviceManufacturer.realme;
    if (isPixel) return DeviceManufacturer.google;
    return DeviceManufacturer.other;
  }

  // ============================================
  // UI 优化参数
  // ============================================

  /// 获取推荐的圆角半径（基于设备品牌风格）
  static double getRecommendedBorderRadius() {
    switch (manufacturer) {
      case DeviceManufacturer.samsung:
        return 20.0; // Samsung One UI 风格
      case DeviceManufacturer.xiaomi:
        return 16.0; // MIUI 风格
      case DeviceManufacturer.huawei:
        return 18.0; // EMUI/HarmonyOS 风格
      case DeviceManufacturer.onePlus:
        return 16.0; // OxygenOS 风格
      case DeviceManufacturer.vivo:
        return 14.0; // OriginOS 风格
      case DeviceManufacturer.oppo:
        return 14.0; // ColorOS 风格
      case DeviceManufacturer.nothing:
        return 12.0; // Nothing OS 风格（更方正）
      case DeviceManufacturer.google:
        return 16.0; // Material You 风格
      default:
        return 16.0;
    }
  }

  /// 获取推荐的卡片内边距
  static double getRecommendedCardPadding() {
    switch (manufacturer) {
      case DeviceManufacturer.samsung:
        return 16.0;
      case DeviceManufacturer.xiaomi:
        return 14.0;
      case DeviceManufacturer.huawei:
        return 16.0;
      case DeviceManufacturer.onePlus:
        return 14.0;
      case DeviceManufacturer.nothing:
        return 12.0;
      default:
        return 14.0;
    }
  }

  /// 获取推荐的图标大小
  static double getRecommendedIconSize() {
    switch (manufacturer) {
      case DeviceManufacturer.samsung:
        return 26.0;
      case DeviceManufacturer.xiaomi:
        return 24.0;
      case DeviceManufacturer.huawei:
        return 24.0;
      case DeviceManufacturer.nothing:
        return 22.0;
      default:
        return 24.0;
    }
  }

  /// 是否支持高刷新率
  static bool get supportsHighRefreshRate {
    if (Platform.isAndroid && _androidInfo != null) {
      final modelLower = model.toLowerCase();
      // 检查是否为旗舰机型
      if (modelLower.contains('pro') ||
          modelLower.contains('ultra') ||
          modelLower.contains('plus') ||
          modelLower.contains('note')) {
        return true;
      }
      // 检查品牌的高端系列
      if (isOnePlus || isPixel) return true;
      if (isSamsung && modelLower.contains('s2')) return true;
    }
    return false;
  }

  /// 是否支持 LTPO（动态刷新率）
  static bool get supportsLtpo {
    if (Platform.isAndroid && _androidInfo != null) {
      final modelLower = model.toLowerCase();
      // LTPO 通常在 Ultra/Pro 机型上
      if (modelLower.contains('ultra') ||
          (modelLower.contains('pro') && !modelLower.contains('lite'))) {
        if (isSamsung) return true;
        if (isOnePlus) return true;
        if (isXiaomi &&
            (modelLower.contains('13') ||
                modelLower.contains('14') ||
                modelLower.contains('15'))) {
          return true;
        }
      }
    }
    return false;
  }

  /// 获取设备信息摘要
  static Map<String, dynamic> getDeviceSummary() {
    return {
      'brand': brand,
      'rawModel': rawModel,
      'model': model,
      'deviceCode': deviceCode,
      'deviceName': deviceName,
      'manufacturer': manufacturer.name,
      'androidSdkVersion': androidSdkVersion,
      'supportsHighRefreshRate': supportsHighRefreshRate,
      'supportsLtpo': supportsLtpo,
    };
  }
}

/// 设备制造商枚举
enum DeviceManufacturer {
  huawei,
  xiaomi,
  onePlus,
  vivo,
  oppo,
  samsung,
  nothing,
  realme,
  google,
  other,
}
