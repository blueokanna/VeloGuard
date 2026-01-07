# Android Flutter-Rust Bridge Fix - Implementation Tasks

## Task 1: Add Diagnostic Logging to Android Native Library Loading

**Status**: pending

**Description**: Add comprehensive logging to understand why the native library fails to load.

**Files to modify**:
- `android/app/src/main/kotlin/com/blueokanna/veloguard/VeloGuardVpnService.kt`
- `android/app/src/main/kotlin/com/blueokanna/veloguard/MainActivity.kt`

**Implementation**:
1. Add a method to check if the native library file exists in the APK
2. Log the native library directory path
3. Log the library loading result with detailed error information
4. Expose library loading status to Flutter via method channel

**Acceptance Criteria**:
- [ ] Library existence check logs the file path and size
- [ ] UnsatisfiedLinkError is caught and logged with full stack trace
- [ ] Library loading status is accessible from Flutter

---

## Task 2: Add x86_64 Architecture Support for Emulator Testing

**Status**: pending

**Description**: Add x86_64 architecture to ABI filters to enable testing on Android emulators.

**Files to modify**:
- `android/app/build.gradle.kts`

**Implementation**:
```kotlin
ndk {
    abiFilters += listOf("arm64-v8a", "x86_64")
}
```

**Acceptance Criteria**:
- [x] Build succeeds with both architectures
- [ ] Library loads on x86_64 emulator
- [x] Library loads on arm64 physical device

---

## Task 3: Verify Rust Android Toolchain Setup

**Status**: pending

**Description**: Ensure Rust toolchain has Android targets installed and NDK is configured.

**Commands to run**:
```bash
# Check installed targets
rustup target list --installed

# Add Android targets if missing
rustup target add aarch64-linux-android
rustup target add x86_64-linux-android

# Verify NDK path
echo $ANDROID_NDK_HOME
```

**Acceptance Criteria**:
- [x] `aarch64-linux-android` target is installed
- [x] `x86_64-linux-android` and `aarch64-linux-android` target is installed (if adding x86_64 support)
- [x] NDK path is correctly set

---

## Task 4: Improve Flutter RustLib Initialization

**Status**: pending

**Description**: Add retry logic and better error handling for RustLib initialization.

**Files to modify**:
- `lib/main.dart`

**Implementation**:
```dart
Future<bool> _initRustLibWithRetry({int maxRetries = 3}) async {
  for (int i = 0; i < maxRetries; i++) {
    try {
      await RustLib.init();
      isRustLibInitialized = true;
      debugPrint('RustLib initialized successfully on attempt ${i + 1}');
      return true;
    } catch (e, stackTrace) {
      debugPrint('RustLib.init() attempt ${i + 1} failed: $e');
      debugPrint('Stack trace: $stackTrace');
      if (i < maxRetries - 1) {
        await Future.delayed(const Duration(milliseconds: 500));
      }
    }
  }
  isRustLibInitialized = false;
  return false;
}
```

**Acceptance Criteria**:
- [x] Initialization retries up to 3 times
- [x] Each failure is logged with stack trace
- [x] `isRustLibInitialized` is correctly set

---

## Task 5: Add Method Channel for Library Status

**Status**: complete

**Description**: Add a method channel call to check native library status from Flutter.

**Files to modify**:
- `android/app/src/main/kotlin/com/blueokanna/veloguard/MainActivity.kt`
- `lib/src/services/native_service.dart` (new file or existing)

**Implementation**:
Add method channel handler:
```kotlin
"isNativeLibraryLoaded" -> {
    result.success(VeloGuardVpnService.isLibraryLoaded())
}
"getNativeLibraryInfo" -> {
    result.success(mapOf(
        "loaded" to VeloGuardVpnService.isLibraryLoaded(),
        "path" to applicationInfo.nativeLibraryDir,
        "architecture" to Build.SUPPORTED_ABIS.toList()
    ))
}
```

**Acceptance Criteria**:
- [x] Flutter can query native library loading status
- [x] Library path and architecture info is available
- [x] Error details are accessible if loading failed

---

## Task 6: Verify JNI Function Exports

**Status**: complete

**Description**: Verify that JNI functions are correctly exported from the Rust library.

**Files to check**:
- `rust/veloguard-lib/src/android_jni.rs`

**Verification**:
After building, check library symbols:
```bash
# Find the built library
find . -name "librust_lib_veloguard.so" -type f

# Check JNI symbols
nm -D librust_lib_veloguard.so | grep Java_
```

Expected symbols:
- `Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeInitRustBridge`
- `Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeClearRustBridge`

**Acceptance Criteria**:
- [x] Both JNI functions are exported
- [x] Function names match exactly with Kotlin declarations

**Verification Results** (verified on 2026-01-06):
```
llvm-nm -D output:
00000000003c513c T Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeClearRustBridge
00000000003c56a4 T Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeInitRustBridge
```
Both symbols are exported with type `T` (text/code section, globally visible).

---

## Task 7: Add User-Facing Error Message

**Status**: complete

**Description**: Show a user-friendly error message when the Rust library fails to load.

**Files to modify**:
- `lib/main.dart`
- `lib/src/widgets/rust_init_error_dialog.dart` (new file)

**Implementation**:
Create a dialog that shows when `isRustLibInitialized` is false:
- Explain that some features won't work
- Suggest possible solutions (update app, check device compatibility)
- Allow user to continue with limited functionality

**Acceptance Criteria**:
- [x] Error dialog appears when library fails to load
- [x] Message is clear and actionable
- [x] User can dismiss and continue using the app

**Implementation Details** (completed on 2026-01-06):
- Created `lib/src/widgets/rust_init_error_dialog.dart` with:
  - User-friendly error message explaining the issue
  - List of affected features (VPN, Proxy, Profile activation)
  - Suggestions for resolution (restart, update, check compatibility)
  - "Retry" button to attempt re-initialization
  - "Continue Anyway" button to use app with limited functionality
- Updated `lib/main.dart` to:
  - Convert VeloGuardApp to StatefulWidget
  - Show error dialog after first frame if RustLib failed to initialize
  - Support retry functionality from the dialog
  - Use global navigator key for dialog context
- Added localization strings for all dialog text in `lib/src/l10n/app_localizations.dart`

---

## Task 8: Test on Physical Device

**Status**: pending

**Description**: Test the fix on a physical Android device with arm64 architecture.

**Test cases**:
1. Fresh install - library loads on first launch
2. App update - library loads after update
3. Profile selection - works after library loads
4. VPN connection - JNI bridge initializes correctly

**Acceptance Criteria**:
- [ ] All test cases pass on physical device
- [ ] No "flutter_rust_bridge has not been initialized" errors
- [ ] Profile selection works correctly
- [ ] VPN service starts and protects sockets

---

## Task 9: Clean Up Initialization Checks

**Status**: pending

**Description**: Review and clean up the `isRustLibInitialized` checks added in previous session.

**Files to review**:
- `lib/src/providers/profiles_provider.dart`
- `lib/src/providers/app_state_provider.dart`
- `lib/src/providers/proxies_provider.dart`
- `lib/src/screens/logs_screen.dart`

**Implementation**:
- Ensure checks are consistent across all files
- Add proper error handling and user feedback
- Consider using a centralized service for Rust library status

**Acceptance Criteria**:
- [ ] All FFI calls are guarded by initialization check
- [ ] Error messages are consistent
- [ ] No duplicate or redundant checks

---

## Priority Order

1. **Task 3**: Verify Rust Android Toolchain Setup (prerequisite)
2. **Task 2**: Add x86_64 Architecture Support (if testing on emulator)
3. **Task 1**: Add Diagnostic Logging
4. **Task 6**: Verify JNI Function Exports
5. **Task 4**: Improve Flutter RustLib Initialization
6. **Task 5**: Add Method Channel for Library Status
7. **Task 7**: Add User-Facing Error Message
8. **Task 8**: Test on Physical Device
9. **Task 9**: Clean Up Initialization Checks
