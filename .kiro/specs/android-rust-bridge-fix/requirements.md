# Android Flutter-Rust Bridge Initialization Fix

## Problem Statement

The VeloGuard Android app fails to initialize the Flutter-Rust Bridge, resulting in:
1. Profile selection not working
2. Error: "flutter_rust_bridge has not been initialized. Did you forget to call `await RustLib.init();`?"
3. After adding initialization checks, shows "Rust library not initialized"

## Root Cause Analysis

The native library `librust_lib_veloguard.so` is failing to load on Android. Key findings:

1. **Dual Loading Mechanism**: The library is loaded in two places:
   - `VeloGuardVpnService.kt` companion object: `System.loadLibrary("rust_lib_veloguard")`
   - Flutter Rust Bridge: `RustLib.init()` which uses `ExternalLibraryLoaderConfig`

2. **Incorrect ioDirectory Path**: The `frb_generated.dart` has:
   ```dart
   ioDirectory: 'rust/veloguard-lib/target/release/'
   ```
   This path is for desktop builds, not Android. On Android, the library should be loaded from the APK's jniLibs.

3. **Build Configuration**: The cargokit plugin builds the library and places it in `jniLibs/${buildType}` directory, which should be correct.

4. **Potential Issues**:
   - Library may not be built for the correct architecture (only `arm64-v8a` is configured)
   - JNI function names may not match between Kotlin and Rust
   - Library loading order/timing issues between VpnService and Flutter

## User Stories

### US-1: Native Library Loading
As a user, I want the Rust native library to load successfully on Android so that I can use all app features.

**Acceptance Criteria:**
- [ ] AC-1.1: `System.loadLibrary("rust_lib_veloguard")` succeeds without `UnsatisfiedLinkError`
- [ ] AC-1.2: `RustLib.init()` completes successfully
- [ ] AC-1.3: `isRustLibInitialized` flag is set to `true` after initialization
- [ ] AC-1.4: No "flutter_rust_bridge has not been initialized" errors appear

### US-2: Profile Selection
As a user, I want to select and activate profiles on Android so that I can configure my VPN connection.

**Acceptance Criteria:**
- [ ] AC-2.1: Profile list loads and displays correctly
- [ ] AC-2.2: Selecting a profile triggers `initializeVeloguard()` or `startProxyFromYaml()`
- [ ] AC-2.3: Profile activation completes without errors
- [ ] AC-2.4: VPN service starts with the selected profile configuration

### US-3: VPN Service Integration
As a user, I want the VPN service to properly integrate with the Rust library so that network traffic is handled correctly.

**Acceptance Criteria:**
- [ ] AC-3.1: JNI bridge initializes when VPN service starts (`nativeInitRustBridge()`)
- [ ] AC-3.2: Socket protection callback works (`protect_socket_via_jni`)
- [ ] AC-3.3: VPN file descriptor is passed to Rust correctly
- [ ] AC-3.4: JNI bridge clears properly when VPN stops (`nativeClearRustBridge()`)

### US-4: Error Handling and Recovery
As a user, I want graceful error handling when the Rust library fails to load so that the app doesn't crash.

**Acceptance Criteria:**
- [ ] AC-4.1: App continues to run even if Rust library fails to load
- [ ] AC-4.2: User sees a clear error message explaining the issue
- [ ] AC-4.3: Features that require Rust are disabled with appropriate UI feedback
- [ ] AC-4.4: Retry mechanism available for library initialization

## Technical Requirements

### TR-1: Library Build Verification
- Verify `.so` file is generated for `arm64-v8a` architecture
- Verify library is included in the APK under `lib/arm64-v8a/librust_lib_veloguard.so`
- Verify library exports required JNI symbols

### TR-2: JNI Function Naming
- Verify JNI function names match between Kotlin and Rust:
  - `Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeInitRustBridge`
  - `Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeClearRustBridge`

### TR-3: Flutter Rust Bridge Configuration
- Verify `ExternalLibraryLoaderConfig` works correctly on Android
- The `ioDirectory` path should be ignored on Android (library loaded from APK)
- Ensure `stem: 'rust_lib_veloguard'` matches the actual library name

### TR-4: Initialization Order
- Ensure library is loaded before any FFI calls
- Handle case where VpnService loads library before Flutter
- Prevent double-loading issues

## Files to Investigate/Modify

1. `rust/veloguard-lib/Cargo.toml` - Library name configuration
2. `rust/veloguard-lib/src/android_jni.rs` - JNI function exports
3. `rust/veloguard-lib/src/lib.rs` - Library entry point
4. `lib/main.dart` - RustLib.init() call
5. `lib/src/rust/frb_generated.dart` - ExternalLibraryLoaderConfig
6. `android/app/src/main/kotlin/.../VeloGuardVpnService.kt` - Native library loading
7. `android/app/build.gradle.kts` - ABI filters and build config
8. `rust_builder/android/build.gradle` - Cargokit configuration
9. `flutter_rust_bridge.yaml` - FRB codegen configuration

## Debugging Steps

1. Check if `.so` file exists in APK: `unzip -l app.apk | grep .so`
2. Check library symbols: `nm -D librust_lib_veloguard.so | grep Java_`
3. Check Android logcat for loading errors: `adb logcat | grep -E "(VeloGuard|rust_lib|UnsatisfiedLinkError)"`
4. Verify architecture: `file librust_lib_veloguard.so`
