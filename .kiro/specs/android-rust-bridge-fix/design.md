# Android Flutter-Rust Bridge Fix - Design Document

## Overview

This document outlines the design for fixing the Flutter-Rust Bridge initialization issue on Android. The core problem is that the native Rust library (`librust_lib_veloguard.so`) fails to load or initialize properly on Android devices.

## Architecture Analysis

### Current Library Loading Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        Android App Start                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  VeloGuardVpnService.kt (companion object init)                 │
│  System.loadLibrary("rust_lib_veloguard")                       │
│  - Loads librust_lib_veloguard.so from APK jniLibs              │
│  - May fail with UnsatisfiedLinkError                           │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  Flutter main.dart                                               │
│  await RustLib.init()                                           │
│  - Uses ExternalLibraryLoaderConfig                             │
│  - stem: 'rust_lib_veloguard'                                   │
│  - ioDirectory: 'rust/veloguard-lib/target/release/' (WRONG!)   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  flutter_rust_bridge package                                     │
│  - On Android: Uses ffi.DynamicLibrary.open() with library name │
│  - Ignores ioDirectory on Android (uses system library path)    │
│  - Library name: "librust_lib_veloguard.so"                     │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

1. **Rust Library (`rust/veloguard-lib/`)**
   - Cargo.toml: `name = "rust_lib_veloguard"`, `crate-type = ["cdylib"]`
   - Exports JNI functions via `#[no_mangle]` in `android_jni.rs`
   - Exports FFI functions via flutter_rust_bridge in `api.rs`

2. **Cargokit Build System (`rust_builder/`)**
   - Builds Rust library for Android using NDK
   - Places `.so` files in `build/jniLibs/${buildType}/`
   - Configured for `arm64-v8a` architecture only

3. **Android App (`android/app/`)**
   - `VeloGuardVpnService.kt`: Loads library in companion object
   - `MainActivity.kt`: Handles VPN permission and method channel
   - `build.gradle.kts`: ABI filters, JNI packaging config

4. **Flutter App (`lib/`)**
   - `main.dart`: Calls `RustLib.init()` on startup
   - `frb_generated.dart`: Generated FFI bindings
   - Providers: Check `isRustLibInitialized` before FFI calls

## Problem Analysis

### Issue 1: Library Not Found

The `ioDirectory` in `frb_generated.dart` points to a desktop build path:
```dart
ioDirectory: 'rust/veloguard-lib/target/release/'
```

However, on Android, flutter_rust_bridge should:
1. Ignore `ioDirectory` 
2. Use `DynamicLibrary.open("librust_lib_veloguard.so")` which loads from APK

**Verification needed**: Check if flutter_rust_bridge correctly handles Android library loading.

### Issue 2: Library Not Built

The cargokit build may not be running or may be failing silently.

**Verification needed**: 
- Check if `librust_lib_veloguard.so` exists in the APK
- Check build logs for Rust compilation errors

### Issue 3: JNI Symbol Mismatch

The JNI function names must exactly match between Kotlin and Rust:
- Kotlin: `private external fun nativeInitRustBridge()`
- Rust: `Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeInitRustBridge`

**Verification needed**: Check library symbols with `nm -D`

### Issue 4: Architecture Mismatch

The app only builds for `arm64-v8a`. If testing on an emulator (usually x86_64), the library won't load.

**Verification needed**: Check device architecture vs built library architecture

## Proposed Solutions

### Solution 1: Verify Library Inclusion in APK

Add a debug check to verify the library is in the APK:

```kotlin
// In MainActivity.kt or VeloGuardVpnService.kt
private fun checkNativeLibrary(): Boolean {
    val nativeLibDir = applicationInfo.nativeLibraryDir
    val libFile = File(nativeLibDir, "librust_lib_veloguard.so")
    Log.d(TAG, "Native lib dir: $nativeLibDir")
    Log.d(TAG, "Library exists: ${libFile.exists()}")
    Log.d(TAG, "Library size: ${if (libFile.exists()) libFile.length() else 0}")
    return libFile.exists()
}
```

### Solution 2: Improve Error Handling in Library Loading

Wrap `System.loadLibrary` with better error handling:

```kotlin
companion object {
    private var libraryLoaded = false
    
    init {
        try {
            System.loadLibrary("rust_lib_veloguard")
            libraryLoaded = true
            Log.d(TAG, "Native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load native library", e)
            libraryLoaded = false
        }
    }
    
    fun isLibraryLoaded(): Boolean = libraryLoaded
}
```

### Solution 3: Add x86_64 Architecture for Emulator Testing

Update `android/app/build.gradle.kts`:

```kotlin
ndk {
    abiFilters += listOf("arm64-v8a", "x86_64")
}
```

### Solution 4: Verify Cargokit Build

Add logging to cargokit build process and verify:
1. NDK is installed and configured
2. Rust toolchain has Android targets installed
3. Build completes without errors

### Solution 5: Flutter-Side Initialization Retry

Add retry logic in `main.dart`:

```dart
Future<bool> initRustLibWithRetry({int maxRetries = 3}) async {
  for (int i = 0; i < maxRetries; i++) {
    try {
      await RustLib.init();
      return true;
    } catch (e) {
      debugPrint('RustLib.init() attempt ${i + 1} failed: $e');
      if (i < maxRetries - 1) {
        await Future.delayed(Duration(milliseconds: 500));
      }
    }
  }
  return false;
}
```

## Implementation Plan

### Phase 1: Diagnostics
1. Add library existence check in Kotlin
2. Add detailed logging for library loading
3. Check APK contents for .so files
4. Verify device architecture

### Phase 2: Build Verification
1. Verify Rust Android targets are installed
2. Check cargokit build output
3. Verify library symbols

### Phase 3: Fix Implementation
1. Apply appropriate fix based on diagnostics
2. Add x86_64 support if needed for emulator
3. Improve error handling and user feedback

### Phase 4: Testing
1. Test on physical arm64 device
2. Test on x86