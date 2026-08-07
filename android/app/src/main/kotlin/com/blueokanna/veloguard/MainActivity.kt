package com.blueokanna.veloguard

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.Manifest
import android.content.pm.PackageManager
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.net.toUri
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.*
import java.io.File

class MainActivity : FlutterActivity() {
    companion object {
        private const val TAG = "VeloGuardMainActivity"
        private const val CHANNEL = "com.veloguard/proxy"
        private const val VPN_REQUEST_CODE = 1001
        private const val NOTIFICATION_PERMISSION_CODE = 1002
    }
    
    private var methodChannel: MethodChannel? = null
    private var pendingVpnResult: MethodChannel.Result? = null
    private var pendingProxyMode: String = "rule"
    private val mainScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermission()
    }
    
    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) 
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    NOTIFICATION_PERMISSION_CODE
                )
            }
        }
    }
    
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        Log.d(TAG, "configureFlutterEngine called")
        
        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        
        methodChannel?.setMethodCallHandler { call, result ->
            Log.d(TAG, "Method called: ${call.method}")
            
            when (call.method) {
                "startVpn" -> {
                    val mode = call.argument<String>("mode") ?: "rule"
                    startVpnService(result, mode)
                }
                "stopVpn" -> {
                    stopVpnService()
                    result.success(true)
                }
                "resetVpnState" -> {
                    Log.d(TAG, "Resetting VPN state...")
                    VeloGuardVpnService.resetAllState()
                    result.success(true)
                }
                "isVpnRunning" -> {
                    result.success(VeloGuardVpnService.isRunning)
                }
                "isOtherVpnActive" -> {
                    result.success(isOtherVpnActive())
                }
                "getVpnFd" -> {
                    result.success(VeloGuardVpnService.vpnFd)
                }
                "setProxyMode" -> {
                    val mode = call.argument<String>("mode") ?: "rule"
                    val proxyMode = when (mode.lowercase()) {
                        "global" -> VeloGuardVpnService.ProxyMode.GLOBAL
                        "direct" -> VeloGuardVpnService.ProxyMode.DIRECT
                        else -> VeloGuardVpnService.ProxyMode.RULE
                    }
                    VeloGuardVpnService.setProxyMode(proxyMode)
                    result.success(true)
                }
                "getProxyMode" -> {
                    result.success(VeloGuardVpnService.proxyMode.name.lowercase())
                }
                "getInstalledApps" -> {
                    result.success(getInstalledApps())
                }
                "getDeviceInfo" -> {
                    result.success(getDeviceInfo())
                }
                "isNativeLibraryLoaded" -> {
                    result.success(VeloGuardVpnService.isLibraryLoaded)
                }
                "installApk" -> {
                    val path = call.argument<String>("path")
                    if (path.isNullOrBlank()) {
                        result.error("INVALID_PATH", "APK path is required", null)
                    } else {
                        installApk(path, result)
                    }
                }
                "getNativeLibraryInfo" -> {
                    result.success(VeloGuardVpnService.getLibraryInfo(this))
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
        
        Log.d(TAG, "MethodChannel configured")
    }

    private fun installApk(path: String, result: MethodChannel.Result) {
        val apk = File(path)
        if (!apk.isFile || !apk.canRead()) {
            result.error("APK_NOT_FOUND", "Downloaded APK is not readable", null)
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !packageManager.canRequestPackageInstalls()) {
            startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
                    data = "package:$packageName".toUri()
                }
            )
            result.success(mapOf("launched" to false, "requiresPermission" to true))
            return
        }

        try {
            val uri = FileProvider.getUriForFile(
                this,
                "$packageName.fileprovider",
                apk,
            )
            startActivity(
                Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, "application/vnd.android.package-archive")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
            result.success(mapOf("launched" to true))
        } catch (error: Exception) {
            Log.e(TAG, "Failed to launch APK installer", error)
            result.error("INSTALL_FAILED", error.message, null)
        }
    }

    private fun startVpnService(result: MethodChannel.Result, mode: String) {
        Log.d(TAG, "=== startVpnService called, mode=$mode ===")
        
        pendingProxyMode = mode
        
        try {
            // First, check if another VPN is currently active
            val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            val activeNetwork = connectivityManager.activeNetwork
            var otherVpnActive = false
            
            if (activeNetwork != null) {
                val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                if (capabilities?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true) {
                    Log.w(TAG, "Another VPN is currently active - will attempt to take over")
                    otherVpnActive = true
                }
            }
            
            Log.d(TAG, "Calling VpnService.prepare()...")
            val intent = VpnService.prepare(this)
            
            if (intent != null) {
                // VPN permission needed - this will also revoke other VPN's permission
                Log.d(TAG, "VPN permission needed, showing permission dialog...")
                if (otherVpnActive) {
                    Log.d(TAG, "This will disconnect the other active VPN")
                }
                pendingVpnResult = result
                try {
                    @Suppress("DEPRECATION")
                    startActivityForResult(intent, VPN_REQUEST_CODE)
                    Log.d(TAG, "VPN permission dialog launched successfully")
                } catch (e: android.content.ActivityNotFoundException) {
                    Log.e(TAG, "VPN permission activity not found: ${e.message}", e)
                    pendingVpnResult = null
                    result.success(mapOf(
                        "success" to false,
                        "fd" to -1,
                        "error" to "VPN permission dialog not available on this device"
                    ))
                } catch (e: SecurityException) {
                    Log.e(TAG, "Security exception requesting VPN permission: ${e.message}", e)
                    pendingVpnResult = null
                    result.success(mapOf(
                        "success" to false,
                        "fd" to -1,
                        "error" to "Security error: ${e.message}"
                    ))
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start VPN permission activity: ${e.message}", e)
                    pendingVpnResult = null
                    result.success(mapOf(
                        "success" to false,
                        "fd" to -1,
                        "error" to "Failed to request VPN permission: ${e.message}"
                    ))
                }
            } else {
                // We already have VPN permission
                // If another VPN is active, calling establish() will take over the VPN slot
                if (otherVpnActive) {
                    Log.d(TAG, "We have VPN permission, will take over from other VPN...")
                } else {
                    Log.d(TAG, "VPN permission already granted, starting service directly...")
                }
                startVpnAndReturnFd(result, mode)
            }
        } catch (e: IllegalStateException) {
            Log.e(TAG, "IllegalStateException preparing VPN: ${e.message}", e)
            result.success(mapOf(
                "success" to false,
                "fd" to -1,
                "error" to "VPN service not available: ${e.message}"
            ))
        } catch (e: Exception) {
            Log.e(TAG, "Error preparing VPN: ${e.message}", e)
            result.success(mapOf(
                "success" to false,
                "fd" to -1,
                "error" to "Error preparing VPN: ${e.message}"
            ))
        }
    }
    
    private fun startVpnAndReturnFd(result: MethodChannel.Result, mode: String) {
        Log.d(TAG, "=== startVpnAndReturnFd called, mode=$mode ===")
        
        mainScope.launch {
            try {
                Log.d(TAG, "Launching VPN start in IO dispatcher...")
                val fd = withContext(Dispatchers.IO) {
                    VeloGuardVpnService.startVpnAndGetFd(this@MainActivity, mode)
                }
                
                Log.d(TAG, "VPN start completed, fd=$fd")
                
                if (fd >= 0) {
                    Log.d(TAG, "=== VPN started successfully, returning fd=$fd ===")
                    result.success(mapOf(
                        "success" to true,
                        "fd" to fd,
                        "mode" to mode
                    ))
                } else {
                    Log.e(TAG, "=== VPN start failed, fd=$fd ===")
                    result.success(mapOf(
                        "success" to false,
                        "fd" to -1,
                        "error" to "Failed to start VPN - VPN interface could not be established"
                    ))
                }
            } catch (e: Exception) {
                Log.e(TAG, "=== VPN start exception: ${e.message} ===", e)
                result.success(mapOf(
                    "success" to false,
                    "fd" to -1,
                    "error" to "VPN start error: ${e.message}"
                ))
            }
        }
    }
    
    private fun stopVpnService() {
        Log.d(TAG, "Stopping VPN service...")
        VeloGuardVpnService.stopVpnFromOutside(this)
    }
    
    private fun getInstalledApps(): List<Map<String, String>> {
        val pm = packageManager
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        return apps.map { app ->
            mapOf(
                "packageName" to app.packageName,
                "appName" to (pm.getApplicationLabel(app)?.toString() ?: app.packageName)
            )
        }
    }
    
    private fun getDeviceInfo(): Map<String, Any> {
        return mapOf(
            "brand" to Build.BRAND,
            "model" to Build.MODEL,
            "manufacturer" to Build.MANUFACTURER,
            "device" to Build.DEVICE,
            "product" to Build.PRODUCT,
            "sdkVersion" to Build.VERSION.SDK_INT,
            "release" to Build.VERSION.RELEASE,
            "display" to Build.DISPLAY,
            "hardware" to Build.HARDWARE
        )
    }
    
    private fun isOtherVpnActive(): Boolean {
        return try {
            val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            val activeNetwork = connectivityManager.activeNetwork
            if (activeNetwork != null) {
                val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                // Check if VPN transport is active AND it's not our VPN
                val isVpnTransport = capabilities?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true
                val isOurVpnRunning = VeloGuardVpnService.isRunning
                
                // If VPN transport is active but our VPN is not running, another VPN is active
                isVpnTransport && !isOurVpnRunning
            } else {
                false
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to check if other VPN is active: ${e.message}")
            false
        }
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        Log.d(TAG, "=== onActivityResult: requestCode=$requestCode, resultCode=$resultCode ===")
        
        if (requestCode == VPN_REQUEST_CODE) {
            val result = pendingVpnResult
            pendingVpnResult = null
            
            when (resultCode) {
                Activity.RESULT_OK -> {
                    Log.d(TAG, "VPN permission GRANTED by user")
                    if (result != null) {
                        startVpnAndReturnFd(result, pendingProxyMode)
                    } else {
                        Log.w(TAG, "VPN permission granted but no pending result callback")
                    }
                }
                Activity.RESULT_CANCELED -> {
                    Log.w(TAG, "VPN permission DENIED by user (RESULT_CANCELED)")
                    result?.success(mapOf(
                        "success" to false,
                        "fd" to -1,
                        "error" to "VPN permission denied by user"
                    ))
                }
                else -> {
                    Log.w(TAG, "VPN permission request returned unexpected result: $resultCode")
                    result?.success(mapOf(
                        "success" to false,
                        "fd" to -1,
                        "error" to "VPN permission request failed with code: $resultCode"
                    ))
                }
            }
        }
    }
    
    override fun onResume() {
        super.onResume()
        methodChannel?.invokeMethod("vpnStatusChanged", mapOf(
            "isRunning" to VeloGuardVpnService.isRunning,
            "fd" to VeloGuardVpnService.vpnFd
        ))
    }
    
    override fun onDestroy() {
        mainScope.cancel()
        methodChannel = null
        super.onDestroy()
    }
}
