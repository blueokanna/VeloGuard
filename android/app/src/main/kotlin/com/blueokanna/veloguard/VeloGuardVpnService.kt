package com.blueokanna.veloguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class VeloGuardVpnService : VpnService() {
    
    // JNI methods for Rust bridge
    private external fun nativeInitRustBridge()
    private external fun nativeClearRustBridge()
    
    companion object {
        private const val TAG = "VeloGuardVpnService"
        const val ACTION_START = "com.blueokanna.veloguard.START_VPN"
        const val ACTION_STOP = "com.blueokanna.veloguard.STOP_VPN"
        const val NOTIFICATION_CHANNEL_ID = "veloguard_vpn"
        const val NOTIFICATION_ID = 1
        
        private val _isRunning = AtomicBoolean(false)
        val isRunning: Boolean get() = _isRunning.get()
        
        private val _connectionCount = AtomicInteger(0)
        val connectionCount: Int get() = _connectionCount.get()
        
        private var _proxyMode = ProxyMode.RULE
        val proxyMode: ProxyMode get() = _proxyMode
        
        private val _jniInitialized = AtomicBoolean(false)
        val jniInitialized: Boolean get() = _jniInitialized.get()
        
        @Volatile
        private var _vpnFd: Int = -1
        val vpnFd: Int get() = _vpnFd
        
        @Volatile
        private var startLatch: CountDownLatch? = null
        
        @Volatile
        private var instance: VeloGuardVpnService? = null
        
        private val _isStarting = AtomicBoolean(false)
        
        init {
            try {
                System.loadLibrary("rust_lib_veloguard")
                Log.d(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library: ${e.message}")
            }
        }
        
        @Synchronized
        fun resetAllState() {
            Log.d(TAG, "=== Resetting all VPN static state ===")
            _isRunning.set(false)
            _connectionCount.set(0)
            _jniInitialized.set(false)
            _vpnFd = -1
            _isStarting.set(false)
            startLatch?.countDown()
            startLatch = null
            instance = null
            Log.d(TAG, "All VPN static state reset complete")
        }

        @Synchronized
        fun startVpnAndGetFd(context: Context, mode: String): Int {
            Log.d(TAG, "=== startVpnAndGetFd called with mode=$mode ===")
            
            if (_isRunning.get() && _vpnFd >= 0) {
                Log.d(TAG, "VPN already running, returning existing fd=$_vpnFd")
                return _vpnFd
            }
            
            if (_isStarting.get()) {
                Log.d(TAG, "VPN start already in progress, waiting...")
                try {
                    val latch = startLatch
                    if (latch != null) {
                        val started = latch.await(10, TimeUnit.SECONDS)
                        if (started && _vpnFd >= 0) {
                            return _vpnFd
                        }
                    }
                } catch (e: InterruptedException) {
                    Log.w(TAG, "Interrupted while waiting for VPN start")
                }
                return -1
            }
            
            // Check if another VPN is active and try to take over
            try {
                val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
                val activeNetwork = connectivityManager.activeNetwork
                if (activeNetwork != null) {
                    val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                    if (capabilities?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true) {
                        Log.w(TAG, "Another VPN is active - will attempt to take over VPN slot")
                        // The VpnService.prepare() call will automatically revoke the other VPN's permission
                        // when the user grants permission to our app, or if we already have permission,
                        // calling establish() will take over the VPN slot
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to check VPN status: ${e.message}")
            }
            
            _vpnFd = -1
            _isStarting.set(true)
            startLatch = CountDownLatch(1)
            
            Log.d(TAG, "Starting VPN service via Intent...")
            
            val intent = Intent(context, VeloGuardVpnService::class.java).apply {
                action = ACTION_START
                putExtra("mode", mode)
            }
            
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                    Log.d(TAG, "startForegroundService called successfully")
                } else {
                    context.startService(intent)
                    Log.d(TAG, "startService called successfully")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN service: ${e.message}", e)
                _isStarting.set(false)
                startLatch?.countDown()
                return -1
            }
            
            try {
                Log.d(TAG, "Waiting for VPN to start (max 10 seconds)...")
                val started = startLatch?.await(10, TimeUnit.SECONDS) ?: false
                _isStarting.set(false)
                
                if (started && _vpnFd >= 0) {
                    Log.d(TAG, "=== VPN started successfully, fd=$_vpnFd ===")
                    return _vpnFd
                } else {
                    Log.e(TAG, "=== VPN start failed ===")
                    return -1
                }
            } catch (e: InterruptedException) {
                Log.e(TAG, "VPN start interrupted: ${e.message}")
                _isStarting.set(false)
                return -1
            }
        }
        
        fun stopVpnFromOutside(context: Context) {
            Log.d(TAG, "=== stopVpnFromOutside called ===")
            
            // Set flags first to signal stop
            _isRunning.set(false)
            _vpnFd = -1
            _isStarting.set(false)
            _connectionCount.set(0)
            
            // Stop the instance if available
            instance?.let { vpnInstance ->
                Log.d(TAG, "Calling stopVpnInternal on instance...")
                vpnInstance.stopVpnInternal()
            }
            
            // Also send stop intent to ensure service stops
            try {
                val intent = Intent(context, VeloGuardVpnService::class.java).apply {
                    action = ACTION_STOP
                }
                context.startService(intent)
                Log.d(TAG, "Stop intent sent to VPN service")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to send stop intent: ${e.message}")
            }
            
            Log.d(TAG, "=== stopVpnFromOutside complete ===")
        }
        
        fun setProxyMode(mode: ProxyMode) {
            _proxyMode = mode
            Log.d(TAG, "Proxy mode set to: $mode")
        }
        
        fun updateConnectionCount(count: Int) {
            _connectionCount.set(count)
        }
    }
    
    enum class ProxyMode {
        RULE, GLOBAL, DIRECT
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private val isStarting = AtomicBoolean(false)
    private var currentMode: ProxyMode = ProxyMode.RULE
    
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "=== VPN Service onCreate ===")
        
        _isRunning.set(false)
        _vpnFd = -1
        _jniInitialized.set(false)
        isStarting.set(false)
        
        instance = this
        createNotificationChannel()
        
        try {
            Log.d(TAG, "Initializing Rust JNI bridge...")
            nativeInitRustBridge()
            _jniInitialized.set(true)
            Log.d(TAG, "Rust JNI bridge initialized successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Rust JNI bridge: ${e.message}", e)
            _jniInitialized.set(false)
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Native library not loaded: ${e.message}", e)
            _jniInitialized.set(false)
        }
        
        Log.d(TAG, "VPN Service created, JNI initialized: ${_jniInitialized.get()}")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}, startId=$startId")
        
        when (intent?.action) {
            ACTION_START -> {
                if (isStarting.getAndSet(true)) {
                    Log.d(TAG, "VPN start already in progress, ignoring duplicate request")
                    return START_NOT_STICKY
                }
                
                val mode = intent.getStringExtra("mode") ?: "rule"
                currentMode = when (mode.lowercase()) {
                    "global" -> ProxyMode.GLOBAL
                    "direct" -> ProxyMode.DIRECT
                    else -> ProxyMode.RULE
                }
                _proxyMode = currentMode
                
                startVpn()
            }
            ACTION_STOP -> {
                stopVpnInternal()
            }
            else -> {
                if (!_isRunning.get()) {
                    Log.d(TAG, "No action and VPN not running, stopping service")
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }
    
    private fun startVpn() {
        try {
            Log.d(TAG, "=== Starting VPN with mode: $currentMode ===")
            
            if (!_jniInitialized.get()) {
                Log.w(TAG, "JNI bridge not initialized, attempting to initialize...")
                try {
                    nativeInitRustBridge()
                    _jniInitialized.set(true)
                    Log.d(TAG, "JNI bridge initialized on retry")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to initialize JNI bridge on retry: ${e.message}", e)
                }
            } else {
                Log.d(TAG, "JNI bridge already initialized")
            }
            
            vpnInterface?.let { oldInterface ->
                try {
                    Log.d(TAG, "Closing old VPN interface...")
                    oldInterface.close()
                    Log.d(TAG, "Closed old VPN interface")
                } catch (e: Exception) {
                    Log.w(TAG, "Error closing old VPN interface: ${e.message}")
                }
            }
            vpnInterface = null
            _vpnFd = -1
            
            // Wait a bit for any previous VPN to fully release resources
            Thread.sleep(200)
            
            Log.d(TAG, "Building VPN interface...")
            val builder = Builder()
                .setSession("VeloGuard")
                .setMtu(1500)
                .addAddress("198.18.0.1", 16)
                .addDnsServer("198.18.0.2")
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setBlocking(false)
            
            when (currentMode) {
                ProxyMode.GLOBAL, ProxyMode.RULE -> {
                    builder.addRoute("0.0.0.0", 0)
                    Log.d(TAG, "Added route: 0.0.0.0/0 (all traffic)")
                }
                ProxyMode.DIRECT -> {
                    builder.addRoute("198.18.0.0", 16)
                    Log.d(TAG, "Added route: 198.18.0.0/16 (Fake-IP only)")
                }
            }
            
            try {
                builder.addDisallowedApplication(packageName)
                Log.d(TAG, "Excluded self from VPN: $packageName")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to exclude self from VPN: ${e.message}")
            }
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            
            // Try to establish VPN with retry logic
            // This handles the case where another VPN is being disconnected
            var retryCount = 0
            val maxRetries = 3
            var lastError: Exception? = null
            
            while (retryCount < maxRetries && vpnInterface == null) {
                try {
                    Log.d(TAG, "Calling builder.establish() (attempt ${retryCount + 1}/$maxRetries)...")
                    vpnInterface = builder.establish()
                    
                    if (vpnInterface == null && retryCount < maxRetries - 1) {
                        Log.w(TAG, "establish() returned null, waiting before retry...")
                        Thread.sleep(500) // Wait for other VPN to fully disconnect
                        retryCount++
                    } else {
                        break
                    }
                } catch (e: Exception) {
                    lastError = e
                    Log.w(TAG, "establish() failed (attempt ${retryCount + 1}): ${e.message}")
                    if (retryCount < maxRetries - 1) {
                        Thread.sleep(500)
                    }
                    retryCount++
                }
            }
            
            if (vpnInterface != null) {
                val fd = vpnInterface!!.fd
                _vpnFd = fd
                _isRunning.set(true)
                
                startForeground(NOTIFICATION_ID, createNotification())
                
                Log.d(TAG, "=== VPN STARTED SUCCESSFULLY ===")
                Log.d(TAG, "  fd=$fd")
                Log.d(TAG, "  JNI initialized=${_jniInitialized.get()}")
                Log.d(TAG, "  mode=$currentMode")
                Log.d(TAG, "  retries=$retryCount")
                
                startLatch?.countDown()
            } else {
                Log.e(TAG, "=== VPN FAILED TO START ===")
                Log.e(TAG, "builder.establish() returned null after $maxRetries attempts")
                if (lastError != null) {
                    Log.e(TAG, "Last error: ${lastError.message}")
                }
                _isRunning.set(false)
                _vpnFd = -1
                startLatch?.countDown()
            }
        } catch (e: Exception) {
            Log.e(TAG, "=== VPN START EXCEPTION ===", e)
            Log.e(TAG, "Error: ${e.message}")
            _isRunning.set(false)
            _vpnFd = -1
            startLatch?.countDown()
        } finally {
            isStarting.set(false)
        }
    }
    
    @Synchronized
    private fun stopVpnInternal() {
        Log.d(TAG, "=== stopVpnInternal called ===")
        
        // Set all flags to stopped state
        _isRunning.set(false)
        _connectionCount.set(0)
        _vpnFd = -1
        isStarting.set(false)
        
        // Close VPN interface
        vpnInterface?.let { pfd ->
            try {
                Log.d(TAG, "Closing VPN interface fd=${pfd.fd}...")
                pfd.close()
                Log.d(TAG, "VPN interface closed successfully")
            } catch (e: Exception) {
                Log.w(TAG, "Error closing VPN interface: ${e.message}")
            }
        }
        vpnInterface = null
        
        // Clear Rust JNI bridge
        try {
            Log.d(TAG, "Clearing Rust JNI bridge...")
            nativeClearRustBridge()
            _jniInitialized.set(false)
            Log.d(TAG, "Rust JNI bridge cleared")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to clear Rust JNI bridge: ${e.message}")
        }
        
        // Stop foreground service
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        
        // Stop the service
        stopSelf()
        
        // Clear instance reference
        instance = null
        
        Log.d(TAG, "=== VPN service stopped completely ===")
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "VeloGuard VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN 服务通知"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val stopIntent = Intent(this, VeloGuardVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val modeText = when (currentMode) {
            ProxyMode.GLOBAL -> "全局代理"
            ProxyMode.RULE -> "规则模式"
            ProxyMode.DIRECT -> "直连模式"
        }
        
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("VeloGuard")
            .setContentText("VPN 正在运行 - $modeText")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "停止", stopPendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .build()
    }
    
    override fun onDestroy() {
        Log.d(TAG, "onDestroy called")
        _isRunning.set(false)
        _vpnFd = -1
        isStarting.set(false)
        instance = null
        
        try {
            nativeClearRustBridge()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to clear Rust JNI bridge: ${e.message}")
        }
        
        vpnInterface?.close()
        vpnInterface = null
        
        super.onDestroy()
    }
    
    override fun onRevoke() {
        Log.d(TAG, "VPN permission revoked")
        stopVpnInternal()
        super.onRevoke()
    }
}
