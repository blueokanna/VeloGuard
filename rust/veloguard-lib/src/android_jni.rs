#![cfg(target_os = "android")]

use jni::objects::{GlobalRef, JObject, JValue};
use jni::sys::jint;
use jni::{JNIEnv, JavaVM};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error, info, warn};

extern "C" {
    fn __android_log_write(prio: i32, tag: *const i8, text: *const i8) -> i32;
}

/// Use RwLock instead of OnceLock to allow resetting on VPN restart
static JAVA_VM: RwLock<Option<JavaVM>> = RwLock::new(None);
static VPN_SERVICE: RwLock<Option<GlobalRef>> = RwLock::new(None);
static JNI_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern "system" fn Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeInitRustBridge<
    'local,
>(
    env: JNIEnv<'local>,
    vpn_service: JObject<'local>,
) {
    android_log(
        "INFO",
        "=== Initializing Rust JNI bridge for VpnService ===",
    );
    info!("=== Initializing Rust JNI bridge for VpnService ===");

    // Clear any existing state first to support VPN restart
    {
        let mut vm_guard = JAVA_VM.write();
        let mut service_guard = VPN_SERVICE.write();
        
        // Drop old references
        *vm_guard = None;
        *service_guard = None;
        JNI_INITIALIZED.store(false, Ordering::SeqCst);
        
        android_log("INFO", "Cleared previous JNI state");
    }

    // Get and store JavaVM
    match env.get_java_vm() {
        Ok(vm) => {
            let mut vm_guard = JAVA_VM.write();
            *vm_guard = Some(vm);
            android_log("INFO", "JavaVM stored successfully");
            info!("JavaVM stored successfully");
        }
        Err(e) => {
            let msg = format!("Failed to get JavaVM: {:?}", e);
            android_log("ERROR", &msg);
            error!("{}", msg);
            return;
        }
    }

    match env.new_global_ref(vpn_service) {
        Ok(global_ref) => {
            let mut service_guard = VPN_SERVICE.write();
            *service_guard = Some(global_ref);
            android_log("INFO", "VpnService reference stored successfully");
            info!("VpnService reference stored successfully");
        }
        Err(e) => {
            let msg = format!("Failed to create global reference: {:?}", e);
            android_log("ERROR", &msg);
            error!("{}", msg);
            return;
        }
    }

    // Mark as initialized
    JNI_INITIALIZED.store(true, Ordering::SeqCst);

    // Set up the protect callback in veloguard-solidtcp
    setup_protect_callback();

    android_log("INFO", "=== JNI bridge initialization complete ===");
    info!("=== JNI bridge initialization complete ===");
}

fn android_log(level: &str, message: &str) {
    use std::ffi::CString;

    let tag = CString::new("VeloGuard-JNI").unwrap_or_default();
    let msg = CString::new(message).unwrap_or_default();

    unsafe {
        let priority = match level {
            "ERROR" => 6, // ANDROID_LOG_ERROR
            "WARN" => 5,  // ANDROID_LOG_WARN
            "INFO" => 4,  // ANDROID_LOG_INFO
            "DEBUG" => 3, // ANDROID_LOG_DEBUG
            _ => 4,
        };
        __android_log_write(
            priority,
            tag.as_ptr() as *const i8,
            msg.as_ptr() as *const i8,
        );
    }
}

#[no_mangle]
pub extern "system" fn Java_com_blueokanna_veloguard_VeloGuardVpnService_nativeClearRustBridge<
    'local,
>(
    _env: JNIEnv<'local>,
    _vpn_service: JObject<'local>,
) {
    android_log("INFO", "Clearing Rust JNI bridge");
    info!("Clearing Rust JNI bridge");
    
    // Clear all state to allow re-initialization
    JNI_INITIALIZED.store(false, Ordering::SeqCst);
    
    {
        let mut vm_guard = JAVA_VM.write();
        let mut service_guard = VPN_SERVICE.write();
        *vm_guard = None;
        *service_guard = None;
    }
    
    // Clear the protect callback for veloguard-netstack (android_tun.rs)
    veloguard_netstack::clear_protect_callback();
    android_log("INFO", "Cleared protect callback for android_tun");
    
    // Clear the protect callback for veloguard-netstack (solidtcp/stack.rs)
    veloguard_netstack::solidtcp::clear_protect_callback();
    android_log("INFO", "Cleared protect callback for solidtcp");
    
    // Clear the protect callback for veloguard-core
    veloguard_core::clear_protect_callback();
    android_log("INFO", "Cleared protect callback for veloguard-core");

    android_log("INFO", "JNI bridge cleared completely");
    info!("JNI bridge cleared completely");
}

pub fn protect_socket_via_jni(fd: i32) -> bool {
    if !JNI_INITIALIZED.load(Ordering::SeqCst) {
        let msg = format!("JNI not initialized, cannot protect socket fd={}", fd);
        android_log("WARN", &msg);
        warn!("{}", msg);
        return false;
    }

    // Hold the read locks for the duration of the JNI call
    let vm_guard = JAVA_VM.read();
    let service_guard = VPN_SERVICE.read();
    
    let vm = match vm_guard.as_ref() {
        Some(vm) => vm,
        None => {
            let msg = format!("JavaVM not available, cannot protect socket fd={}", fd);
            android_log("WARN", &msg);
            warn!("{}", msg);
            return false;
        }
    };

    let vpn_service_ref = match service_guard.as_ref() {
        Some(service) => service,
        None => {
            let msg = format!("VpnService not available, cannot protect socket fd={}", fd);
            android_log("WARN", &msg);
            warn!("{}", msg);
            return false;
        }
    };

    // Attach current thread to JVM
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(e) => {
            let msg = format!("Failed to attach thread to JVM: {:?}", e);
            android_log("ERROR", &msg);
            error!("{}", msg);
            return false;
        }
    };

    // Call VpnService.protect(int fd)
    let result = env.call_method(
        vpn_service_ref.as_obj(),
        "protect",
        "(I)Z",
        &[JValue::Int(fd as jint)],
    );

    match result {
        Ok(ret) => match ret.z() {
            Ok(protected) => {
                if protected {
                    let msg = format!("Socket fd={} protected successfully via JNI", fd);
                    android_log("DEBUG", &msg);
                    debug!("{}", msg);
                } else {
                    let msg = format!("VpnService.protect() returned false for fd={}", fd);
                    android_log("WARN", &msg);
                    warn!("{}", msg);
                }
                protected
            }
            Err(e) => {
                let msg = format!("Failed to get boolean result: {:?}", e);
                android_log("ERROR", &msg);
                error!("{}", msg);
                false
            }
        },
        Err(e) => {
            let msg = format!("Failed to call VpnService.protect(): {:?}", e);
            android_log("ERROR", &msg);
            error!("{}", msg);
            // Check for exceptions
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_describe();
                let _ = env.exception_clear();
            }
            false
        }
    }
}

/// Set up the protect callback in all modules that need socket protection
fn setup_protect_callback() {
    // 1. Set up callback for veloguard-netstack (android_tun.rs)
    android_log(
        "INFO",
        "Setting up socket protect callback for veloguard-netstack (android_tun)",
    );
    veloguard_netstack::set_protect_callback(|fd| {
        let msg = format!("protect_socket callback called for fd={} (android_tun)", fd);
        android_log("DEBUG", &msg);
        protect_socket_via_jni(fd)
    });
    android_log(
        "INFO",
        "Socket protect callback configured for veloguard-netstack (android_tun)",
    );
    info!("Socket protect callback configured for veloguard-netstack (android_tun)");
    
    // 2. Set up callback for veloguard-netstack solidtcp stack
    // This is a SEPARATE static variable in solidtcp/stack.rs!
    android_log(
        "INFO",
        "Setting up socket protect callback for veloguard-netstack (solidtcp)",
    );
    veloguard_netstack::solidtcp::set_protect_callback(|fd| {
        let msg = format!("protect_socket callback called for fd={} (solidtcp)", fd);
        android_log("DEBUG", &msg);
        protect_socket_via_jni(fd)
    });
    android_log(
        "INFO",
        "Socket protect callback configured for veloguard-netstack (solidtcp)",
    );
    info!("Socket protect callback configured for veloguard-netstack (solidtcp)");
    
    // 3. Set up callback for veloguard-core outbound protocols
    android_log(
        "INFO",
        "Setting up socket protect callback for veloguard-core",
    );
    veloguard_core::set_protect_callback(|fd| {
        let msg = format!("protect_socket callback called for fd={} (core)", fd);
        android_log("DEBUG", &msg);
        protect_socket_via_jni(fd)
    });
    android_log(
        "INFO",
        "Socket protect callback configured for veloguard-core",
    );
    info!("Socket protect callback configured for veloguard-core");
}

/// Check if JNI bridge is initialized
pub fn is_jni_initialized() -> bool {
    JNI_INITIALIZED.load(Ordering::SeqCst) 
        && JAVA_VM.read().is_some() 
        && VPN_SERVICE.read().is_some()
}

/// Get JNI initialization status for debugging
pub fn get_jni_status() -> String {
    let initialized = JNI_INITIALIZED.load(Ordering::SeqCst);
    let has_vm = JAVA_VM.read().is_some();
    let has_service = VPN_SERVICE.read().is_some();
    format!(
        "JNI Status: initialized={}, has_vm={}, has_service={}",
        initialized, has_vm, has_service
    )
}
