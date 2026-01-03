#[cfg(windows)]
use crate::error::{NetStackError, Result};

#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use tracing::{debug, info, warn};

#[cfg(windows)]
use once_cell::sync::OnceCell;

#[cfg(windows)]
static WINTUN_INSTANCE: OnceCell<wintun_bindings::Wintun> = OnceCell::new();

#[cfg(windows)]
const WINTUN_DLL_BYTES: Option<&[u8]> = None;

/// Wintun download URL
#[cfg(windows)]
const WINTUN_DOWNLOAD_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

/// Get the path where wintun.dll should be located
#[cfg(windows)]
pub fn get_wintun_dll_path() -> Result<PathBuf> {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            return Ok(exe_dir.join("wintun.dll"));
        }
    }
    Ok(std::env::current_dir()
        .map_err(|e| NetStackError::TunError(format!("Failed to get current directory: {}", e)))?
        .join("wintun.dll"))
}

/// Check if wintun.dll exists at the expected location
#[cfg(windows)]
pub fn is_wintun_available() -> bool {
    get_wintun_dll_path().map(|p| p.exists()).unwrap_or(false)
}


/// Extract embedded wintun.dll to the executable directory
#[cfg(windows)]
pub fn extract_wintun_dll() -> Result<PathBuf> {
    let dll_path = get_wintun_dll_path()?;
    
    if dll_path.exists() {
        debug!("wintun.dll already exists at {:?}", dll_path);
        return Ok(dll_path);
    }
    
    match WINTUN_DLL_BYTES {
        Some(bytes) => {
            info!("Extracting embedded wintun.dll to {:?}", dll_path);
            std::fs::write(&dll_path, bytes)
                .map_err(|e| NetStackError::TunError(format!("Failed to write wintun.dll: {}", e)))?;
            info!("wintun.dll extracted successfully ({} bytes)", bytes.len());
            Ok(dll_path)
        }
        None => {
            warn!("No embedded wintun.dll available");
            warn!("Please download from https://www.wintun.net/ or use download_wintun_dll()");
            Err(NetStackError::TunNotAvailable)
        }
    }
}

/// Ensure wintun.dll is available
#[cfg(windows)]
pub fn ensure_wintun_available() -> Result<PathBuf> {
    if is_wintun_available() {
        get_wintun_dll_path()
    } else {
        extract_wintun_dll()
    }
}

/// Download wintun.dll from the official source
#[cfg(windows)]
pub async fn download_wintun_dll() -> Result<PathBuf> {
    use std::io::Write;
    
    let dll_path = get_wintun_dll_path()?;
    
    if dll_path.exists() {
        return Ok(dll_path);
    }
    
    info!("Downloading wintun.dll from {}...", WINTUN_DOWNLOAD_URL);
    
    let response = reqwest::get(WINTUN_DOWNLOAD_URL)
        .await
        .map_err(|e| NetStackError::TunError(format!("Failed to download wintun: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(NetStackError::TunError(format!(
            "Failed to download wintun: HTTP {}",
            response.status()
        )));
    }
    
    let bytes = response.bytes()
        .await
        .map_err(|e| NetStackError::TunError(format!("Failed to read download: {}", e)))?;
    
    info!("Downloaded {} bytes, extracting...", bytes.len());
    
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| NetStackError::TunError(format!("Failed to open zip: {}", e)))?;
    
    #[cfg(target_arch = "x86_64")]
    let dll_name = "wintun/bin/amd64/wintun.dll";
    #[cfg(target_arch = "aarch64")]
    let dll_name = "wintun/bin/arm64/wintun.dll";
    #[cfg(target_arch = "x86")]
    let dll_name = "wintun/bin/x86/wintun.dll";
    
    let mut dll_file = archive.by_name(dll_name)
        .map_err(|e| NetStackError::TunError(format!("Failed to find {}: {}", dll_name, e)))?;
    
    let mut dll_bytes = Vec::new();
    std::io::Read::read_to_end(&mut dll_file, &mut dll_bytes)
        .map_err(|e| NetStackError::TunError(format!("Failed to read DLL: {}", e)))?;
    
    let mut output_file = std::fs::File::create(&dll_path)
        .map_err(|e| NetStackError::TunError(format!("Failed to create file: {}", e)))?;
    output_file.write_all(&dll_bytes)
        .map_err(|e| NetStackError::TunError(format!("Failed to write file: {}", e)))?;
    
    info!("wintun.dll extracted to {:?} ({} bytes)", dll_path, dll_bytes.len());
    Ok(dll_path)
}


/// Load the wintun library, downloading if necessary
#[cfg(windows)]
pub async fn load_wintun() -> Result<&'static wintun_bindings::Wintun> {
    if let Some(wintun) = WINTUN_INSTANCE.get() {
        return Ok(wintun);
    }
    
    let dll_path = match ensure_wintun_available() {
        Ok(path) => path,
        Err(_) => download_wintun_dll().await?
    };
    
    info!("Loading wintun.dll from {:?}", dll_path);
    
    let wintun = unsafe {
        wintun_bindings::load_from_path(&dll_path)
            .map_err(|e| NetStackError::TunError(format!("Failed to load wintun.dll: {}", e)))?
    };
    
    info!("Wintun library loaded successfully");
    
    let _ = WINTUN_INSTANCE.set(wintun);
    Ok(WINTUN_INSTANCE.get().unwrap())
}

/// Load wintun synchronously
#[cfg(windows)]
pub fn load_wintun_sync() -> Result<&'static wintun_bindings::Wintun> {
    if let Some(wintun) = WINTUN_INSTANCE.get() {
        return Ok(wintun);
    }
    
    let dll_path = ensure_wintun_available()?;
    info!("Loading wintun.dll from {:?}", dll_path);
    
    let wintun = unsafe {
        wintun_bindings::load_from_path(&dll_path)
            .map_err(|e| NetStackError::TunError(format!("Failed to load wintun.dll: {}", e)))?
    };
    
    info!("Wintun library loaded successfully");
    
    let _ = WINTUN_INSTANCE.set(wintun);
    Ok(WINTUN_INSTANCE.get().unwrap())
}

/// Get the loaded wintun instance
#[cfg(windows)]
pub fn get_wintun() -> Option<&'static wintun_bindings::Wintun> {
    WINTUN_INSTANCE.get()
}

// Non-Windows stubs
#[cfg(not(windows))]
pub fn is_wintun_available() -> bool {
    true
}

#[cfg(not(windows))]
pub fn ensure_wintun_available() -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::new())
}

#[cfg(not(windows))]
use crate::error::Result;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_get_wintun_path() {
        let path = get_wintun_dll_path();
        assert!(path.is_ok());
        assert!(path.unwrap().ends_with("wintun.dll"));
    }
}
