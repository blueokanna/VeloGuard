use std::net::SocketAddr;

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::net::SocketAddr;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    pub fn get_process_name_by_socket(_local_addr: SocketAddr) -> Option<String> {
        None
    }

    pub fn get_process_name_by_pid(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

        unsafe {
            let handle: HANDLE = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            ).ok()?;

            if handle.is_invalid() {
                return None;
            }

            let mut buffer = vec![0u16; 1024];
            let len = GetModuleFileNameExW(Some(handle), None, &mut buffer);
            let _ = CloseHandle(handle);

            if len == 0 {
                return None;
            }

            let path = OsString::from_wide(&buffer[..len as usize]);
            let path_str = path.to_string_lossy().to_string();
            
            path_str.rsplit('\\').next().map(|s| s.to_string())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::net::SocketAddr;
    use std::fs;
    use std::path::PathBuf;

    pub fn get_process_name_by_socket(local_addr: SocketAddr) -> Option<String> {
        let inode = find_socket_inode(local_addr)?;
        let pid = find_pid_by_inode(inode)?;
        get_process_name_by_pid(pid)
    }

    fn find_socket_inode(addr: SocketAddr) -> Option<u64> {
        let (tcp_path, tcp6_path) = ("/proc/net/tcp", "/proc/net/tcp6");
        
        if let Some(inode) = search_proc_net(tcp_path, addr) {
            return Some(inode);
        }
        
        search_proc_net(tcp6_path, addr)
    }

    fn search_proc_net(path: &str, addr: SocketAddr) -> Option<u64> {
        let content = fs::read_to_string(path).ok()?;
        let port = addr.port();
        
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            
            let local_addr_parts: Vec<&str> = parts[1].split(':').collect();
            if local_addr_parts.len() != 2 {
                continue;
            }
            
            if let Ok(local_port) = u16::from_str_radix(local_addr_parts[1], 16) {
                if local_port == port {
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        return Some(inode);
                    }
                }
            }
        }
        
        None
    }

    fn find_pid_by_inode(target_inode: u64) -> Option<u32> {
        let proc_dir = fs::read_dir("/proc").ok()?;
        
        for entry in proc_dir.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(pid) = name.parse::<u32>() {
                    let fd_path = path.join("fd");
                    if let Ok(fd_dir) = fs::read_dir(&fd_path) {
                        for fd_entry in fd_dir.flatten() {
                            if let Ok(link) = fs::read_link(fd_entry.path()) {
                                let link_str = link.to_string_lossy();
                                if link_str.starts_with("socket:[") {
                                    let inode_str = link_str
                                        .trim_start_matches("socket:[")
                                        .trim_end_matches(']');
                                    if let Ok(inode) = inode_str.parse::<u64>() {
                                        if inode == target_inode {
                                            return Some(pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        None
    }

    pub fn get_process_name_by_pid(pid: u32) -> Option<String> {
        let comm_path = PathBuf::from(format!("/proc/{}/comm", pid));
        if let Ok(name) = fs::read_to_string(&comm_path) {
            return Some(name.trim().to_string());
        }
        
        let exe_path = PathBuf::from(format!("/proc/{}/exe", pid));
        if let Ok(link) = fs::read_link(&exe_path) {
            return link.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
        }
        
        None
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use std::net::SocketAddr;

    pub fn get_process_name_by_socket(_local_addr: SocketAddr) -> Option<String> {
        None
    }

    pub fn get_process_name_by_pid(pid: u32) -> Option<String> {
        use std::ffi::CStr;
        
        let mut buffer = vec![0u8; 1024];
        let result = unsafe {
            libc::proc_pidpath(
                pid as i32,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len() as u32,
            )
        };
        
        if result <= 0 {
            return None;
        }
        
        let path = unsafe { CStr::from_ptr(buffer.as_ptr() as *const i8) };
        let path_str = path.to_string_lossy();
        
        path_str.rsplit('/').next().map(|s| s.to_string())
    }
}

#[cfg(target_os = "android")]
mod android_impl {
    use std::net::SocketAddr;
    use std::fs;
    use std::path::PathBuf;

    pub fn get_process_name_by_socket(local_addr: SocketAddr) -> Option<String> {
        let inode = find_socket_inode(local_addr)?;
        let pid = find_pid_by_inode(inode)?;
        get_process_name_by_pid(pid)
    }

    fn find_socket_inode(addr: SocketAddr) -> Option<u64> {
        let tcp_path = "/proc/net/tcp";
        let tcp6_path = "/proc/net/tcp6";
        
        if let Some(inode) = search_proc_net(tcp_path, addr) {
            return Some(inode);
        }
        
        search_proc_net(tcp6_path, addr)
    }

    fn search_proc_net(path: &str, addr: SocketAddr) -> Option<u64> {
        let content = fs::read_to_string(path).ok()?;
        let port = addr.port();
        
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            
            let local_addr_parts: Vec<&str> = parts[1].split(':').collect();
            if local_addr_parts.len() != 2 {
                continue;
            }
            
            if let Ok(local_port) = u16::from_str_radix(local_addr_parts[1], 16) {
                if local_port == port {
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        return Some(inode);
                    }
                }
            }
        }
        
        None
    }

    fn find_pid_by_inode(target_inode: u64) -> Option<u32> {
        let proc_dir = fs::read_dir("/proc").ok()?;
        
        for entry in proc_dir.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(pid) = name.parse::<u32>() {
                    let fd_path = path.join("fd");
                    if let Ok(fd_dir) = fs::read_dir(&fd_path) {
                        for fd_entry in fd_dir.flatten() {
                            if let Ok(link) = fs::read_link(fd_entry.path()) {
                                let link_str = link.to_string_lossy();
                                if link_str.starts_with("socket:[") {
                                    let inode_str = link_str
                                        .trim_start_matches("socket:[")
                                        .trim_end_matches(']');
                                    if let Ok(inode) = inode_str.parse::<u64>() {
                                        if inode == target_inode {
                                            return Some(pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        None
    }

    pub fn get_process_name_by_pid(pid: u32) -> Option<String> {
        let cmdline_path = PathBuf::from(format!("/proc/{}/cmdline", pid));
        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
            let first_arg = cmdline.split('\0').next()?;
            return first_arg.rsplit('/').next().map(|s| s.to_string());
        }
        
        let comm_path = PathBuf::from(format!("/proc/{}/comm", pid));
        if let Ok(name) = fs::read_to_string(&comm_path) {
            return Some(name.trim().to_string());
        }
        
        None
    }
}

#[cfg(not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "android"
)))]
mod fallback_impl {
    use std::net::SocketAddr;

    pub fn get_process_name_by_socket(_local_addr: SocketAddr) -> Option<String> {
        None
    }

    pub fn get_process_name_by_pid(_pid: u32) -> Option<String> {
        None
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(target_os = "macos")]
pub use macos_impl::*;

#[cfg(target_os = "android")]
pub use android_impl::*;

#[cfg(not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "android"
)))]
pub use fallback_impl::*;

pub fn get_process_name(local_addr: Option<SocketAddr>, pid: Option<u32>) -> Option<String> {
    if let Some(pid) = pid {
        if let Some(name) = get_process_name_by_pid(pid) {
            return Some(name);
        }
    }
    
    if let Some(addr) = local_addr {
        if let Some(name) = get_process_name_by_socket(addr) {
            return Some(name);
        }
    }
    
    None
}

pub fn matches_process_name(pattern: &str, process_name: &str) -> bool {
    let pattern_lower = pattern.to_lowercase();
    let process_lower = process_name.to_lowercase();
    
    if pattern_lower == process_lower {
        return true;
    }
    
    if let Some(name) = process_name.rsplit(['/', '\\']).next() {
        if name.to_lowercase() == pattern_lower {
            return true;
        }
    }
    
    if let Some(name_without_ext) = pattern_lower.strip_suffix(".exe") {
        if process_lower == name_without_ext {
            return true;
        }
        if let Some(proc_name) = process_name.rsplit(['/', '\\']).next() {
            if proc_name.to_lowercase() == name_without_ext {
                return true;
            }
        }
    }
    
    if let Some(proc_without_ext) = process_lower.strip_suffix(".exe") {
        if proc_without_ext == pattern_lower {
            return true;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_process_name_exact() {
        assert!(matches_process_name("chrome", "chrome"));
        assert!(matches_process_name("Chrome", "chrome"));
        assert!(matches_process_name("chrome", "Chrome"));
    }

    #[test]
    fn test_matches_process_name_with_path() {
        assert!(matches_process_name("chrome", "/usr/bin/chrome"));
        assert!(matches_process_name("chrome", "C:\\Program Files\\Google\\Chrome\\chrome"));
    }

    #[test]
    fn test_matches_process_name_with_exe() {
        assert!(matches_process_name("chrome.exe", "chrome"));
        assert!(matches_process_name("chrome", "chrome.exe"));
        assert!(matches_process_name("chrome.exe", "chrome.exe"));
    }

    #[test]
    fn test_matches_process_name_no_match() {
        assert!(!matches_process_name("chrome", "firefox"));
        assert!(!matches_process_name("chrome", "chromium"));
    }
}
