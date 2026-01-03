use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ptr;

use crate::{ProcessInfo, Sock2ProcError};

#[allow(non_camel_case_types)]
type DWORD = u32;
#[allow(non_camel_case_types)]
type ULONG = u32;
#[allow(non_camel_case_types)]
type BYTE = u8;

#[repr(C)]
#[derive(Clone)]
struct MIB_TCPROW2 {
    dw_state: DWORD,
    dw_local_addr: DWORD,
    dw_local_port: DWORD,
    dw_remote_addr: DWORD,
    dw_remote_port: DWORD,
    dw_owning_pid: DWORD,
    dw_offload_state: BYTE,
}

#[repr(C)]
#[derive(Clone)]
struct MIB_TCPTABLE2 {
    dw_num_entries: DWORD,
    table: [MIB_TCPROW2; 1],
}

#[repr(C)]
#[derive(Clone)]
struct MIB_UDPROW {
    dw_local_addr: DWORD,
    dw_local_port: DWORD,
    dw_owning_pid: DWORD,
}

#[repr(C)]
#[derive(Clone)]
struct MIB_UDPTABLE {
    dw_num_entries: DWORD,
    table: [MIB_UDPROW; 1],
}

extern "system" {
    fn GetTcpTable2(
        tcp_table: *mut MIB_TCPTABLE2,
        size_pointer: *mut ULONG,
        order: bool,
    ) -> DWORD;

    fn GetUdpTable(
        udp_table: *mut MIB_UDPTABLE,
        size_pointer: *mut ULONG,
        order: bool,
    ) -> DWORD;
}

fn dword_to_ipv4(dw: DWORD) -> Ipv4Addr {
    Ipv4Addr::new(
        ((dw >> 24) & 0xFF) as u8,
        ((dw >> 16) & 0xFF) as u8,
        ((dw >> 8) & 0xFF) as u8,
        (dw & 0xFF) as u8,
    )
}

fn port_from_network(port: DWORD) -> u16 {
    ((port >> 8) | ((port & 0xFF) << 8)) as u16
}

fn get_process_info(pid: u32) -> Result<ProcessInfo, Sock2ProcError> {
    let name = format!("Process_{}", pid);

    Ok(ProcessInfo {
        pid,
        name,
        exe_path: None,
        cmdline: None,
    })
}

pub fn find_process_by_socket(socket_addr: SocketAddr) -> Result<ProcessInfo, Sock2ProcError> {
    match socket_addr {
        SocketAddr::V4(addr) => {
            let ip = addr.ip();
            let port = addr.port();

            if let Ok(process_info) = find_process_by_tcp_socket(ip, port) {
                return Ok(process_info);
            }

            find_process_by_udp_socket(ip, port)
        }
        SocketAddr::V6(_) => {
            Err(Sock2ProcError::NotImplemented)
        }
    }
}

fn find_process_by_tcp_socket(ip: &Ipv4Addr, port: u16) -> Result<ProcessInfo, Sock2ProcError> {
    let mut size: ULONG = 0;

    unsafe {
        GetTcpTable2(ptr::null_mut(), &mut size, true);
    }

    if size == 0 {
        return Err(Sock2ProcError::SystemError("Failed to get TCP table size".to_string()));
    }

    let mut buffer = vec![0u8; size as usize];
    let tcp_table = buffer.as_mut_ptr() as *mut MIB_TCPTABLE2;

    let result = unsafe { GetTcpTable2(tcp_table, &mut size, true) };

    if result != 0 {
        return Err(Sock2ProcError::SystemError(format!("GetTcpTable2 failed: {}", result)));
    }

    let table = unsafe { &*tcp_table };
    let entries = unsafe {
        std::slice::from_raw_parts(
            &table.table as *const MIB_TCPROW2,
            table.dw_num_entries as usize,
        )
    };

    let target_ip = u32::from_be_bytes(ip.octets());
    let target_port = (port as u32) << 8;

    for entry in entries {
        if entry.dw_local_addr == target_ip && entry.dw_local_port == target_port {
            return get_process_info(entry.dw_owning_pid);
        }
    }

    Err(Sock2ProcError::ProcessNotFound)
}

fn find_process_by_udp_socket(ip: &Ipv4Addr, port: u16) -> Result<ProcessInfo, Sock2ProcError> {
    let mut size: ULONG = 0;

    unsafe {
        GetUdpTable(ptr::null_mut(), &mut size, true);
    }

    if size == 0 {
        return Err(Sock2ProcError::SystemError("Failed to get UDP table size".to_string()));
    }

    let mut buffer = vec![0u8; size as usize];
    let udp_table = buffer.as_mut_ptr() as *mut MIB_UDPTABLE;

    let result = unsafe { GetUdpTable(udp_table, &mut size, true) };

    if result != 0 {
        return Err(Sock2ProcError::SystemError(format!("GetUdpTable failed: {}", result)));
    }

    let table = unsafe { &*udp_table };
    let entries = unsafe {
        std::slice::from_raw_parts(
            &table.table as *const MIB_UDPROW,
            table.dw_num_entries as usize,
        )
    };

    let target_ip = u32::from_be_bytes(ip.octets());
    let target_port = (port as u32) << 8;

    for entry in entries {
        if entry.dw_local_addr == target_ip && entry.dw_local_port == target_port {
            return get_process_info(entry.dw_owning_pid);
        }
    }

    Err(Sock2ProcError::ProcessNotFound)
}

pub fn find_processes_by_tcp_sockets() -> Result<Vec<(SocketAddr, ProcessInfo)>, Sock2ProcError> {
    let mut size: ULONG = 0;

    unsafe {
        GetTcpTable2(ptr::null_mut(), &mut size, true);
    }

    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    let tcp_table = buffer.as_mut_ptr() as *mut MIB_TCPTABLE2;

    let result = unsafe { GetTcpTable2(tcp_table, &mut size, true) };

    if result != 0 {
        return Err(Sock2ProcError::SystemError(format!("GetTcpTable2 failed: {}", result)));
    }

    let table = unsafe { &*tcp_table };
    let entries = unsafe {
        std::slice::from_raw_parts(
            &table.table as *const MIB_TCPROW2,
            table.dw_num_entries as usize,
        )
    };

    let mut result = Vec::new();
    for entry in entries {
        let ip = dword_to_ipv4(entry.dw_local_addr);
        let port = port_from_network(entry.dw_local_port);
        let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));

        if let Ok(process_info) = get_process_info(entry.dw_owning_pid) {
            result.push((socket_addr, process_info));
        }
    }

    Ok(result)
}

pub fn find_processes_by_udp_sockets() -> Result<Vec<(SocketAddr, ProcessInfo)>, Sock2ProcError> {
    let mut size: ULONG = 0;

    unsafe {
        GetUdpTable(ptr::null_mut(), &mut size, true);
    }

    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    let udp_table = buffer.as_mut_ptr() as *mut MIB_UDPTABLE;

    let result = unsafe { GetUdpTable(udp_table, &mut size, true) };

    if result != 0 {
        return Err(Sock2ProcError::SystemError(format!("GetUdpTable failed: {}", result)));
    }

    let table = unsafe { &*udp_table };
    let entries = unsafe {
        std::slice::from_raw_parts(
            &table.table as *const MIB_UDPROW,
            table.dw_num_entries as usize,
        )
    };

    let mut result = Vec::new();
    for entry in entries {
        let ip = dword_to_ipv4(entry.dw_local_addr);
        let port = port_from_network(entry.dw_local_port);
        let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));

        if let Ok(process_info) = get_process_info(entry.dw_owning_pid) {
            result.push((socket_addr, process_info));
        }
    }

    Ok(result)
}
