use crate::windows::exe_cmd;
use std::net::Ipv4Addr;
use std::{io, process};

/// 设置网卡名称
pub fn set_interface_name(old_name: &str, new_name: &str) -> io::Result<()> {
    let cmd = format!(
        " netsh interface set interface name={:?} newname={:?}",
        old_name, new_name
    );
    exe_cmd(&cmd)
}
/// 删除缓存
pub fn delete_cache() -> io::Result<()> {
    //清除缓存
    let cmd = "netsh interface ip delete destinationcache";
    exe_cmd(cmd)
}

/// 设置网卡ip
pub fn set_interface_ip(index: u32, address: &Ipv4Addr, netmask: &Ipv4Addr) -> io::Result<()> {
    let cmd = format!(
        "netsh interface ip set address {} static {:?} {:?} ",
        index, address, netmask,
    );
    exe_cmd(&cmd)
}

pub fn set_interface_mtu(index: u32, mtu: u32) -> io::Result<()> {
    let cmd = format!(
        "netsh interface ipv4 set subinterface {}  mtu={} store=persistent",
        index, mtu
    );
    exe_cmd(&cmd)
}
pub fn set_interface_metric(index: u32, metric: u16) -> io::Result<()> {
    let cmd = format!(
        "netsh interface ip set interface {} metric={}",
        index, metric
    );
    exe_cmd(&cmd)
}
/// 禁用ipv6
pub fn disabled_ipv6(index: u32) -> io::Result<()> {
    let cmd = format!("netsh interface ipv6 set interface {} disabled", index);
    exe_cmd(&cmd)
}
