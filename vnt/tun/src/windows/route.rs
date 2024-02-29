use std::io;
use std::net::Ipv4Addr;

use crate::windows::exe_cmd;

/// 添加路由
pub fn add_route(
    index: u32,
    dest: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    metric: u16,
) -> io::Result<()> {
    let cmd = format!(
        "route add {:?} mask {:?} {:?} metric {} if {}",
        dest, netmask, gateway, metric, index
    );
    exe_cmd(&cmd)
}

/// 删除路由
pub fn delete_route(
    index: u32,
    dest: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> io::Result<()> {
    let cmd = format!(
        "route delete  {:?} mask {:?} {:?} if {}",
        dest, netmask, gateway, index
    );
    exe_cmd(&cmd)
}
