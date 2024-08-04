use std::io;
use std::net::Ipv4Addr;

use crate::unix::exe_cmd;

pub fn add_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let cmd = if netmask.is_broadcast() {
        format!("route add -host {:?} {}", address, name)
    } else {
        format!(
            "route add -net {}/{} {}",
            address,
            u32::from(netmask).count_ones(),
            name
        )
    };
    exe_cmd(&cmd)?;
    Ok(())
}

pub fn del_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let cmd = format!("ip route del {:?}/{:?} dev {}", address, netmask, name);
    exe_cmd(&cmd)?;
    Ok(())
}
