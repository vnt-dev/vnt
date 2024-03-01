use crate::unix::exe_cmd;
use std::io;
use std::net::Ipv4Addr;

pub fn add_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let cmd = format!(
        "route -n add {} -netmask {} -interface {}",
        address, netmask, name
    );
    exe_cmd(&cmd)?;
    Ok(())
}
pub fn del_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let cmd = format!(
        "route -n delete {} -netmask {} -interface {}",
        address, netmask, name
    );
    exe_cmd(&cmd)?;
    Ok(())
}
