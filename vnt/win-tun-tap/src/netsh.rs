use std::io;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;

/// 设置网卡名称
pub fn set_interface_name(old_name: &str, new_name: &str) -> io::Result<()> {
    let cmd = format!(" netsh interface set interface name={:?} newname={:?}", old_name, new_name);
    let out = std::process::Command::new("cmd")
        .creation_flags(0x08000000) //winapi-0.3.9/src/um/winbase.rs:283
        .arg("/C")
        .arg(&cmd)
        .output()?;
    if !out.status.success() {
        log::warn!("修改网卡名称失败：cmd={:?},out={:?}",cmd,out);
        return Err(io::Error::new(io::ErrorKind::Other, "修改网卡名称失败"));
    }
    Ok(())
}
/// 设置网卡ip
pub fn set_interface_ip(index: u32, address: &Ipv4Addr, netmask: &Ipv4Addr) -> io::Result<()> {
    let set_address = format!(
        "netsh interface ip set address {} static {:?} {:?} ",
        index, address, netmask,
    );
    let out = std::process::Command::new("cmd")
        .creation_flags(0x08000000)
        .arg("/C")
        .arg(&set_address)
        .output()?;
    if !out.status.success() {
        log::error!("cmd={:?},out={:?}",set_address,out);
        return Err(io::Error::new(io::ErrorKind::Other, format!("设置网络地址失败: {:?}", out)));
    }
    Ok(())
}

pub fn set_interface_mtu(index: u32, mtu: u16) -> io::Result<()> {
    let set_mtu = format!(
        "netsh interface ipv4 set subinterface {}  mtu={} store=persistent",
        index, mtu
    );
    let out = std::process::Command::new("cmd")
        .creation_flags(0x08000000)
        .arg("/C")
        .arg(&set_mtu)
        .output()?;
    if !out.status.success() {
        log::error!("cmd={:?},out={:?}",set_mtu,out);
        return Err(io::Error::new(io::ErrorKind::Other, format!("设置mtu失败: {:?}", out)));
    }
    Ok(())
}
pub fn set_interface_metric(index: u32, metric: u16) -> io::Result<()> {
    let set_metric = format!("netsh interface ip set interface {} metric={}", index,metric);
    let out = std::process::Command::new("cmd")
        .creation_flags(0x08000000)
        .arg("/C")
        .arg(&set_metric)
        .output()?;
    if !out.status.success() {
        log::error!("cmd={:?},out={:?}",set_metric,out);
        return Err(io::Error::new(io::ErrorKind::Other, format!("设置metric失败: {:?}", out)));
    }
    Ok(())
}