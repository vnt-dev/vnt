use std::io;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;

/// 添加路由
pub fn add_route(index: u32, dest: Ipv4Addr,
                 netmask: Ipv4Addr,
                 gateway: Ipv4Addr, metric: u16) -> io::Result<()> {
    let set_route = format!(
        "route add {:?} mask {:?} {:?} metric {} if {}",
        dest, netmask, gateway, metric, index
    );
    // 执行添加路由命令
    let out = std::process::Command::new("cmd")
        .creation_flags(0x08000000)
        .arg("/C")
        .arg(&set_route)
        .output()
        .unwrap();
    if !out.status.success() {
        log::error!("cmd={:?},out={:?}",set_route,out);
        return Err(io::Error::new(io::ErrorKind::Other, format!("添加路由失败: {:?}", out)));
    }
    Ok(())
}

/// 删除路由
pub fn delete_route(index: u32, dest: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
    if index == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("网络接口索引错误: {:?}", index)));
    }
    let delete_route = format!(
        "route delete  {:?} mask {:?} {:?} if {}",
        dest, netmask, gateway, index
    );
    // 删除路由
    let out = std::process::Command::new("cmd")
        .creation_flags(0x08000000)
        .arg("/C")
        .arg(delete_route)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("删除路由失败: {:?}", out)));
    }
    Ok(())
}