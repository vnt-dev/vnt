use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tun_rs::SyncDevice;

use crate::{DeviceConfig, ErrorInfo, ErrorType, VntCallback};

#[cfg(any(target_os = "windows", target_os = "linux"))]
const DEFAULT_TUN_NAME: &str = "vnt-tun";

pub fn create_device<Call: VntCallback>(
    config: DeviceConfig,
    call: &Call,
) -> Result<Arc<SyncDevice>, ErrorInfo> {
    let device = match create_device0(&config) {
        Ok(device) => device,
        Err(e) => {
            return Err(ErrorInfo::new_msg(
                ErrorType::FailedToCrateDevice,
                format!("create device {:?}", e),
            ));
        }
    };
    #[cfg(windows)]
    let index = device.if_index().unwrap();
    #[cfg(unix)]
    let index = &device.name().unwrap();
    if let Err(e) = add_route(index, Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST) {
        log::warn!("添加广播路由失败 ={:?}", e);
    }

    if let Err(e) = add_route(
        index,
        Ipv4Addr::from([224, 0, 0, 0]),
        Ipv4Addr::from([240, 0, 0, 0]),
    ) {
        log::warn!("添加组播路由失败 ={:?}", e);
    }

    for (dest, mask) in config.external_route {
        if let Err(e) = add_route(index, dest, mask) {
            log::warn!("添加路由失败,请检查-i参数是否和现有路由冲突 ={:?}", e);
            call.error(ErrorInfo::new_msg(
                ErrorType::Warn,
                format!(
                    "警告！ 添加路由失败,请检查-i参数是否和现有路由冲突 ={:?}",
                    e
                ),
            ))
        }
    }
    Ok(device)
}

fn create_device0(config: &DeviceConfig) -> io::Result<Arc<SyncDevice>> {
    let mut tun_builder = tun_rs::DeviceBuilder::default();
    tun_builder = tun_builder.ipv4(config.virtual_ip, config.virtual_netmask, None);

    match &config.device_name {
        None => {
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            {
                tun_builder = tun_builder.name(DEFAULT_TUN_NAME);
            }
        }
        Some(name) => {
            tun_builder = tun_builder.name(name);
        }
    }

    #[cfg(target_os = "windows")]
    {
        tun_builder = tun_builder.metric(0).ring_capacity(4 * 1024 * 1024);
    }

    #[cfg(target_os = "linux")]
    {
        let device_name = config
            .device_name
            .clone()
            .unwrap_or(DEFAULT_TUN_NAME.to_string());
        if &device_name == DEFAULT_TUN_NAME {
            delete_device(DEFAULT_TUN_NAME);
        }
    }

    let device = tun_builder.mtu(config.mtu as u16).build_sync()?;
    Ok(Arc::new(device))
}

#[cfg(target_os = "linux")]
fn delete_device(name: &str) {
    // 删除默认网卡，此操作有风险，后续可能去除
    use std::process::Command;
    let cmd = format!("ip link delete {}", name);
    let delete_tun = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("sh exec error!");
    if !delete_tun.status.success() {
        log::warn!("删除网卡失败:{:?}", delete_tun);
    }
}

#[cfg(target_os = "windows")]
pub fn add_route(index: u32, dest: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let cmd = format!(
        "route add {:?} mask {:?} {:?} metric {} if {}",
        dest,
        netmask,
        Ipv4Addr::UNSPECIFIED,
        1,
        index
    );
    exe_cmd(&cmd)
}
#[cfg(target_os = "windows")]
pub fn exe_cmd(cmd: &str) -> io::Result<()> {
    use std::os::windows::process::CommandExt;

    println!("exe cmd: {}", cmd);
    let out = std::process::Command::new("cmd")
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .arg("/C")
        .arg(&cmd)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={},out={:?}", cmd, String::from_utf8(out.stderr)),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn add_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let cmd = format!(
        "route -n add {} -netmask {} -interface {}",
        address, netmask, name
    );
    exe_cmd(&cmd)?;
    Ok(())
}
#[cfg(target_os = "linux")]
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
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn exe_cmd(cmd: &str) -> io::Result<std::process::Output> {
    use std::process::Command;
    println!("exe cmd: {}", cmd);
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("sh exec error!");
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={},out={:?}", cmd, out),
        ));
    }
    Ok(out)
}
