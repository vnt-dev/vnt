use std::io;
use std::sync::Arc;

use tun::device::IFace;
use tun::Device;

use crate::core::Config;

const DEFAULT_TUN_NAME: &str = "vnt-tun";
const DEFAULT_TAP_NAME: &str = "vnt-tap";

pub fn create_device(config: &Config) -> io::Result<Arc<Device>> {
    let default_name: &str = if config.tap {
        DEFAULT_TAP_NAME
    } else {
        DEFAULT_TUN_NAME
    };
    #[cfg(target_os = "linux")]
    let device = {
        let device_name = config
            .device_name
            .clone()
            .unwrap_or(default_name.to_string());
        if &device_name == default_name {
            delete_device(default_name);
        }
        Arc::new(Device::new(Some(device_name), config.tap)?)
    };
    #[cfg(target_os = "macos")]
    let device = Arc::new(Device::new(config.device_name.clone())?);
    #[cfg(target_os = "windows")]
    let device = Arc::new(Device::new(
        config
            .device_name
            .clone()
            .unwrap_or(default_name.to_string()),
        config.tap,
    )?);
    #[cfg(target_os = "android")]
    let device = Arc::new(Device::new(config.device_fd as _)?);
    #[cfg(not(target_os = "android"))]
    {
        let mtu = config.mtu.unwrap_or_else(|| {
            if config.password.is_none() {
                1450
            } else {
                1410
            }
        });
        device.set_mtu(mtu)?;
    }
    Ok(device)
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
