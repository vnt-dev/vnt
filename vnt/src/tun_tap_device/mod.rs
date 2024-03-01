use std::io;
use std::sync::Arc;

use tun::device::IFace;
use tun::Device;

use crate::core::Config;

const DEFAULT_NAME: &str = "vnt0";

pub fn create_device(config: &Config) -> io::Result<Arc<Device>> {
    #[cfg(target_os = "linux")]
    let device = {
        let device_name = config
            .device_name
            .clone()
            .unwrap_or(DEFAULT_NAME.to_string());
        if &device_name == DEFAULT_NAME {
            delete_device();
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
            .unwrap_or(DEFAULT_NAME.to_string()),
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
fn delete_device() {
    // 删除默认网卡，此操作有风险，后续可能去除
    use std::process::Command;
    let cmd = format!("ip link delete {}", DEFAULT_NAME);
    let delete_tun = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("sh exec error!");
    if !delete_tun.status.success() {
        log::warn!("删除网卡失败:{:?}", delete_tun);
    }
}
