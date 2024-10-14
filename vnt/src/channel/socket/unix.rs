use crate::channel::socket::{LocalInterface, VntSocketTrait};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;

#[cfg(target_os = "linux")]
impl VntSocketTrait for socket2::Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> anyhow::Result<()> {
        if let Some(name) = &interface.name {
            self.bind_device(Some(name.as_bytes()))
                .context("bind_device")?;
        }
        Ok(())
    }
}
#[cfg(target_os = "macos")]
impl VntSocketTrait for socket2::Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> anyhow::Result<()> {
        if interface.index != 0 {
            self.bind_device_by_index_v4(std::num::NonZeroU32::new(interface.index))
                .with_context(|| format!("bind_device_by_index_v4 {:?}", interface))?;
        }
        Ok(())
    }
}
#[cfg(target_os = "android")]
impl VntSocketTrait for socket2::Socket {
    fn set_ip_unicast_if(&self, _interface: &LocalInterface) -> anyhow::Result<()> {
        Ok(())
    }
}

// #[cfg(any(target_os = "linux", target_os = "macos"))]
// pub fn get_best_interface(dest_ip: Ipv4Addr) -> anyhow::Result<LocalInterface> {
//     match get_interface(dest_ip) {
//         Ok(iface) => return Ok(iface),
//         Err(e) => {
//             log::warn!("not find interface e={:?},ip={}", e, dest_ip);
//         }
//     }
//     // 应该再查路由表找到默认路由的
//     Ok(LocalInterface::default())
// }
// #[cfg(target_os = "android")]
// pub fn get_best_interface(_dest_ip: Ipv4Addr) -> anyhow::Result<LocalInterface> {
//     Ok(LocalInterface::default())
// }
