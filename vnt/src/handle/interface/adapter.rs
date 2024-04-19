use std::net::Ipv4Addr;
use std::{io, process, thread};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use crossbeam_utils::atomic::AtomicCell;
use tun::Device;
use tun::device::IFace;
use crate::handle::callback::DeviceConfig;
use crate::protocol::NetPacket;
use crate::util::{BufBlock, BufPool, GroupSyncSender, StopManager};

pub struct TunAdapter {
    #[cfg(any(target_os = "windows", target_os = "linux"))] is_tap: bool,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] device_name: Option<String>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] mtu: u32,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] route_record: Vec<(Ipv4Addr, Ipv4Addr)>,
    device: Option<Arc<Device>>,
    buf_pool: BufPool,
    stop_manager: StopManager,
    receiver_stage: Option<Receiver<NetPacket<BufBlock>>>,
    sender_stage: Option<SyncSender<NetPacket<BufBlock>>>,
}
impl TunAdapter {
    pub fn new(
        #[cfg(any(target_os = "windows", target_os = "linux"))] is_tap: bool,
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] device_name: Option<String>,
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] mtu: u32,
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] route_record: Vec<(Ipv4Addr, Ipv4Addr)>,
        buf_pool: BufPool,
        stop_manager: StopManager,
        receiver: Receiver<NetPacket<BufBlock>>,
        sender: SyncSender<NetPacket<BufBlock>>,
    )->Self{
        Self{
            #[cfg(any(target_os = "windows", target_os = "linux"))] is_tap,
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]  device_name,
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]  mtu,
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]   route_record,
            device: None,
            buf_pool,
            stop_manager,
            receiver_stage: Some(receiver),
            sender_stage: Some(sender),
        }
    }
}

impl TunAdapter {
    pub fn device(&mut self, #[cfg(target_os = "android")] device_fd: u32) -> io::Result<()> {
        if self.device.is_some() {
            return Ok(());
        } else {
            let device = create_device(#[cfg(any(target_os = "windows", target_os = "linux"))] self.is_tap,
                                       #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] self.device_name.clone(),
                                       #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] self.mtu,
                                       #[cfg(target_os = "android")] device_fd, )?;
            let device = Arc::new(device);
            self.device.replace(device);
            {
                let device = device.clone();
                let buf_pool = self.buf_pool.clone();
                let stop_manager = self.stop_manager.clone();
                let sender = self.sender_stage.take().unwrap();
                thread::Builder::new().name("tun-read".into()).spawn(move || {
                    loop {
                        let mut buf_block = buf_pool.alloc();
                        #[cfg(not(target_os = "macos"))]
                            let start = 12;
                        #[cfg(target_os = "macos")]
                            let start = 8;
                        match device.read(&mut buf_block.as_mut()[start..]) {
                            Ok(len) => {
                                buf_block.as_mut()[..12].fill(0);
                                buf_block.set_data_len(start + len);
                                if let Err(e) = sender.try_send(buf_block) {
                                    match e {
                                        TrySendError::Full(_) => {
                                            log::warn!("发生丢包");
                                        }
                                        TrySendError::Disconnected(_) => {
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("{:?}",e);
                                break;
                            }
                        }
                    }
                    stop_manager.stop();
                }).unwrap();
            }
            {
                let device = device.clone();
                let stop_manager = self.stop_manager.clone();
                let receiver = self.receiver_stage.take().unwrap();

                thread::Builder::new().name("tun-write".into()).spawn(move || {
                    while let Ok(data) = receiver.recv() {
                        if let Err(e) = device.write(data.as_data()) {
                            log::warn!("写入网卡失败:{}",e);
                            break;
                        }
                    }
                    stop_manager.stop();
                }).unwrap();
            }
        }
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub fn change_ip(&mut self, info: DeviceConfig) -> io::Result<()> {
        let device = if let Some(device) = &self.device {
            device
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "IFace"));
        };
        device.set_ip(info.virtual_ip, info.virtual_netmask)?;
        for (dest, mask) in self.route_record.drain(..) {
            if let Err(e) = self.device.delete_route(dest, mask) {
                log::warn!("删除路由失败 ={:?}", e);
            }
        }
        if let Err(e) = device.add_route(info.virtual_network, info.virtual_netmask, 1)
        {
            log::warn!("添加默认路由失败 ={:?}", e);
        } else {
            self.route_record.push((info.virtual_network, info.virtual_netmask));
        }
        if let Err(e) = device
            .add_route(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, 1)
        {
            log::warn!("添加广播路由失败 ={:?}", e);
        } else {
            self.route_record.push((Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST));
        }

        if let Err(e) = device.add_route(
            Ipv4Addr::from([224, 0, 0, 0]),
            Ipv4Addr::from([240, 0, 0, 0]),
            1,
        ) {
            log::warn!("添加组播路由失败 ={:?}", e);
        } else {
            self.route_record.push((
                Ipv4Addr::from([224, 0, 0, 0]),
                Ipv4Addr::from([240, 0, 0, 0]),
            ));
        }

        for (dest, mask) in info.external_route {
            if let Err(e) = self.device.add_route(dest, mask, 1) {
                log::warn!("添加路由失败 ={:?}", e);
            } else {
                self.route_record.push((dest, mask));
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
const DEFAULT_TUN_NAME: &str = "vnt-tun";
#[cfg(any(target_os = "windows", target_os = "linux"))]
const DEFAULT_TAP_NAME: &str = "vnt-tap";

pub fn create_device(#[cfg(any(target_os = "windows", target_os = "linux"))] is_tap: bool,
                     #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] device_name: Option<String>,
                     #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))] mtu: u32,
                     #[cfg(target_os = "android")] device_fd: u32, ) -> io::Result<Device> {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
        let default_name: &str = if is_tap {
        DEFAULT_TAP_NAME
    } else {
        DEFAULT_TUN_NAME
    };
    #[cfg(target_os = "linux")]
        let device = {
        let device_name = device_name
            .unwrap_or(default_name.to_string());
        if &device_name == default_name {
            delete_device(default_name);
        }
        Device::new(Some(device_name), is_tap)?
    };
    #[cfg(target_os = "macos")]
        let device = Device::new(device_name)?;
    #[cfg(target_os = "windows")]
        let device = Device::new(
        device_name
            .unwrap_or(default_name.to_string()),
        is_tap,
    )?;
    #[cfg(target_os = "android")]
        let device = Device::new(device_fd as _)?;
    #[cfg(not(target_os = "android"))]
    device.set_mtu(mtu)?;
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
        log::info!("{},{:?}",cmd, delete_tun);
    }
}

