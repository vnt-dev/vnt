use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use libloading::Library;
use parking_lot::Mutex;
use wintun::{Adapter, Packet, Session};

pub const INTERFACE_NAME: &str = "Switch-V1";
pub const POOL_NAME: &str = "Switch-V1";

#[derive(Clone)]
pub struct TunWriter(Arc<Session>, Arc<Mutex<u32>>);

impl TunWriter {
    pub fn write(&self, buf: &[u8]) -> io::Result<()> {
        match self.0.allocate_send_packet(buf.len() as u16) {
            Ok(mut packet) => {
                packet.bytes_mut().copy_from_slice(buf);
                self.0.send_packet(packet);
                return Ok(());
            }
            Err(_) => {}
        }
        return Err(io::Error::new(io::ErrorKind::Other, "send err"));
    }
    pub fn change_ip(&self, address: Ipv4Addr, netmask: Ipv4Addr,
                     gateway: Ipv4Addr, old_netmask: Ipv4Addr, old_gateway: Ipv4Addr) -> io::Result<()> {
        let index = self.1.lock();
        if let Err(e) = delete_route(*index, old_netmask, old_gateway) {
            log::warn!("{:?}",e);
        }
        config_ip(*index, address, netmask, gateway)
    }
}

#[derive(Clone)]
pub struct TunReader(pub(crate) Arc<Session>);


impl TunReader {
    pub fn next(&self) -> io::Result<Packet> {
        match self.0.receive_blocking() {
            Ok(packet) => {
                return Ok(packet);
            }
            Err(_) => {}
        }
        return Err(io::Error::new(io::ErrorKind::Other, "read err"));
    }
    pub fn close(&self) {
        self.0.shutdown()
    }
}

pub fn create_tun(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> io::Result<(TunWriter, TunReader)> {
    let win_tun = unsafe {
        match Library::new("wintun.dll") {
            Ok(library) => match wintun::load_from_library(library) {
                Ok(win_tun) => win_tun,
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e)));
                }
            },
            Err(e) => {
                log::error!("wintun.dll not found");
                return Err(io::Error::new(io::ErrorKind::Other, format!("wintun.dll not found {:?}", e)));
            }
        }
    };
    if let Ok(adapter) = Adapter::open(&win_tun, INTERFACE_NAME) {
        log::warn!("Switch-V1 未正常退出");
        drop(adapter);
        std::thread::sleep(std::time::Duration::from_secs(1));
    };
    let adapter = match Adapter::create(&win_tun, POOL_NAME, INTERFACE_NAME, None) {
        Ok(adapter) => adapter,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e))),
    };
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
    let index = match adapter.get_adapter_index() {
        Ok(index) => {
            index
        }
        Err(e) => {
            log::error!("get_adapter_index err {:?}",e);
            get_if_index()
        }
    };
    config_ip(index, address, netmask, gateway)?;
    let reader_session = session.clone();
    Ok((TunWriter(session.clone(), Arc::new(Mutex::new(index))), TunReader(reader_session)))
}

fn get_if_index() -> u32 {
    let cmd = format!("netsh int ipv4 show interfaces  {} |findstr IfIndex", INTERFACE_NAME);
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(&cmd)
        .output()
        .unwrap();
    if !out.status.success() {
        log::warn!("1获取网络接口索引失败：cmd={:?},out={:?}",cmd,out);
        return 0;
    }
    if let Ok(stdout) = String::from_utf8(out.stdout) {
        if let Some(start) = stdout.find(":") {
            if let Some(end) = stdout.find("\r\n") {
                if let Ok(index) = stdout[start + 1..end].trim().parse::<u32>() {
                    return index;
                }
            }
        }
    }
    log::warn!("2获取网络接口索引失败：cmd={:?}",cmd);
    0
}

fn config_ip(index: u32, address: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
    if index == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("网络接口索引错误: {:?}", index)));
    }
    let set_mtu = format!(
        "netsh interface ipv4 set subinterface {}  mtu=1420 store=persistent",
        index
    );
    let set_metric = format!("netsh interface ip set interface {} metric=1", index);
    let set_address = format!(
        "netsh interface ip set address {} static {:?} {:?}  ", // gateway={:?}
        index, address, netmask,
    );
    // 执行网卡初始化命令
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(set_mtu)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("设置mtu失败: {:?}", out)));
    }
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(set_metric)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("设置接口跃点失败: {:?}", out)));
    }
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(&set_address)
        .output()
        .unwrap();
    if !out.status.success() {
        log::error!("cmd={:?},out={:?}",set_address,out);
        return Err(io::Error::new(io::ErrorKind::Other, format!("设置网络地址失败: {:?}", out)));
    }
    let dest = {
        let ip = address.octets();
        let mask = netmask.octets();
        Ipv4Addr::from([
            ip[0] & mask[0],
            ip[1] & mask[1],
            ip[2] & mask[2],
            ip[3] & mask[3],
        ])
    };
    let set_route = format!(
        "route add {:?} mask {:?} {:?} if {}",
        dest, netmask, gateway, index
    );
    // 执行添加路由命令
    let out = std::process::Command::new("cmd")
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

fn delete_route(index: u32, netmask: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
    if index == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("网络接口索引错误: {:?}", index)));
    }
    let mask = netmask.octets();
    let ip = gateway.octets();
    let dest = Ipv4Addr::from([
        ip[0] & mask[0],
        ip[1] & mask[1],
        ip[2] & mask[2],
        ip[3] & mask[3],
    ]);
    let delete_route = format!(
        "route delete  {:?} mask {:?} {:?} if {}",
        dest, netmask, gateway, index
    );
    // 删除路由
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(delete_route)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("删除路由失败: {:?}", out)));
    }
    Ok(())
}
