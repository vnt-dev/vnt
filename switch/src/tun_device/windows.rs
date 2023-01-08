use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use libloading::Library;
use wintun::{Adapter, Packet, Session};

use crate::error::*;

pub struct TunWriter(Arc<Session>);

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
}

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
}

pub fn create_tun(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> Result<(TunWriter, TunReader)> {
    let win_tun = unsafe {
        match Library::new("wintun.dll") {
            Ok(library) => match wintun::load_from_library(library) {
                Ok(win_tun) => win_tun,
                Err(e) => {
                    return Err(Error::Stop(format!("{:?}", e)));
                }
            },
            Err(e) => {
                log::error!("wintun.dll not found");
                return Err(Error::Stop(format!("wintun.dll not found {:?}", e)));
            }
        }
    };
    let adapter = match Adapter::open(&win_tun, "Switch") {
        Ok(a) => a,
        Err(_) => match Adapter::create(&win_tun, "Switch", "Switch", None) {
            Ok(adapter) => adapter,

            Err(e) => return Err(Error::Stop(format!("{:?}", e))),
        },
    };
    let index = adapter.get_adapter_index().unwrap();
    let set_mtu = format!(
        "netsh interface ipv4 set subinterface {}  mtu=1420 store=persistent",
        index
    );
    let set_metric = format!("netsh interface ip set interface {} metric=1", index);
    let set_address = format!(
        "netsh interface ip set address {} static {:?} {:?}  ", // gateway={:?}
        index, address, netmask,
    );
    // println!("{}", set_mtu);
    // println!("{}", set_metric);
    // println!("{}", set_address);
    // 执行网卡初始化命令
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(set_mtu)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(Error::Stop(format!("设置mtu失败:{:?}", out)));
    }
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(set_metric)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(Error::Stop(format!("设置接口跃点失败:{:?}", out)));
    }
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(set_address)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(Error::Stop(format!("设置网络地址失败:{:?}", out)));
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
    // println!("{}", set_route);
    // 执行添加路由命令
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg(set_route)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(Error::Stop(format!("添加路由失败:{:?}", out)));
    }
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
    let reader_session = session.clone();
    Ok((TunWriter(session), TunReader(reader_session)))
}
