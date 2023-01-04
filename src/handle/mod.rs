use std::net::{ Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicI64;
use std::time::Duration;

use chrono::Local;
use dashmap::DashMap;
use lazy_static::lazy_static;
use moka::sync::Cache;
use parking_lot::{const_mutex, Mutex};

use crate::proto::message::NatType;

pub mod heartbeat_handler;
pub mod punch_handler;
pub mod registration_handler;
pub mod tun_handler;
pub mod udp_recv_handler;
lazy_static! {
    /// 0. 机器纪元，每一次上线或者下线都会增1，由服务端维护，用于感知网络中机器变化
    /// 服务端和客户端的不一致，则服务端会推送新的设备列表
    /// 1. 网络中的虚拟ip列表
    pub static ref DEVICE_LIST:Mutex<(u32,Vec<Ipv4Addr>)> = const_mutex((0,Vec::new()));
    /// 服务器延迟
    pub static ref SERVER_RT:AtomicI64 = AtomicI64::new(-1);
    /// id
    pub static ref ID:AtomicI64 = AtomicI64::new(0);
    /// 直连路由表
    pub static ref DIRECT_ROUTE_TABLE:DashMap<Ipv4Addr,Route> = DashMap::new();
    /// 地址映射
    pub static ref ADDR_TABLE:Cache<SocketAddr,Ipv4Addr> = Cache::builder()
        .time_to_idle(Duration::from_secs(60*5)).build();
    /// 当前设备的nat信息
    pub static ref NAT_INFO:Mutex<Option<NatInfo>> = const_mutex(None);
}

#[derive(Clone, Debug)]
pub struct NatInfo {
    public_ips: Vec<u32>,
    public_port: u16,
    public_port_range: u16,
    nat_type: NatType,
}

impl NatInfo {
    pub fn new(public_ips: Vec<u32>,
               public_port: u16,
               public_port_range: u16,
               nat_type: NatType, ) -> Self {
        Self {
            public_ips,
            public_port,
            public_port_range,
            nat_type,
        }
    }
}

/// 初始化nat信息
pub fn init_nat_info(public_ip: u32, public_port: u16) {
    match crate::nat::check::public_ip_list() {
        Ok((nat_type, ips, port_range)) => {
            let mut public_ips = Vec::new();
            public_ips.push(public_ip);
            for ip in ips {
                let ip = u32::from_be_bytes(ip.octets());
                if ip != public_ip {
                    public_ips.push(ip);
                }
            }
            let nat_info = NatInfo::new(public_ips,
                                        public_port,
                                        port_range, nat_type);
            // println!("nat信息:{:?}",nat_info);
            let mut nat_info_lock = NAT_INFO.lock();
            nat_info_lock.replace(nat_info);
        }
        Err(e) => {
            println!("获取nat数据失败，将无法进行udp打洞:{:?}", e);
        }
    }
}

#[derive(Clone, Debug)]
pub struct CurrentDeviceInfo {
    pub(crate) virtual_ip: Ipv4Addr,
    pub(crate) virtual_gateway: Ipv4Addr,
    pub(crate)  virtual_netmask: Ipv4Addr,
    //网络地址
    pub(crate)  virtual_network: Ipv4Addr,
    //直接广播地址
    pub(crate)   broadcast_address: Ipv4Addr,
    //链接的服务器地址
    pub(crate)  connect_server: SocketAddr,
}

impl CurrentDeviceInfo {
    pub fn new(virtual_ip: Ipv4Addr, virtual_gateway: Ipv4Addr, virtual_netmask: Ipv4Addr, connect_server: SocketAddr) -> Self {
        let broadcast_address = (!u32::from_be_bytes(virtual_netmask.octets()))
            | u32::from_be_bytes(virtual_gateway.octets());
        let broadcast_address = Ipv4Addr::from(broadcast_address);
        let virtual_network = u32::from_be_bytes(virtual_netmask.octets())
            & u32::from_be_bytes(virtual_gateway.octets());
        let virtual_network = Ipv4Addr::from(virtual_network);
        Self {
            virtual_ip,
            virtual_netmask,
            virtual_gateway,
            virtual_network,
            broadcast_address,
            connect_server,
        }
    }
}

#[derive(Clone,Debug)]
pub struct Route {
    pub(crate) address: SocketAddr,
    //用心跳探测延迟，收包时更新
    pub(crate) delay: i64,
    //收包时更新，如果太久没有收到消息则剔除
    pub(crate) recv_time: i64,
}

impl Route {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            delay: -1,
            recv_time: Local::now().timestamp_millis(),
        }
    }
}
