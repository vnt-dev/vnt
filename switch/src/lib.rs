use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::sync::atomic::Ordering;

use crossbeam::sync::WaitGroup;
use tokio::sync::watch;

use error::*;

use crate::handle::{ApplicationStatus, ConnectStatus, CurrentDeviceInfo, DEVICE_LIST, DIRECT_ROUTE_TABLE, Route, RouteType, SERVER_RT};
use crate::handle::registration_handler::CONNECTION_STATUS;

pub mod tun_device;
pub mod nat;
pub mod error;
pub mod handle;
pub mod proto;
pub mod protocol;

#[derive(Clone, Debug)]
pub struct Config {
    pub token: String,
    pub mac_address: String,
}

impl Config {
    pub fn new(token: String, mac_address: String) -> Self {
        Self {
            token,
            mac_address,
        }
    }
}

pub struct Switch {
    current_device: CurrentDeviceInfo,
    status_sender: watch::Sender<ApplicationStatus>,
    wait_group: WaitGroup,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Switch {
    pub fn start(config: Config) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        return match runtime.block_on(Switch::start_(config.token, config.mac_address)) {
            Ok(mut switch) => {
                switch.runtime = Some(runtime);
                Ok(switch)
            }
            Err(e) => {
                Err(e)
            }
        };
    }
    pub fn stop(self) {
        let _ = self.status_sender.send(ApplicationStatus::Stopping);
        self.wait_group.wait();
    }
    pub fn current_device(&self) -> &CurrentDeviceInfo {
        &self.current_device
    }
    pub fn server_rt(&self) -> i64 {
        SERVER_RT.load(Ordering::Relaxed)
    }
    pub fn connection_status(&self) -> ConnectStatus {
        CONNECTION_STATUS.load()
    }
    pub fn device_list(&self) -> Vec<Ipv4Addr> {
        let device_list_lock = DEVICE_LIST.lock();
        let (_epoch, device_list) = device_list_lock.clone();
        drop(device_list_lock);
        device_list
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Route {
        if let Some(route_ref) = DIRECT_ROUTE_TABLE.get(ip) {
            route_ref.value().clone()
        } else {
            let mut route = Route::new(self.current_device.connect_server);
            route.route_type = RouteType::ServerRelay;
            route.rt = self.server_rt() * 2;
            route.recv_time = -1;
            route
        }
    }
}

impl Switch {
    pub async fn start_(token: String, mac_address: String) -> Result<Self> {
        let server_address = "nat1.wherewego.top:29876".to_socket_addrs().unwrap().next().unwrap();
        let mut port = 101 as u16;
        let udp = loop {
            match UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), port))) {
                Ok(udp) => {
                    break udp;
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::AddrInUse {
                        port += 1;
                    } else {
                        log::error!("创建udp失败 {:?}",e);
                        return Err(Error::Stop("udp bind error".to_string()));
                    }
                }
            }
        };
        //注册
        let response = handle::registration_handler::registration(&udp, server_address, token, mac_address)?;
        {
            let ip_list = response
                .virtual_ip_list
                .iter()
                .map(|ip| Ipv4Addr::from(*ip))
                .collect();
            let mut dev = DEVICE_LIST.lock();
            dev.0 = response.epoch;
            dev.1 = ip_list;
        }
        let virtual_ip = Ipv4Addr::from(response.virtual_ip);
        let virtual_gateway = Ipv4Addr::from(response.virtual_gateway);
        let virtual_netmask = Ipv4Addr::from(response.virtual_netmask);
        let (status_sender, status_receiver) = tokio::sync::watch::channel(ApplicationStatus::Starting);
        let current_device = CurrentDeviceInfo::new(virtual_ip, virtual_gateway, virtual_netmask, server_address);
        let wait_group = WaitGroup::new();
        //心跳线程
        {
            let udp = udp.try_clone()?;
            let wait_group1 = wait_group.clone();
            handle::heartbeat_handler::start(status_receiver.clone(), udp, current_device, || {
                drop(wait_group1);
            }).await;
        }
        //初始化nat数据
        handle::init_nat_info(response.public_ip, response.public_port as u16);
        // tun服务
        let (tun_writer, tun_reader) =
            tun_device::create_tun(virtual_ip, virtual_netmask, virtual_gateway)?;
        // 打洞数据通道
        let (punch_sender, cone_receiver, req_symmetric_receiver, res_symmetric_receiver) = handle::punch_handler::bounded();
        //udp数据处理
        {
            // 低优先级的udp数据通道
            let (sender, receiver) = tokio::sync::mpsc::channel(50);
            let udp1 = udp.try_clone()?;
            let wait_group1 = wait_group.clone();
            handle::udp_recv_handler::udp_recv_start(
                status_receiver.clone(),
                udp1,
                server_address,
                sender,
                tun_writer,
                current_device,
                || {
                    drop(wait_group1);
                },
            ).await;
            let udp1 = udp.try_clone()?;
            let wait_group1 = wait_group.clone();
            handle::udp_recv_handler::udp_other_recv_start(status_receiver.clone(), udp1,
                                                           receiver, current_device, punch_sender,
                                                           || {
                                                               drop(wait_group1);
                                                           }).await;
        }
        //打洞处理
        {
            let udp1 = udp.try_clone()?;
            let wait_group1 = wait_group.clone();
            handle::punch_handler::cone_handler_start(status_receiver.clone(),
                                                      cone_receiver, udp1,
                                                      current_device,
                                                      || {
                                                          drop(wait_group1);
                                                      }).await;
            let udp1 = udp.try_clone()?;
            let wait_group1 = wait_group.clone();
            handle::punch_handler::req_symmetric_handler_start(status_receiver.clone(),
                                                               req_symmetric_receiver, udp1,
                                                               current_device,
                                                               || {
                                                                   drop(wait_group1);
                                                               }).await;
            let udp1 = udp.try_clone()?;
            let wait_group1 = wait_group.clone();
            handle::punch_handler::res_symmetric_handler_start(status_receiver.clone(),
                                                               res_symmetric_receiver,
                                                               udp1,
                                                               current_device,
                                                               || {
                                                                   drop(wait_group1);
                                                               }).await;
        }
        //tun数据处理
        {
            let wait_group1 = wait_group.clone();
            handle::tun_handler::handler_start(status_receiver.clone(), udp,
                                               tun_reader, current_device,
                                               || {
                                                   drop(wait_group1);
                                               }).await;
        }
        Ok(Switch {
            current_device,
            status_sender,
            wait_group,
            runtime: None,
        })
    }
}