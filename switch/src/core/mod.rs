use std::{io, thread};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use aes_gcm::{Aes256Gcm, Key, KeyInit};

use crossbeam_utils::atomic::AtomicCell;
use crossbeam_skiplist::SkipMap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;


use crate::channel::channel::{Channel, Context};
use crate::channel::idle::Idle;
use crate::channel::punch::{NatInfo, Punch};
use crate::channel::{Route, RouteKey};
use crate::channel::sender::ChannelSender;

use crate::external_route::ExternalRoute;
use crate::handle::{ConnectStatus, CurrentDeviceInfo, heartbeat_handler, PeerDeviceInfo, punch_handler, registration_handler};
use crate::handle::recv_handler::ChannelDataHandler;
use crate::handle::tun_tap::{tap_handler, tun_handler};
use crate::igmp_server::IgmpServer;
use crate::nat::NatTest;
use crate::tun_tap_device;
use crate::tun_tap_device::DeviceWriter;

pub struct Switch {
    name: String,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    context: Context,
    device_writer: DeviceWriter,
    /// 0. 机器纪元，每一次上线或者下线都会增1，用于感知网络中机器变化
    /// 服务端和客户端的不一致，则服务端会推送新的设备列表
    /// 1. 网络中的虚拟ip列表
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    nat_test: NatTest,
    connect_status: Arc<AtomicCell<ConnectStatus>>,
    peer_nat_info_map: Arc<SkipMap<Ipv4Addr, NatInfo>>,
}

impl Switch {
    pub async fn start(config: Config) -> crate::Result<Switch> {
        log::info!("config:{:?}",config);
        let cipher = if let Some(key) = &config.key {
            let key: &Key<Aes256Gcm> = key.into();
            Some(Aes256Gcm::new(&key))
        } else {
            None
        };
        let main_channel = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let response = registration_handler::registration(&main_channel, config.server_address, config.token.clone(), config.device_id.clone(), config.name.clone()).await?;
        let (cone_sender, cone_receiver) = channel(3);
        let (symmetric_sender, symmetric_receiver) = channel(2);
        let context = Context::new(main_channel, 1);
        let punch = Punch::new(context.clone());
        let idle = Idle::new(Duration::from_secs(16), context.clone());
        let channel_sender = ChannelSender::new(context.clone());

        let register = Arc::new(registration_handler::Register::new(channel_sender.clone(), config.server_address, config.token.clone(), config.device_id.clone(), config.name.clone()));
        let device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>> = Arc::new(Mutex::new((0, Vec::new())));
        let peer_nat_info_map: Arc<SkipMap<Ipv4Addr, NatInfo>> = Arc::new(SkipMap::new());
        let connect_status = Arc::new(AtomicCell::new(ConnectStatus::Connected));
        let virtual_ip = Ipv4Addr::from(response.virtual_ip);
        let virtual_gateway = Ipv4Addr::from(response.virtual_gateway);
        let virtual_netmask = Ipv4Addr::from(response.virtual_netmask);

        let local_ip = crate::nat::local_ip()?;
        let local_port = context.main_local_port()?;
        // NAT检测
        let nat_test = NatTest::new(config.nat_test_server.clone(), Ipv4Addr::from(response.public_ip), response.public_port as u16, local_ip, local_port);
        let in_ips = config.in_ips.iter().map(|(dest, mask, _)| { (Ipv4Addr::from(*dest & *mask), Ipv4Addr::from(*mask)) }).collect::<Vec<(Ipv4Addr, Ipv4Addr)>>();

        let out_ips = config.out_ips.iter().map(|(_, _, ip)| *ip).collect::<Vec<Ipv4Addr>>();
        let out_external_route = ExternalRoute::new(config.out_ips);
        let in_external_route = if config.in_ips.is_empty() {
            None
        } else {
            Some(ExternalRoute::new(config.in_ips))
        };
        let current_device = Arc::new(AtomicCell::new(CurrentDeviceInfo::new(virtual_ip, virtual_gateway, virtual_netmask, config.server_address)));
        let ip_proxy_map = if out_ips.is_empty(){
            None
        }else{
            Some(crate::ip_proxy::init_proxy(channel_sender.clone(), out_ips, current_device.clone()).await?)
        };
        let (device_writer, igmp_server) = if config.tap {
            #[cfg(windows)]
            {
                //删除switch的tun网卡避免ip冲突，因为非正常退出会保留网卡
                tun_tap_device::delete_device(tun_tap_device::DeviceType::Tap);
            }
            let (tap_writer, tap_reader) = tun_tap_device::create_device(tun_tap_device::DeviceType::Tap, virtual_ip, virtual_netmask, virtual_gateway, in_ips)?;
            let igmp_server = if config.simulate_multicast {
                Some(IgmpServer::new(tap_writer.clone()))
            } else {
                None
            };
            //tap数据处理
            tap_handler::start(channel_sender.clone(), tap_reader.clone(), tap_writer.clone(),
                               igmp_server.clone(), current_device.clone(), in_external_route, ip_proxy_map.clone(), cipher.clone());
            (tap_writer, igmp_server)
        } else {
            #[cfg(windows)]
            {
                //删除switch的tap网卡避免ip冲突，非正常退出会保留网卡
                tun_tap_device::delete_device(tun_tap_device::DeviceType::Tap);
            }
            // tun通道
            let (tun_writer, tun_reader) = tun_tap_device::create_device(tun_tap_device::DeviceType::Tun, virtual_ip, virtual_netmask, virtual_gateway, in_ips)?;
            let igmp_server = if config.simulate_multicast {
                Some(IgmpServer::new(tun_writer.clone()))
            } else {
                None
            };
            //tun数据接收处理
            tun_handler::start(channel_sender.clone(), tun_reader.clone(), tun_writer.clone(),
                               igmp_server.clone(), current_device.clone(), in_external_route, ip_proxy_map.clone(), cipher.clone());
            (tun_writer, igmp_server)
        };
        //外部数据接收处理
        let channel_recv_handler = ChannelDataHandler::new(current_device.clone(), device_list.clone(),
                                                           register.clone(), nat_test.clone(), igmp_server,
                                                           device_writer.clone(), connect_status.clone(),
                                                           peer_nat_info_map.clone(), ip_proxy_map, out_external_route,
                                                           cone_sender, symmetric_sender, cipher);
        let channel = Channel::new(context.clone(), channel_recv_handler);
        thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build().unwrap()
                .block_on(channel.start(14, 60));
        });
        context.switch(nat_test.nat_info().nat_type);
        // 定时心跳
        heartbeat_handler::start_heartbeat(channel_sender.clone(), device_list.clone(), current_device.clone()).await;
        // 空闲检查
        heartbeat_handler::start_idle(idle, channel_sender.clone()).await;
        // 打洞处理
        punch_handler::start(cone_receiver, punch.clone(), current_device.clone()).await;
        punch_handler::start(symmetric_receiver, punch, current_device.clone()).await;
        punch_handler::start_punch(nat_test.clone(), device_list.clone(), channel_sender.clone(), current_device.clone()).await;

        log::info!("switch启动成功");
        Ok(Switch {
            name: config.name,
            current_device,
            context,
            device_writer,
            nat_test,
            device_list,
            connect_status,
            peer_nat_info_map,
        })
    }
}

impl Switch {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.current_device.load()
    }
    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.peer_nat_info_map.get(ip).map(|e| e.value().clone())
    }
    pub fn connection_status(&self) -> ConnectStatus {
        self.connect_status.load()
    }
    pub fn nat_info(&self) -> NatInfo {
        self.nat_test.nat_info()
    }
    pub fn device_list(&self) -> Vec<PeerDeviceInfo> {
        let device_list_lock = self.device_list.lock();
        let (_epoch, device_list) = device_list_lock.clone();
        drop(device_list_lock);
        device_list
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Route> {
        self.context.route_one(ip)
    }
    pub fn route_key(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        self.context.route_to_id(route_key)
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Route)> {
        self.context.route_table_one()
    }
    pub fn stop(&self) -> io::Result<()> {
        self.context.close();
        self.device_writer.close()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub tap: bool,
    pub token: String,
    pub device_id: String,
    pub name: String,
    pub server_address: SocketAddr,
    pub nat_test_server: Vec<SocketAddr>,
    pub in_ips: Vec<(u32, u32, Ipv4Addr)>,
    pub out_ips: Vec<(u32, u32, Ipv4Addr)>,
    pub key: Option<[u8; 32]>,
    pub simulate_multicast: bool,
}

use sha2::Digest;

impl Config {
    pub fn new(tap: bool, token: String,
               device_id: String,
               name: String,
               server_address: SocketAddr,
               nat_test_server: Vec<SocketAddr>,
               in_ips: Vec<(u32, u32, Ipv4Addr)>, out_ips: Vec<(u32, u32, Ipv4Addr)>,
               password: Option<String>, simulate_multicast: bool, ) -> Self {
        let key = if let Some(password) = password {
            let mut hasher = sha2::Sha256::new();
            hasher.update(password.as_bytes());
            let key: [u8; 32] = hasher.finalize().into();
            Some(key)
        } else {
            None
        };
        Self {
            tap,
            token,
            device_id,
            name,
            server_address,
            nat_test_server,
            in_ips,
            out_ips,
            key,
            simulate_multicast,
        }
    }
}