use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};
use rand::Rng;

use tun::device::IFace;

use crate::channel::context::Context;
use crate::channel::idle::Idle;
use crate::channel::punch::{NatInfo, Punch};
use crate::channel::{init_channel, init_context, Route, RouteKey, UseChannelType};
use crate::cipher::Cipher;
#[cfg(feature = "server_encrypt")]
use crate::cipher::RsaCipher;
use crate::core::Config;
use crate::external_route::{AllowExternalRoute, ExternalRoute};
use crate::handle::recv_data::RecvDataHandler;
use crate::handle::{
    maintain, tun_tap, BaseConfigInfo, ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo,
};
use crate::nat::NatTest;
use crate::util::{
    Scheduler, SingleU64Adder, StopManager, U64Adder, WatchSingleU64Adder, WatchU64Adder,
};
use crate::{nat, tun_tap_device, DeviceInfo, VntCallback};

#[derive(Clone)]
pub struct Vnt {
    stop_manager: StopManager,
    config: Config,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    context: Context,
    peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
    down_count_watcher: WatchU64Adder,
    up_count_watcher: WatchSingleU64Adder,
}

impl Vnt {
    pub fn new<Call: VntCallback>(config: Config, callback: Call) -> io::Result<Self> {
        //服务端非对称加密
        #[cfg(feature = "server_encrypt")]
        let rsa_cipher: Arc<Mutex<Option<RsaCipher>>> = Arc::new(Mutex::new(None));
        //服务端对称加密
        let server_cipher: Cipher = if config.server_encrypt {
            let mut key = [0u8; 32];
            rand::thread_rng().fill(&mut key);
            Cipher::new_key(key, config.token.clone())?
        } else {
            Cipher::None
        };
        let finger = if config.finger {
            Some(config.token.clone())
        } else {
            None
        };
        //客户端对称加密
        let client_cipher =
            Cipher::new_password(config.cipher_model, config.password.clone(), finger);
        //当前设备信息
        let current_device = Arc::new(AtomicCell::new(CurrentDeviceInfo::new0(
            config.server_address,
        )));
        //设备列表
        let device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>> =
            Arc::new(Mutex::new((0, Vec::with_capacity(16))));
        //基础信息
        let config_info = BaseConfigInfo::new(
            config.name.clone(),
            config.token.clone(),
            config.ip,
            config.password.is_some(),
            config.device_id.clone(),
            config.server_address_str.clone(),
        );
        let ports = config.ports.as_ref().map_or(vec![0, 0], |v| {
            if v.is_empty() {
                vec![0, 0]
            } else {
                v.clone()
            }
        });
        //通道上下文
        let (context, tcp_listener) = init_context(
            ports,
            config.use_channel_type,
            config.first_latency,
            config.tcp,
        )?;
        let local_ipv4 = nat::local_ipv4();
        let local_ipv6 = nat::local_ipv6();
        let udp_ports = context.main_local_udp_port()?;
        let tcp_port = tcp_listener.local_addr()?.port();
        //nat检测工具
        let nat_test = NatTest::new(
            config.stun_server.clone(),
            local_ipv4,
            local_ipv6,
            udp_ports,
            tcp_port,
        );

        // 虚拟网卡
        let device = tun_tap_device::create_device(&config)?;
        let tun_info = DeviceInfo::new(device.name()?, device.version()?);
        callback.create_tun(tun_info);
        // 服务停止管理器
        let stop_manager = {
            let callback = callback.clone();
            StopManager::new(move || callback.stop())
        };
        // 定时器
        let scheduler = Scheduler::new(stop_manager.clone())?;
        let external_route = ExternalRoute::new(config.in_ips.clone());
        let out_external_route = AllowExternalRoute::new(config.out_ips.clone());

        #[cfg(feature = "ip_proxy")]
        let proxy_map = if !config.out_ips.is_empty() && !config.no_proxy {
            Some(crate::ip_proxy::init_proxy(
                context.clone(),
                scheduler.clone(),
                stop_manager.clone(),
                current_device.clone(),
                client_cipher.clone(),
            )?)
        } else {
            None
        };
        let (punch_sender, punch_receiver) = sync_channel(3);
        let peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>> =
            Arc::new(RwLock::new(HashMap::with_capacity(16)));
        let down_counter = U64Adder::with_capacity(config.ports.as_ref().map(|v| v.len()).unwrap_or_default() + 8);
        let down_count_watcher = down_counter.watch();
        let handler = RecvDataHandler::new(
            #[cfg(feature = "server_encrypt")]
            rsa_cipher,
            server_cipher.clone(),
            client_cipher.clone(),
            current_device.clone(),
            device.clone(),
            device_list.clone(),
            config_info.clone(),
            nat_test.clone(),
            callback.clone(),
            config.use_channel_type,
            punch_sender,
            peer_nat_info_map.clone(),
            external_route.clone(),
            out_external_route,
            #[cfg(feature = "ip_proxy")]
            proxy_map.clone(),
            down_counter,
        );

        //初始化网络数据通道
        let (udp_socket_sender, tcp_socket_sender) =
            init_channel(tcp_listener, context.clone(), stop_manager.clone(), handler)?;
        // 打洞逻辑
        let punch = Punch::new(
            context.clone(),
            config.punch_model,
            config.tcp,
            tcp_socket_sender.clone(),
        );
        let up_counter = SingleU64Adder::new();
        let up_count_watcher = up_counter.watch();
        tun_tap::tun_handler::start(
            stop_manager.clone(),
            context.clone(),
            device.clone(),
            current_device.clone(),
            external_route,
            #[cfg(feature = "ip_proxy")]
            proxy_map,
            client_cipher.clone(),
            server_cipher.clone(),
            config.parallel,
            up_counter,
        )?;
        maintain::idle_gateway(
            &scheduler,
            context.clone(),
            current_device.clone(),
            config_info.clone(),
            tcp_socket_sender.clone(),
            callback.clone(),
            0,
        );
        {
            let context = context.clone();
            let nat_test = nat_test.clone();
            let device_list = device_list.clone();
            let current_device = current_device.clone();
            let use_channel_type = config.use_channel_type;
            if !use_channel_type.is_only_relay() {
                // 定时nat探测
                maintain::retrieve_nat_type(
                    &scheduler,
                    context.clone(),
                    nat_test.clone(),
                    udp_socket_sender,
                );
            }
            //延迟启动
            scheduler.timeout(Duration::from_secs(3), move |scheduler| {
                start(
                    scheduler,
                    context,
                    nat_test,
                    device_list,
                    current_device,
                    client_cipher,
                    server_cipher,
                    punch_receiver,
                    config_info,
                    punch,
                    callback,
                    use_channel_type,
                );
            });
        }

        Ok(Self {
            stop_manager,
            config,
            current_device,
            nat_test,
            device_list,
            context,
            peer_nat_info_map,
            down_count_watcher,
            up_count_watcher,
        })
    }
}

pub fn start<Call: VntCallback>(
    scheduler: &Scheduler,
    context: Context,
    nat_test: NatTest,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    punch_receiver: Receiver<(Ipv4Addr, NatInfo)>,
    config_info: BaseConfigInfo,
    punch: Punch,
    callback: Call,
    use_channel_type: UseChannelType,
) {
    // 定时心跳
    maintain::heartbeat(
        &scheduler,
        context.clone(),
        current_device.clone(),
        device_list.clone(),
        client_cipher.clone(),
        server_cipher.clone(),
    );
    // 路由空闲检测逻辑
    let idle = Idle::new(Duration::from_secs(10), context.clone());
    // 定时空闲检查
    maintain::idle_route(
        &scheduler,
        idle,
        context.clone(),
        current_device.clone(),
        callback,
    );
    // 定时客户端中继检测
    maintain::client_relay(
        &scheduler,
        context.clone(),
        current_device.clone(),
        device_list.clone(),
        client_cipher.clone(),
    );
    // 定时地址探测
    maintain::addr_request(
        &scheduler,
        context.clone(),
        current_device.clone(),
        server_cipher.clone(),
        config_info.clone(),
    );
    if !use_channel_type.is_only_relay() {
        // 定时打洞
        maintain::punch(
            &scheduler,
            context.clone(),
            nat_test.clone(),
            device_list.clone(),
            current_device.clone(),
            client_cipher.clone(),
            punch_receiver,
            punch,
        );
    }
}

impl Vnt {
    pub fn name(&self) -> &str {
        &self.config.name
    }
    pub fn server_encrypt(&self) -> bool {
        self.config.server_encrypt
    }
    pub fn client_encrypt(&self) -> bool {
        self.config.password.is_some()
    }
    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.current_device.load()
    }
    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.peer_nat_info_map.read().get(ip).cloned()
    }
    pub fn connection_status(&self) -> ConnectStatus {
        self.current_device.load().status
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
        self.context.route_table.route_one(ip)
    }
    pub fn is_gateway(&self, ip: &Ipv4Addr) -> bool {
        self.current_device.load().is_gateway(ip)
    }
    pub fn route_key(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        self.context.route_table.route_to_id(route_key)
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.context.route_table.route_table()
    }
    pub fn up_stream(&self) -> u64 {
        self.up_count_watcher.get()
    }
    pub fn down_stream(&self) -> u64 {
        self.down_count_watcher.get()
    }
    pub fn stop(&self) {
        self.stop_manager.stop()
    }
    pub fn wait(&self) {
        self.stop_manager.wait()
    }
}
