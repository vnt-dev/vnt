use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};
use rand::Rng;

use crate::channel::context::ChannelContext;
use crate::channel::idle::Idle;
use crate::channel::punch::{NatInfo, Punch};
use crate::channel::sender::IpPacketSender;
use crate::channel::{init_channel, init_context, Route, RouteKey};
use crate::cipher::Cipher;
#[cfg(feature = "server_encrypt")]
use crate::cipher::RsaCipher;
use crate::compression::Compressor;
use crate::core::Config;
use crate::external_route::{AllowExternalRoute, ExternalRoute};
use crate::handle::handshaker::Handshake;
use crate::handle::maintain::PunchReceiver;
use crate::handle::recv_data::RecvDataHandler;
use crate::handle::{maintain, BaseConfigInfo, ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::NatTest;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::tun_create_helper::{DeviceAdapter, TunDeviceHelper};
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::limit::TrafficMeterMultiAddress;
use crate::util::{Scheduler, StopManager};
use crate::{nat, VntCallback};

#[derive(Clone)]
pub struct Vnt {
    inner: Arc<VntInner>,
}

impl Vnt {
    #[cfg(feature = "integrated_tun")]
    pub fn new<Call: VntCallback>(config: Config, callback: Call) -> anyhow::Result<Self> {
        let inner = Arc::new(VntInner::new(config, callback)?);
        Ok(Self { inner })
    }
    #[cfg(not(feature = "integrated_tun"))]
    pub fn new_device<Call: VntCallback, Device: DeviceWrite>(
        config: Config,
        callback: Call,
        device: Device,
    ) -> anyhow::Result<Self> {
        let inner = Arc::new(VntInner::new_device(config, callback, device)?);
        Ok(Self { inner })
    }
}

impl Deref for Vnt {
    type Target = VntInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct VntInner {
    stop_manager: StopManager,
    config: Config,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    context: Arc<Mutex<Option<ChannelContext>>>,
    peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
    client_secret_hash: Option<[u8; 16]>,
    compressor: Compressor,
    client_cipher: Cipher,
    server_cipher: Cipher,
    external_route: ExternalRoute,
    up_traffic_meter: Option<TrafficMeterMultiAddress>,
    down_traffic_meter: Option<TrafficMeterMultiAddress>,
}

impl VntInner {
    #[cfg(feature = "integrated_tun")]
    pub fn new<Call: VntCallback>(config: Config, callback: Call) -> anyhow::Result<Self> {
        VntInner::new_device0(config, callback, DeviceAdapter::default())
    }
    #[cfg(not(feature = "integrated_tun"))]
    pub fn new_device<Call: VntCallback, Device: DeviceWrite>(
        config: Config,
        callback: Call,
        device: Device,
    ) -> anyhow::Result<Self> {
        VntInner::new_device0(config, callback, device)
    }
    fn new_device0<Call: VntCallback, Device: DeviceWrite>(
        config: Config,
        callback: Call,
        device: Device,
    ) -> anyhow::Result<Self> {
        log::info!("config: {:?}", config);
        let (up_traffic_meter, down_traffic_meter) = if config.enable_traffic {
            (
                Some(TrafficMeterMultiAddress::default()),
                Some(TrafficMeterMultiAddress::default()),
            )
        } else {
            (None, None)
        };

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
            Cipher::new_password(config.cipher_model, config.password.clone(), finger)?;
        //当前设备信息
        let current_device = Arc::new(AtomicCell::new(CurrentDeviceInfo::new0(
            config.server_address,
        )));
        //设备列表
        let device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>> =
            Arc::new(Mutex::new((0, HashMap::with_capacity(16))));
        let local_ipv4 = if let Some(local_ipv4) = config.local_ipv4 {
            Some(local_ipv4)
        } else {
            nat::local_ipv4()
        };
        let default_interface = config.local_interface.clone();

        //基础信息
        let config_info = BaseConfigInfo::new(
            config.name.clone(),
            config.token.clone(),
            config.ip,
            config.password_hash(),
            config.server_encrypt,
            config.device_id.clone(),
            config.server_address_str.clone(),
            config.name_servers.clone(),
            config.mtu.unwrap_or(1420),
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            config.tap,
            #[cfg(feature = "integrated_tun")]
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            config.device_name.clone(),
            config.allow_wire_guard,
            default_interface.clone(),
        );
        // 服务停止管理器
        let stop_manager = {
            let callback = callback.clone();
            StopManager::new(move || callback.stop())
        };
        #[cfg(feature = "port_mapping")]
        crate::port_mapping::start_port_mapping(
            stop_manager.clone(),
            config.port_mapping_list.clone(),
        )?;
        let mut ports = config.ports.as_ref().map_or(vec![0, 0], |v| {
            if v.is_empty() {
                vec![0, 0]
            } else {
                v.clone()
            }
        });
        if config.use_channel_type.is_only_relay() {
            //中继模式下只监听一个端口就够了
            ports.truncate(1);
        }
        //通道上下文
        let (context, tcp_listener) = init_context(
            ports,
            config.use_channel_type,
            config.first_latency,
            config.protocol,
            config.packet_loss_rate,
            config.packet_delay,
            default_interface,
            up_traffic_meter.clone(),
            down_traffic_meter.clone(),
        )?;
        let local_ipv6 = nat::local_ipv6();
        let udp_ports = context.main_local_udp_port()?;
        let tcp_port = tcp_listener.local_addr()?.port();
        //nat检测工具
        let nat_test = NatTest::new(
            context.channel_num(),
            config.stun_server.clone(),
            local_ipv4,
            local_ipv6,
            udp_ports,
            tcp_port,
            config.local_ipv4.is_none(),
            config.punch_model,
        );
        // 定时器
        let scheduler = Scheduler::new(stop_manager.clone())?;
        let external_route = ExternalRoute::new(config.in_ips.clone());
        let out_external_route = AllowExternalRoute::new(config.out_ips.clone());

        #[cfg(feature = "ip_proxy")]
        #[cfg(feature = "integrated_tun")]
        let proxy_map = if !config.out_ips.is_empty() && !config.no_proxy {
            Some(crate::ip_proxy::init_proxy(
                context.clone(),
                stop_manager.clone(),
                current_device.clone(),
                client_cipher.clone(),
            )?)
        } else {
            None
        };
        let (punch_sender, punch_receiver) = maintain::punch_channel();
        let peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>> =
            Arc::new(RwLock::new(HashMap::with_capacity(16)));
        let handshake = Handshake::new(
            #[cfg(feature = "server_encrypt")]
            rsa_cipher.clone(),
        );
        #[cfg(feature = "integrated_tun")]
        let tun_device_helper = {
            TunDeviceHelper::new(
                stop_manager.clone(),
                context.clone(),
                current_device.clone(),
                external_route.clone(),
                #[cfg(feature = "ip_proxy")]
                proxy_map.clone(),
                client_cipher.clone(),
                server_cipher.clone(),
                device_map.clone(),
                config.compressor,
                device.clone().into_device_adapter(),
            )
        };

        let handler = RecvDataHandler::new(
            #[cfg(feature = "server_encrypt")]
            rsa_cipher,
            server_cipher.clone(),
            client_cipher.clone(),
            current_device.clone(),
            device,
            device_map.clone(),
            config_info.clone(),
            nat_test.clone(),
            callback.clone(),
            punch_sender,
            peer_nat_info_map.clone(),
            external_route.clone(),
            out_external_route,
            #[cfg(feature = "ip_proxy")]
            #[cfg(feature = "integrated_tun")]
            proxy_map.clone(),
            handshake.clone(),
            #[cfg(feature = "integrated_tun")]
            tun_device_helper,
        );

        //初始化网络数据通道
        let (udp_socket_sender, connect_util) =
            init_channel(tcp_listener, context.clone(), stop_manager.clone(), handler)?;
        // 打洞逻辑
        let punch = Punch::new(
            context.clone(),
            config.punch_model,
            connect_util.clone(),
            nat_test.clone(),
            current_device.clone(),
        );

        // #[cfg(not(target_os = "android"))]
        // tun_helper.start(device)?;

        maintain::idle_gateway(
            &scheduler,
            context.clone(),
            current_device.clone(),
            config_info.clone(),
            connect_util.clone(),
            callback.clone(),
            0,
            handshake,
        );
        {
            let context = context.clone();
            let nat_test = nat_test.clone();
            let device_map = device_map.clone();
            let config_info = config_info.clone();
            let current_device = current_device.clone();
            if !config.use_channel_type.is_only_relay() {
                // 定时nat探测
                maintain::retrieve_nat_type(
                    &scheduler,
                    context.clone(),
                    nat_test.clone(),
                    udp_socket_sender,
                );
            }
            let client_cipher = client_cipher.clone();
            let server_cipher = server_cipher.clone();
            //延迟启动
            scheduler.timeout(Duration::from_secs(1), move |scheduler| {
                start(
                    scheduler,
                    context,
                    nat_test,
                    device_map,
                    current_device,
                    client_cipher,
                    server_cipher,
                    punch_receiver,
                    config_info,
                    punch,
                    callback,
                );
            });
        }
        let compressor = config.compressor;
        Ok(Self {
            stop_manager,
            config,
            current_device,
            nat_test,
            device_map,
            context: Arc::new(Mutex::new(Some(context))),
            peer_nat_info_map,
            client_secret_hash: config_info.client_secret_hash,
            compressor,
            client_cipher,
            server_cipher,
            external_route,
            up_traffic_meter,
            down_traffic_meter,
        })
    }
}

pub fn start<Call: VntCallback>(
    scheduler: &Scheduler,
    context: ChannelContext,
    nat_test: NatTest,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    punch_receiver: PunchReceiver,
    config_info: BaseConfigInfo,
    punch: Punch,
    callback: Call,
) {
    // 定时心跳
    maintain::heartbeat(
        &scheduler,
        context.clone(),
        current_device.clone(),
        device_map.clone(),
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
    if !context.use_channel_type().is_only_p2p() {
        maintain::client_relay(
            &scheduler,
            context.clone(),
            current_device.clone(),
            device_map.clone(),
            client_cipher.clone(),
        );
    }

    if !context.use_channel_type().is_only_relay() {
        // 定时地址探测
        maintain::addr_request(
            &scheduler,
            context.clone(),
            current_device.clone(),
            nat_test.clone(),
            config_info.clone(),
        );
        // 定时打洞
        maintain::punch(
            &scheduler,
            context.clone(),
            nat_test.clone(),
            device_map.clone(),
            current_device.clone(),
            client_cipher.clone(),
            punch_receiver,
            punch,
        );
    }
    maintain::up_status(scheduler, context.clone(), current_device.clone())
}

impl VntInner {
    pub fn name(&self) -> &str {
        &self.config.name
    }
    pub fn server_encrypt(&self) -> bool {
        self.config.server_encrypt
    }
    pub fn client_encrypt(&self) -> bool {
        self.config.password.is_some()
    }
    pub fn client_encrypt_hash(&self) -> Option<&[u8]> {
        self.client_secret_hash.as_ref().map(|v| v.as_ref())
    }
    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.current_device.load()
    }
    pub fn current_device_info(&self) -> Arc<AtomicCell<CurrentDeviceInfo>> {
        self.current_device.clone()
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
        let device_list_lock = self.device_map.lock();
        let (_epoch, device_list) = device_list_lock.clone();
        drop(device_list_lock);
        device_list.into_values().collect()
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Route> {
        self.context.lock().as_ref()?.route_table.route_one(ip)
    }
    pub fn is_gateway(&self, ip: &Ipv4Addr) -> bool {
        self.current_device.load().is_gateway(ip)
    }
    pub fn route_key(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        self.context
            .lock()
            .as_ref()?
            .route_table
            .route_to_id(route_key)
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        if let Some(context) = self.context.lock().as_ref() {
            context.route_table.route_table()
        } else {
            vec![]
        }
    }
    pub fn up_stream(&self) -> u64 {
        self.up_traffic_meter.as_ref().map_or(0, |v| v.total())
    }
    pub fn up_stream_all(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.up_traffic_meter.as_ref().map(|v| v.get_all())
    }
    pub fn up_stream_history(&self) -> Option<(u64, HashMap<Ipv4Addr, (u64, Vec<usize>)>)> {
        self.up_traffic_meter.as_ref().map(|v| v.get_all_history())
    }
    pub fn down_stream(&self) -> u64 {
        self.down_traffic_meter.as_ref().map_or(0, |v| v.total())
    }
    pub fn down_stream_all(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.down_traffic_meter.as_ref().map(|v| v.get_all())
    }
    pub fn down_stream_history(&self) -> Option<(u64, HashMap<Ipv4Addr, (u64, Vec<usize>)>)> {
        self.down_traffic_meter
            .as_ref()
            .map(|v| v.get_all_history())
    }
    pub fn stop(&self) {
        //退出协助回收资源
        let _ = self.context.lock().take();
        self.stop_manager.stop()
    }
    pub fn is_stopped(&self) -> bool {
        self.stop_manager.is_stopped()
    }
    pub fn add_stop_listener<F>(&self, name: String, f: F) -> anyhow::Result<crate::util::Worker>
    where
        F: FnOnce() + Send + 'static,
    {
        self.stop_manager.add_listener(name, f)
    }
    pub fn wait(&self) {
        self.stop_manager.wait()
    }
    pub fn wait_timeout(&self, dur: Duration) -> bool {
        self.stop_manager.wait_timeout(dur)
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn ipv4_packet_sender(&self) -> Option<IpPacketSender> {
        if let Some(c) = self.context.lock().as_ref() {
            Some(IpPacketSender::new(
                c.clone(),
                self.current_device.clone(),
                self.compressor.clone(),
                self.client_cipher.clone(),
                self.server_cipher.clone(),
                self.external_route.clone(),
                self.device_map.clone(),
                self.config.allow_wire_guard,
            ))
        } else {
            None
        }
    }
}

impl Drop for VntInner {
    fn drop(&mut self) {
        self.stop();
    }
}
