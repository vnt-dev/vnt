use crate::error::Error;

// use std::io;
// use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
// use std::sync::atomic::Ordering;
// use std::sync::Arc;
// use std::time::Duration;
//
// use crossbeam::atomic::AtomicCell;
// use crossbeam::sync::WaitGroup;
// use parking_lot::Mutex;
// use tokio::sync::watch;
//
// use error::*;
//
// use crate::handle::registration_handler::CONNECTION_STATUS;
// use crate::handle::{
//     ApplicationStatus, ConnectStatus, CurrentDeviceInfo, NatInfo, PeerDeviceInfo, Route, RouteType,
//     DEVICE_LIST, DIRECT_ROUTE_TABLE, NAT_INFO, SERVER_RT,
// };
// use crate::nat::channel::NatChannel;
pub use nat_traversal::channel::{Route, RouteKey};

pub type Result<T> = std::result::Result<T, Error>;

pub mod error;
pub mod handle;
pub mod nat;
pub mod proto;
pub mod protocol;
pub mod tun_device;
pub mod core;

//
// #[derive(Clone, Debug)]
// pub struct Config<F> {
//     pub token: String,
//     pub mac_address: String,
//     pub name: String,
//     pub server_address: SocketAddr,
//     pub nat_test_server: Vec<SocketAddr>,
//     pub abnormal_call: F,
// }
//
// impl<F> Config<F> {
//     pub fn new(
//         token: String,
//         mac_address: String,
//         name: Option<String>,
//         server_address: SocketAddr,
//         nat_test_server: Vec<SocketAddr>,
//         abnormal_call: F,
//     ) -> Result<Self>
//     where
//         F: FnOnce() + Send + 'static,
//     {
//         if token.is_empty() || token.len() > 64 {
//             return Err(Error::Stop("token invalid".to_string()));
//         }
//         if mac_address.len() != 12 + 5 {
//             return Err(Error::Stop("mac_address invalid".to_string()));
//         }
//         if let Some(name) = name {
//             if name.is_empty() || name.len() > 64 {
//                 return Err(Error::Stop("name invalid".to_string()));
//             }
//             Ok(Self {
//                 token,
//                 mac_address,
//                 name,
//                 server_address,
//                 nat_test_server,
//                 abnormal_call,
//             })
//         } else {
//             let info = os_info::get();
//             let name = if info.version() != &os_info::Version::Unknown {
//                 format!("{} {}", info.os_type(), info.version())
//             } else {
//                 format!("{}", info.os_type())
//             };
//             Ok(Self {
//                 token,
//                 mac_address,
//                 name,
//                 server_address,
//                 nat_test_server,
//                 abnormal_call,
//             })
//         }
//     }
// }
//
// pub struct Switch {
//     current_device: CurrentDeviceInfo,
//     status_sender: Arc<Mutex<watch::Sender<ApplicationStatus>>>,
//     wait_group: WaitGroup,
//     runtime: Option<tokio::runtime::Runtime>,
// }
//
// impl Switch {
//     pub fn start<F>(config: Config<F>) -> Result<Self>
//     where
//         F: FnOnce() + Send + 'static,
//     {
//         let runtime = tokio::runtime::Builder::new_multi_thread()
//             .enable_all()
//             .build()
//             .unwrap();
//         todo!()
//         // return match runtime.block_on(Switch::start_(config)) {
//         //     Ok(mut switch) => {
//         //         switch.runtime = Some(runtime);
//         //         Ok(switch)
//         //     }
//         //     Err(e) => Err(e),
//         // };
//     }
//     pub fn stop(self) {
//         Self::call_stop(self.status_sender);
//         self.wait_group.wait();
//     }
//     pub fn stop_async(&self) {
//         Self::call_stop(self.status_sender.clone());
//     }
//     pub fn current_device(&self) -> &CurrentDeviceInfo {
//         &self.current_device
//     }
//     pub fn nat_info(&self) -> Option<NatInfo> {
//         NAT_INFO.lock().clone()
//     }
//     pub fn server_rt(&self) -> i64 {
//         SERVER_RT.load(Ordering::Relaxed)
//     }
//     pub fn connection_status(&self) -> ConnectStatus {
//         CONNECTION_STATUS.load()
//     }
//     pub fn device_list(&self) -> Vec<PeerDeviceInfo> {
//         let device_list_lock = DEVICE_LIST.lock();
//         let (_epoch, device_list) = device_list_lock.clone();
//         drop(device_list_lock);
//         device_list
//     }
//     pub fn route(&self, ip: &Ipv4Addr) -> Route {
//         if let Some(route_ref) = DIRECT_ROUTE_TABLE.get(ip) {
//             route_ref.value().clone()
//         } else {
//             let mut route = Route::new(self.current_device.connect_server);
//             route.route_type = RouteType::ServerRelay;
//             route.rt = self.server_rt() * 2;
//             route.recv_time = -1;
//             route
//         }
//     }
// }
//
// impl Switch {
//     fn call_stop(status_sender: Arc<Mutex<watch::Sender<ApplicationStatus>>>) -> bool {
//         let lock = status_sender.lock();
//         let status = lock.send_replace(ApplicationStatus::Stopping);
//         return status == ApplicationStatus::Starting;
//     }
//     // pub async fn start_<F>(config: Config<F>) -> Result<Self>
//     // where
//     //     F: FnOnce() + Send + 'static,
//     // {
//     //     // let server_address = "nat1.wherewego.top:29876"
//     //     // let server_address = "nat1.wherewego.top:29875".to_socket_addrs().unwrap().next().unwrap();
//     //     let server_address = config.server_address;
//     //     let nat_channel = NatChannel::new(server_address,100,).await?;
//     //     //注册
//     //     let response = handle::registration_handler::registration(
//     //         &udp,
//     //         server_address,
//     //         config.token,
//     //         config.mac_address,
//     //         config.name,
//     //     )?;
//     //     {
//     //         let ip_list = response
//     //             .device_info_list
//     //             .into_iter()
//     //             .map(|info| {
//     //                 PeerDeviceInfo::new(
//     //                     Ipv4Addr::from(info.virtual_ip),
//     //                     info.name,
//     //                     info.device_status as u8,
//     //                 )
//     //             })
//     //             .collect();
//     //         let mut dev = DEVICE_LIST.lock();
//     //         dev.0 = response.epoch;
//     //         dev.1 = ip_list;
//     //     }
//     //     let virtual_ip = Ipv4Addr::from(response.virtual_ip);
//     //     let virtual_gateway = Ipv4Addr::from(response.virtual_gateway);
//     //     let virtual_netmask = Ipv4Addr::from(response.virtual_netmask);
//     //     let (status_sender, status_receiver) = watch::channel(ApplicationStatus::Starting);
//     //     let current_device =
//     //         CurrentDeviceInfo::new(virtual_ip, virtual_gateway, virtual_netmask, server_address);
//     //     let wait_group = WaitGroup::new();
//     //     let status_sender = Arc::new(parking_lot::const_mutex(status_sender));
//     //     let call = Arc::new(AtomicCell::new(Some(config.abnormal_call)));
//     //     //心跳线程
//     //     {
//     //         let udp = udp.try_clone()?;
//     //         let wait_group1 = wait_group.clone();
//     //         let status_sender1 = status_sender.clone();
//     //         let call1 = call.clone();
//     //         handle::heartbeat_handler::start(
//     //             status_receiver.clone(),
//     //             udp,
//     //             current_device,
//     //             move || {
//     //                 if Self::call_stop(status_sender1) {
//     //                     if let Some(call) = call1.take() {
//     //                         call();
//     //                     }
//     //                 }
//     //                 drop(wait_group1);
//     //             },
//     //         )
//     //         .await;
//     //     }
//     //     //初始化nat数据
//     //     handle::init_nat_test_addr(config.nat_test_server);
//     //     handle::init_nat_info(response.public_ip, response.public_port as u16);
//     //     // tun服务
//     //     let (tun_writer, tun_reader) =
//     //         tun_device::create_tun(virtual_ip, virtual_netmask, virtual_gateway)?;
//     //     // 打洞数据通道
//     //     let (punch_sender, cone_receiver, req_symmetric_receiver, res_symmetric_receiver) =
//     //         handle::punch_handler::bounded();
//     //     //udp数据处理
//     //     {
//     //         // 低优先级的udp数据通道
//     //         let (sender, receiver) = tokio::sync::mpsc::channel(50);
//     //         let udp1 = udp.try_clone()?;
//     //         let wait_group1 = wait_group.clone();
//     //         let status_sender1 = status_sender.clone();
//     //         let call1 = call.clone();
//     //         handle::udp_recv_handler::udp_recv_start(
//     //             status_receiver.clone(),
//     //             udp1,
//     //             server_address,
//     //             sender,
//     //             tun_writer,
//     //             current_device,
//     //             move || {
//     //                 if Self::call_stop(status_sender1) {
//     //                     if let Some(call) = call1.take() {
//     //                         call();
//     //                     }
//     //                 }
//     //                 drop(wait_group1);
//     //             },
//     //         )
//     //         .await;
//     //         let udp1 = udp.try_clone()?;
//     //         let wait_group1 = wait_group.clone();
//     //         let status_sender1 = status_sender.clone();
//     //         let call1 = call.clone();
//     //         handle::udp_recv_handler::udp_other_recv_start(
//     //             status_receiver.clone(),
//     //             udp1,
//     //             receiver,
//     //             current_device,
//     //             punch_sender,
//     //             move || {
//     //                 if Self::call_stop(status_sender1) {
//     //                     if let Some(call) = call1.take() {
//     //                         call();
//     //                     }
//     //                 }
//     //                 drop(wait_group1);
//     //             },
//     //         )
//     //         .await;
//     //     }
//     //     //打洞处理
//     //     {
//     //         let udp1 = udp.try_clone()?;
//     //         let wait_group1 = wait_group.clone();
//     //         let status_sender1 = status_sender.clone();
//     //         let call1 = call.clone();
//     //         handle::punch_handler::cone_handler_start(
//     //             status_receiver.clone(),
//     //             cone_receiver,
//     //             udp1,
//     //             current_device,
//     //             move || {
//     //                 if Self::call_stop(status_sender1) {
//     //                     if let Some(call) = call1.take() {
//     //                         call();
//     //                     }
//     //                 }
//     //                 drop(wait_group1);
//     //             },
//     //         )
//     //         .await;
//     //         let udp1 = udp.try_clone()?;
//     //         let wait_group1 = wait_group.clone();
//     //         let status_sender1 = status_sender.clone();
//     //         let call1 = call.clone();
//     //         handle::punch_handler::req_symmetric_handler_start(
//     //             status_receiver.clone(),
//     //             req_symmetric_receiver,
//     //             udp1,
//     //             current_device,
//     //             move || {
//     //                 if Self::call_stop(status_sender1) {
//     //                     if let Some(call) = call1.take() {
//     //                         call();
//     //                     }
//     //                 }
//     //                 drop(wait_group1);
//     //             },
//     //         )
//     //         .await;
//     //         let udp1 = udp.try_clone()?;
//     //         let wait_group1 = wait_group.clone();
//     //         let status_sender1 = status_sender.clone();
//     //         let call1 = call.clone();
//     //         handle::punch_handler::res_symmetric_handler_start(
//     //             status_receiver.clone(),
//     //             res_symmetric_receiver,
//     //             udp1,
//     //             current_device,
//     //             move || {
//     //                 if Self::call_stop(status_sender1) {
//     //                     if let Some(call) = call1.take() {
//     //                         call();
//     //                     }
//     //                 }
//     //                 drop(wait_group1);
//     //             },
//     //         )
//     //         .await;
//     //     }
//     //     //tun数据处理
//     //     {
//     //         let wait_group1 = wait_group.clone();
//     //         let status_sender1 = status_sender.clone();
//     //         let call1 = call.clone();
//     //         handle::tun_handler::handler_start(
//     //             status_receiver.clone(),
//     //             udp,
//     //             tun_reader,
//     //             current_device,
//     //             move || {
//     //                 if Self::call_stop(status_sender1) {
//     //                     if let Some(call) = call1.take() {
//     //                         call();
//     //                     }
//     //                 }
//     //                 drop(wait_group1);
//     //             },
//     //         )
//     //         .await;
//     //     }
//     //     Ok(Switch {
//     //         current_device,
//     //         status_sender,
//     //         wait_group,
//     //         runtime: None,
//     //     })
//     // }
// }
