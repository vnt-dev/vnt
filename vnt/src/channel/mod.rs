use anyhow::Context;
use std::net::{SocketAddr, UdpSocket};
use std::str::FromStr;
use tokio::sync::mpsc::channel;

use crate::channel::context::ChannelContext;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::sender::{AcceptSocketSender, ConnectUtil};
use crate::channel::socket::{bind_udp, LocalInterface};
use crate::channel::tcp_channel::tcp_listen;
use crate::channel::udp_channel::udp_listen;
#[cfg(feature = "ws")]
use crate::channel::ws_channel::ws_connect_accept;
use crate::util::limit::TrafficMeterMultiAddress;
use crate::util::StopManager;

pub mod context;
pub mod handler;
pub mod idle;
pub mod notify;
pub mod punch;
pub mod sender;
pub mod socket;
pub mod tcp_channel;
pub mod udp_channel;
#[cfg(feature = "ws")]
pub mod ws_channel;

pub const BUFFER_SIZE: usize = 1024 * 64;
// 这里留个坑，tcp是支持_TCP_MAX_PACKET_SIZE长度的，
// 但是缓存只用BUFFER_SIZE，会导致多余的数据接收不了
const TCP_MAX_PACKET_SIZE: usize = (1 << 24) - 1;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum UseChannelType {
    Relay,
    P2p,
    All,
}

impl UseChannelType {
    pub fn is_only_relay(&self) -> bool {
        self == &UseChannelType::Relay
    }
    pub fn is_only_p2p(&self) -> bool {
        self == &UseChannelType::P2p
    }
    pub fn is_all(&self) -> bool {
        self == &UseChannelType::All
    }
}

impl FromStr for UseChannelType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "relay" => Ok(UseChannelType::Relay),
            "p2p" => Ok(UseChannelType::P2p),
            "all" => Ok(UseChannelType::All),
            _ => Err(format!("not match '{}', enum: relay/p2p/all", s)),
        }
    }
}

impl Default for UseChannelType {
    fn default() -> Self {
        UseChannelType::All
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConnectProtocol {
    UDP,
    TCP,
    WS,
    WSS,
}

impl ConnectProtocol {
    #[inline]
    pub fn is_tcp(&self) -> bool {
        self == &ConnectProtocol::TCP
    }
    #[inline]
    pub fn is_udp(&self) -> bool {
        self == &ConnectProtocol::UDP
    }
    #[inline]
    pub fn is_ws(&self) -> bool {
        self == &ConnectProtocol::WS
    }
    #[inline]
    pub fn is_wss(&self) -> bool {
        self == &ConnectProtocol::WSS
    }
    pub fn is_transport(&self) -> bool {
        self.is_tcp() || self.is_udp()
    }
    pub fn is_base_tcp(&self) -> bool {
        self.is_tcp() || self.is_ws() || self.is_wss()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Route {
    pub protocol: ConnectProtocol,
    index: usize,
    pub addr: SocketAddr,
    pub metric: u8,
    pub rt: i64,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteSortKey {
    pub metric: u8,
    pub rt: i64,
}

const DEFAULT_RT: i64 = 9999;

impl Route {
    pub fn new(
        protocol: ConnectProtocol,
        index: usize,
        addr: SocketAddr,
        metric: u8,
        rt: i64,
    ) -> Self {
        Self {
            protocol,
            index,
            addr,
            metric,
            rt,
        }
    }
    pub fn from(route_key: RouteKey, metric: u8, rt: i64) -> Self {
        Self {
            protocol: route_key.protocol,
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt,
        }
    }
    pub fn from_default_rt(route_key: RouteKey, metric: u8) -> Self {
        Self {
            protocol: route_key.protocol,
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt: DEFAULT_RT,
        }
    }
    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            protocol: self.protocol,
            index: self.index,
            addr: self.addr,
        }
    }
    pub fn sort_key(&self) -> RouteSortKey {
        RouteSortKey {
            metric: self.metric,
            rt: self.rt,
        }
    }
    pub fn is_p2p(&self) -> bool {
        self.metric == 1
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteKey {
    protocol: ConnectProtocol,
    index: usize,
    pub addr: SocketAddr,
}

impl RouteKey {
    pub(crate) const fn new(protocol: ConnectProtocol, index: usize, addr: SocketAddr) -> Self {
        Self {
            protocol,
            index,
            addr,
        }
    }
    #[inline]
    pub fn protocol(&self) -> ConnectProtocol {
        self.protocol
    }
    #[inline]
    pub fn index(&self) -> usize {
        self.index
    }
}

pub(crate) fn init_context(
    ports: Vec<u16>,
    use_channel_type: UseChannelType,
    first_latency: bool,
    protocol: ConnectProtocol,
    packet_loss_rate: Option<f64>,
    packet_delay: u32,
    default_interface: LocalInterface,
    up_traffic_meter: Option<TrafficMeterMultiAddress>,
    down_traffic_meter: Option<TrafficMeterMultiAddress>,
) -> anyhow::Result<(ChannelContext, std::net::TcpListener)> {
    assert!(!ports.is_empty(), "not channel");
    let mut main_udp_socket_v4 = Vec::with_capacity(ports.len());
    let mut main_udp_socket_v6 = Vec::with_capacity(ports.len());
    //检查系统是否支持ipv6
    let use_ipv6 = match socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None) {
        Ok(_) => true,
        Err(e) => {
            log::warn!("{:?}", e);
            false
        }
    };
    for port in &ports {
        let addr_v4: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        if use_ipv6 {
            let (main_channel_v4, main_channel_v6) = bind_udp_v4_and_v6(*port, &default_interface)?;
            main_udp_socket_v4.push(main_channel_v4);
            main_udp_socket_v6.push(main_channel_v6);
        } else {
            let socket = bind_udp(addr_v4, &default_interface)?;
            let main_channel_v4: UdpSocket = socket.into();
            main_udp_socket_v4.push(main_channel_v4);
        }
    }
    let mut main_udp_socket =
        Vec::with_capacity(main_udp_socket_v4.len() + main_udp_socket_v6.len());
    let v4_len = main_udp_socket_v4.len();
    main_udp_socket.append(&mut main_udp_socket_v4);
    main_udp_socket.append(&mut main_udp_socket_v6);
    let context = ChannelContext::new(
        main_udp_socket,
        v4_len,
        use_channel_type,
        first_latency,
        protocol,
        packet_loss_rate,
        packet_delay,
        up_traffic_meter,
        down_traffic_meter,
        default_interface,
    );

    let port = context.main_local_udp_port()?[0];
    //监听v6+v4双栈，tcp通道使用异步io
    let (socket, address) = if use_ipv6 {
        let address: SocketAddr = format!("[::]:{}", port).parse().unwrap();
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
        socket
            .set_only_v6(false)
            .with_context(|| format!("set_only_v6 failed: {}", &address))?;
        (socket, address)
    } else {
        let address: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        (socket, address)
    };
    socket
        .set_reuse_address(true)
        .context("set_reuse_address")?;
    #[cfg(unix)]
    if let Err(e) = socket.set_reuse_port(true) {
        log::warn!("set_reuse_port {:?}", e)
    }
    if let Err(e) = socket.bind(&address.into()) {
        if ports[0] == 0 {
            //端口可能冲突，则使用任意端口
            log::warn!("监听tcp端口失败 {:?},重试一次", address);
            let address: SocketAddr = if use_ipv6 {
                format!("[::]:{}", 0).parse().unwrap()
            } else {
                format!("0.0.0.0:{}", port).parse().unwrap()
            };
            socket
                .bind(&address.into())
                .with_context(|| format!("bind failed: {}", &address))?;
        } else {
            //手动指定的ip,直接报错
            Err(anyhow::anyhow!("{:?},bind failed: {}", e, address))?;
        }
    }
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    socket.set_nodelay(true)?;
    Ok((context, socket.into()))
}
fn bind_udp_v4_and_v6(
    port: u16,
    default_interface: &LocalInterface,
) -> anyhow::Result<(UdpSocket, UdpSocket)> {
    let mut count = 0;
    loop {
        let addr_v4: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        let socket = bind_udp(addr_v4, default_interface)?;
        if let Err(e) = socket.set_recv_buffer_size(2 * 1024 * 1024) {
            log::warn!("set_recv_buffer_size {:?}", e);
        }
        let main_channel_v4: UdpSocket = socket.into();
        let addr = main_channel_v4.local_addr()?;
        let addr_v6: SocketAddr = format!("[::]:{}", addr.port()).parse().unwrap();
        let socket = if port == 0 {
            match bind_udp(addr_v6, default_interface) {
                Ok(socket) => socket,
                Err(e) => {
                    if count > 10 {
                        return Err(e);
                    }
                    if let Some(e) = e.downcast_ref::<std::io::Error>() {
                        if e.kind() == std::io::ErrorKind::AddrInUse {
                            count += 1;
                            continue;
                        }
                    }
                    Err(e)?
                }
            }
        } else {
            bind_udp(addr_v6, default_interface)?
        };
        if let Err(e) = socket.set_recv_buffer_size(2 * 1024 * 1024) {
            log::warn!("set_recv_buffer_size {:?}", e);
        }
        let main_channel_v6: UdpSocket = socket.into();
        return Ok((main_channel_v4, main_channel_v6));
    }
}

pub(crate) fn init_channel<H>(
    tcp_listener: std::net::TcpListener,
    context: ChannelContext,
    stop_manager: StopManager,
    recv_handler: H,
) -> anyhow::Result<(
    AcceptSocketSender<Option<Vec<mio::net::UdpSocket>>>,
    ConnectUtil,
)>
where
    H: RecvChannelHandler,
{
    let (tcp_connect_s, tcp_connect_r) = channel(16);
    let (ws_connect_s, _ws_connect_r) = channel(16);
    let connect_util = ConnectUtil::new(tcp_connect_s, ws_connect_s);
    // udp监听，udp_socket_sender 用于NAT类型切换
    let udp_socket_sender =
        udp_listen(stop_manager.clone(), recv_handler.clone(), context.clone())?;
    // 建立tcp监听，tcp_socket_sender 用于tcp 直连
    tcp_listen(
        tcp_listener,
        tcp_connect_r,
        recv_handler.clone(),
        context.clone(),
        stop_manager.clone(),
    )?;
    #[cfg(feature = "ws")]
    ws_connect_accept(_ws_connect_r, recv_handler, context.clone(), stop_manager)?;

    Ok((udp_socket_sender, connect_util))
}
