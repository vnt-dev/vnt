use fnv::FnvHashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;
use rand::Rng;

use crate::channel::punch::NatType;
use crate::channel::sender::{AcceptSocketSender, PacketSender};
use crate::channel::socket::LocalInterface;
use crate::channel::{ConnectProtocol, Route, RouteKey, UseChannelType, DEFAULT_RT};
use crate::protocol::NetPacket;
use crate::util::limit::TrafficMeterMultiAddress;

/// 传输通道上下文，持有udp socket、tcp socket和路由信息
#[derive(Clone)]
pub struct ChannelContext {
    inner: Arc<ContextInner>,
}

impl ChannelContext {
    pub fn new(
        main_udp_socket: Vec<UdpSocket>,
        v4_len: usize,
        use_channel_type: UseChannelType,
        first_latency: bool,
        protocol: ConnectProtocol,
        packet_loss_rate: Option<f64>,
        packet_delay: u32,
        up_traffic_meter: Option<TrafficMeterMultiAddress>,
        down_traffic_meter: Option<TrafficMeterMultiAddress>,
        default_interface: LocalInterface,
    ) -> Self {
        let channel_num = v4_len;
        assert_ne!(channel_num, 0, "not channel");
        let packet_loss_rate = packet_loss_rate
            .map(|v| {
                let v = (v * PACKET_LOSS_RATE_DENOMINATOR as f64) as u32;
                if v > PACKET_LOSS_RATE_DENOMINATOR {
                    PACKET_LOSS_RATE_DENOMINATOR
                } else {
                    v
                }
            })
            .unwrap_or(0);
        let inner = ContextInner {
            main_udp_socket,
            v4_len,
            sub_udp_socket: RwLock::new(Vec::new()),
            packet_map: RwLock::new(FnvHashMap::default()),
            route_table: RouteTable::new(use_channel_type, first_latency, channel_num),
            protocol,
            packet_loss_rate,
            packet_delay,
            up_traffic_meter,
            down_traffic_meter,
            default_interface,
            default_route_key: AtomicCell::default(),
        };
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl Deref for ChannelContext {
    type Target = ContextInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// 对称网络增加的udp socket数目，有助于增加打洞成功率
pub const SYMMETRIC_CHANNEL_NUM: usize = 84;
const PACKET_LOSS_RATE_DENOMINATOR: u32 = 100_0000;

pub struct ContextInner {
    // 核心udp socket
    pub(crate) main_udp_socket: Vec<UdpSocket>,
    v4_len: usize,
    // 对称网络增加的udp socket
    sub_udp_socket: RwLock<Vec<UdpSocket>>,
    // tcp数据发送器
    pub(crate) packet_map: RwLock<FnvHashMap<RouteKey, PacketSender>>,
    // 路由信息
    pub route_table: RouteTable,
    // 使用什么协议连接服务器
    protocol: ConnectProtocol,
    //控制丢包率，取值v=[0,100_0000] 丢包率r=v/100_0000
    packet_loss_rate: u32,
    //控制延迟
    packet_delay: u32,
    pub(crate) up_traffic_meter: Option<TrafficMeterMultiAddress>,
    pub(crate) down_traffic_meter: Option<TrafficMeterMultiAddress>,
    default_interface: LocalInterface,
    default_route_key: AtomicCell<Option<RouteKey>>,
}

impl ContextInner {
    pub fn use_channel_type(&self) -> UseChannelType {
        self.route_table.use_channel_type
    }
    pub fn default_interface(&self) -> &LocalInterface {
        &self.default_interface
    }
    pub fn set_default_route_key(&self, route_key: RouteKey) {
        self.default_route_key.store(Some(route_key));
    }
    /// 通过sub_udp_socket是否为空来判断是否为锥形网络
    pub fn is_cone(&self) -> bool {
        self.sub_udp_socket.read().is_empty()
    }
    pub fn main_protocol(&self) -> ConnectProtocol {
        self.protocol
    }
    pub fn is_udp_main(&self, route_key: &RouteKey) -> bool {
        route_key.protocol().is_udp() && route_key.index < self.main_udp_socket.len()
    }
    pub fn first_latency(&self) -> bool {
        self.route_table.first_latency
    }
    /// 切换NAT类型，不同的nat打洞模式会有不同
    pub fn switch(
        &self,
        nat_type: NatType,
        udp_socket_sender: &AcceptSocketSender<Option<Vec<mio::net::UdpSocket>>>,
    ) -> anyhow::Result<()> {
        let mut write_guard = self.sub_udp_socket.write();
        match nat_type {
            NatType::Symmetric => {
                if !write_guard.is_empty() {
                    return Ok(());
                }
                let mut vec = Vec::with_capacity(SYMMETRIC_CHANNEL_NUM);
                for _ in 0..SYMMETRIC_CHANNEL_NUM {
                    let udp = crate::channel::socket::bind_udp(
                        "0.0.0.0:0".parse().unwrap(),
                        &self.default_interface,
                    )?;
                    let udp: UdpSocket = udp.into();
                    vec.push(udp);
                }
                let mut mio_vec = Vec::with_capacity(SYMMETRIC_CHANNEL_NUM);
                for udp in vec.iter() {
                    let udp_socket = mio::net::UdpSocket::from_std(udp.try_clone()?);
                    mio_vec.push(udp_socket);
                }
                udp_socket_sender.try_add_socket(Some(mio_vec))?;
                *write_guard = vec;
            }
            NatType::Cone => {
                if write_guard.is_empty() {
                    return Ok(());
                }
                udp_socket_sender.try_add_socket(None)?;
                *write_guard = Vec::new();
            }
        }
        Ok(())
    }
    #[inline]
    pub fn channel_num(&self) -> usize {
        self.v4_len
    }
    #[inline]
    pub fn main_len(&self) -> usize {
        self.main_udp_socket.len()
    }
    /// 获取核心udp监听的端口，用于其他客户端连接
    pub fn main_local_udp_port(&self) -> io::Result<Vec<u16>> {
        let mut ports = Vec::new();
        for udp in self.main_udp_socket[..self.v4_len].iter() {
            ports.push(udp.local_addr()?.port())
        }
        Ok(ports)
    }
    pub fn send_tcp(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<()> {
        if let Some(tcp) = self.packet_map.read().get(route_key) {
            tcp.try_send(buf)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("dest={:?}", route_key),
            ))
        }
    }
    pub fn send_main_udp(&self, index: usize, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        if let Some(udp) = self.main_udp_socket.get(index) {
            udp.send_to(buf, addr)?;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "overflow"))
        }
    }
    /// 将数据发送到默认通道，一般发往服务器才用此方法
    pub fn send_default<B: AsRef<[u8]>>(
        &self,
        buf: &NetPacket<B>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        if self.protocol.is_udp() {
            if addr.is_ipv4() {
                self.send_main_udp(0, buf.buffer(), addr)?
            } else {
                self.send_main_udp(self.v4_len, buf.buffer(), addr)?
            }
        } else {
            if let Some(key) = self.default_route_key.load() {
                self.send_tcp(buf.buffer(), &key)?
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("dest={:?}", addr),
                ));
            }
        }
        if let Some(up_traffic_meter) = &self.up_traffic_meter {
            up_traffic_meter.add_traffic(buf.destination(), buf.data_len());
        }
        Ok(())
    }

    /// 此方法仅用于对称网络打洞
    pub fn try_send_all(&self, buf: &[u8], addr: SocketAddr) {
        self.try_send_all_main(buf, addr);
        for udp in self.sub_udp_socket.read().iter() {
            if let Err(e) = udp.send_to(buf, addr) {
                log::warn!("{:?},add={:?}", e, addr);
            }
            thread::sleep(Duration::from_millis(3));
        }
    }
    pub fn try_send_all_main(&self, buf: &[u8], addr: SocketAddr) {
        for index in 0..self.channel_num() {
            if let Err(e) = self.send_main_udp(index, buf, addr) {
                log::warn!("{:?},add={:?}", e, addr);
            }
        }
    }
    /// 发送网络数据
    pub fn send_ipv4_by_id<B: AsRef<[u8]>>(
        &self,
        buf: &NetPacket<B>,
        id: &Ipv4Addr,
        server_addr: SocketAddr,
        send_default: bool,
    ) -> io::Result<()> {
        if self.packet_loss_rate > 0 {
            if rand::thread_rng().gen_ratio(self.packet_loss_rate, PACKET_LOSS_RATE_DENOMINATOR) {
                return Ok(());
            }
        }

        if self.packet_delay > 0 {
            thread::sleep(Duration::from_millis(self.packet_delay as _));
        }
        //优先发到直连到地址
        if let Err(e) = self.send_by_id(buf, id) {
            if e.kind() != io::ErrorKind::NotFound {
                log::warn!("{}:{:?}", id, e);
            }
            if !self.route_table.use_channel_type.is_only_p2p() && send_default {
                //符合条件再发到服务器转发
                self.send_default(buf, server_addr)?;
            }
        }
        Ok(())
    }
    /// 将数据发到指定id
    pub fn send_by_id<B: AsRef<[u8]>>(&self, buf: &NetPacket<B>, id: &Ipv4Addr) -> io::Result<()> {
        let mut c = 0;
        loop {
            let route = self.route_table.get_route_by_id(c, id)?;
            return if let Err(e) = self.send_by_key(buf, route.route_key()) {
                //降低发送速率
                if e.kind() == io::ErrorKind::WouldBlock {
                    c += 1;
                    if c < 10 {
                        thread::sleep(Duration::from_micros(200));
                        continue;
                    }
                }
                Err(e)
            } else {
                Ok(())
            };
        }
    }
    /// 将数据发到指定路由
    pub fn send_by_key<B: AsRef<[u8]>>(
        &self,
        buf: &NetPacket<B>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        match route_key.protocol() {
            ConnectProtocol::UDP => {
                if let Some(main_udp) = self.main_udp_socket.get(route_key.index) {
                    main_udp.send_to(buf.buffer(), route_key.addr)?;
                } else {
                    if let Some(udp) = self
                        .sub_udp_socket
                        .read()
                        .get(route_key.index - self.main_len())
                    {
                        udp.send_to(buf.buffer(), route_key.addr)?;
                    } else {
                        Err(io::Error::from(io::ErrorKind::NotFound))?
                    }
                }
            }
            ConnectProtocol::TCP | ConnectProtocol::WS | ConnectProtocol::WSS => {
                self.send_tcp(buf.buffer(), &route_key)?
            }
        }
        if let Some(up_traffic_meter) = &self.up_traffic_meter {
            up_traffic_meter.add_traffic(buf.destination(), buf.data_len());
        }
        Ok(())
    }
    pub fn remove_route(&self, ip: &Ipv4Addr, route_key: RouteKey) {
        self.route_table.remove_route(ip, route_key)
    }
}

pub struct RouteTable {
    pub(crate) route_table:
        RwLock<FnvHashMap<Ipv4Addr, (AtomicUsize, Vec<(Route, AtomicCell<Instant>)>)>>,
    first_latency: bool,
    channel_num: usize,
    use_channel_type: UseChannelType,
}

impl RouteTable {
    fn new(use_channel_type: UseChannelType, first_latency: bool, channel_num: usize) -> Self {
        Self {
            route_table: RwLock::new(FnvHashMap::with_capacity_and_hasher(64, Default::default())),
            use_channel_type,
            first_latency,
            channel_num,
        }
    }
}

impl RouteTable {
    fn get_route_by_id(&self, index: usize, id: &Ipv4Addr) -> io::Result<Route> {
        if let Some((_count, v)) = self.route_table.read().get(id) {
            if self.first_latency {
                if let Some((route, _)) = v.first() {
                    return Ok(*route);
                }
            } else {
                let len = v.len();
                if len != 0 {
                    let route = &v[index % len].0;
                    // 跳过默认rt的路由(一般是刚加入的)，这有助于提升稳定性
                    if route.rt != DEFAULT_RT {
                        return Ok(*route);
                    }
                    for (route, _) in v {
                        if route.rt != DEFAULT_RT {
                            return Ok(*route);
                        }
                    }
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub fn add_route_if_absent(&self, id: Ipv4Addr, route: Route) -> bool {
        self.add_route_(id, route, true)
    }
    pub fn add_route(&self, id: Ipv4Addr, route: Route) -> bool {
        self.add_route_(id, route, false)
    }
    fn add_route_(&self, id: Ipv4Addr, route: Route, only_if_absent: bool) -> bool {
        // 限制通道类型
        match self.use_channel_type {
            UseChannelType::P2p => {
                if !route.is_p2p() {
                    return false;
                }
            }
            _ => {}
        }
        let key = route.route_key();
        if only_if_absent {
            if let Some((_, list)) = self.route_table.read().get(&id) {
                for (x, _) in list {
                    if x.route_key() == key {
                        return true;
                    }
                }
            }
        }
        let mut route_table = self.route_table.write();
        let (_, list) = route_table
            .entry(id)
            .or_insert_with(|| (AtomicUsize::new(0), Vec::with_capacity(4)));
        let mut exist = false;
        for (x, time) in list.iter_mut() {
            if x.metric < route.metric && !self.first_latency {
                //非优先延迟的情况下 不能比当前的路径更长
                return false;
            }
            if x.route_key() == key {
                if only_if_absent {
                    return true;
                }
                x.metric = route.metric;
                x.rt = route.rt;
                exist = true;
                time.store(Instant::now());
                break;
            }
        }
        if exist {
            list.sort_by_key(|(k, _)| k.rt);
        } else {
            if !self.first_latency {
                if route.is_p2p() {
                    //非优先延迟的情况下 添加了直连的则排除非直连的
                    list.retain(|(k, _)| k.is_p2p());
                }
            };
            list.sort_by_key(|(k, _)| k.rt);
            list.push((route, AtomicCell::new(Instant::now())));
        }
        return true;
    }
    // 直接移除会导致通道不稳定，所以废弃这个方法，后面改用多余通道不发心跳包，从而让通道自动过期
    // fn truncate_(&self, list: &mut Vec<(Route, AtomicCell<Instant>)>, len: usize) {
    //     if list.len() <= len {
    //         return;
    //     }
    //     if self.first_latency {
    //         //找到第一个p2p通道
    //         if let Some(index) =
    //             list.iter()
    //                 .enumerate()
    //                 .find_map(|(index, (route, _))| if route.is_p2p() { Some(index) } else { None })
    //         {
    //             if index >= len {
    //                 //保留第一个p2p通道
    //                 let route = list.remove(index);
    //                 list.truncate(len - 1);
    //                 list.push(route);
    //                 return;
    //             }
    //         }
    //     }
    //     list.truncate(len);
    // }
    pub fn route(&self, id: &Ipv4Addr) -> Option<Vec<Route>> {
        if let Some((_, v)) = self.route_table.read().get(id) {
            Some(v.iter().map(|(i, _)| *i).collect())
        } else {
            None
        }
    }
    pub fn route_one(&self, id: &Ipv4Addr) -> Option<Route> {
        if let Some((_, v)) = self.route_table.read().get(id) {
            v.first().map(|(i, _)| *i)
        } else {
            None
        }
    }
    pub fn route_one_p2p(&self, id: &Ipv4Addr) -> Option<Route> {
        if let Some((_, v)) = self.route_table.read().get(id) {
            for (i, _) in v {
                if i.is_p2p() {
                    return Some(*i);
                }
            }
        }
        None
    }
    pub fn route_to_id(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        let table = self.route_table.read();
        for (k, (_, v)) in table.iter() {
            for (route, _) in v {
                if &route.route_key() == route_key && route.is_p2p() {
                    return Some(*k);
                }
            }
        }
        None
    }
    pub fn no_need_punch(&self, id: &Ipv4Addr) -> bool {
        if let Some((_, v)) = self.route_table.read().get(id) {
            //p2p的通道数符合要求
            return v.iter().filter(|(k, _)| k.is_p2p()).count() >= self.channel_num;
        }
        false
    }
    pub fn p2p_num(&self, id: &Ipv4Addr) -> usize {
        if let Some((_, v)) = self.route_table.read().get(id) {
            v.iter().filter(|(k, _)| k.is_p2p()).count()
        } else {
            0
        }
    }
    /// 返回所有路由
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        let table = self.route_table.read();
        table
            .iter()
            .map(|(k, (_, v))| (k.clone(), v.iter().map(|(i, _)| *i).collect()))
            .collect()
    }
    pub fn route_table_p2p(&self) -> Vec<(Ipv4Addr, Route)> {
        let table = self.route_table.read();
        let mut list = Vec::with_capacity(8);
        for (ip, (_, routes)) in table.iter() {
            for (route, _) in routes.iter() {
                if route.is_p2p() {
                    list.push((*ip, *route));
                    break;
                }
            }
        }
        list
    }
    pub fn route_table_one(&self) -> Vec<(Ipv4Addr, Route)> {
        let mut list = Vec::with_capacity(8);
        let table = self.route_table.read();
        for (k, (_, v)) in table.iter() {
            if let Some((route, _)) = v.first() {
                list.push((*k, *route));
            }
        }
        list
    }
    pub fn remove_route(&self, id: &Ipv4Addr, route_key: RouteKey) {
        let mut write_guard = self.route_table.write();
        if let Some((_, routes)) = write_guard.get_mut(id) {
            routes.retain(|(x, _)| x.route_key() != route_key);
            if routes.is_empty() {
                write_guard.remove(id);
            }
        }
    }
    /// 更新路由入栈包的时刻，长时间没有收到数据的路由将会被剔除
    pub fn update_read_time(&self, id: &Ipv4Addr, route_key: &RouteKey) {
        if let Some((_, routes)) = self.route_table.read().get(id) {
            for (route, time) in routes {
                if &route.route_key() == route_key {
                    time.store(Instant::now());
                    break;
                }
            }
        }
    }
}
