use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;
use rand::Rng;

use crate::channel::punch::NatType;
use crate::channel::sender::{AcceptSocketSender, ChannelSender, PacketSender};
use crate::channel::{Route, RouteKey, UseChannelType, DEFAULT_RT};
use crate::handle::{ConnectStatus, CurrentDeviceInfo};

/// 传输通道上下文，持有udp socket、tcp socket和路由信息
#[derive(Clone)]
pub struct Context {
    inner: Arc<ContextInner>,
}

impl Context {
    pub fn new(
        main_udp_socket: Vec<UdpSocket>,
        use_channel_type: UseChannelType,
        first_latency: bool,
        is_tcp: bool,
        packet_loss_rate: Option<f64>,
        packet_delay: u32,
    ) -> Self {
        let channel_num = main_udp_socket.len();
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
            sub_udp_socket: RwLock::new(Vec::with_capacity(64)),
            tcp_map: RwLock::new(HashMap::with_capacity(64)),
            route_table: RouteTable::new(use_channel_type, first_latency, channel_num),
            is_tcp,
            state: AtomicBool::new(true),
            packet_loss_rate,
            packet_delay,
        };
        Self {
            inner: Arc::new(inner),
        }
    }
    pub fn sender(&self) -> ChannelSender {
        ChannelSender::new(self.clone())
    }
}

impl Deref for Context {
    type Target = ContextInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// 对称网络增加的udp socket数目，有助于增加打洞成功率
pub const SYMMETRIC_CHANNEL_NUM: usize = 64;
const PACKET_LOSS_RATE_DENOMINATOR: u32 = 100_0000;
pub struct ContextInner {
    // 核心udp socket
    pub(crate) main_udp_socket: Vec<UdpSocket>,
    // 对称网络增加的udp socket
    sub_udp_socket: RwLock<Vec<UdpSocket>>,
    // tcp数据发送器
    pub(crate) tcp_map: RwLock<HashMap<SocketAddr, PacketSender>>,
    // 路由信息
    pub route_table: RouteTable,
    // 是否使用tcp连接服务器
    is_tcp: bool,
    //状态
    state: AtomicBool,
    //控制丢包率，取值v=[0,100_0000] 丢包率r=v/100_0000
    packet_loss_rate: u32,
    //控制延迟
    packet_delay: u32,
}

impl ContextInner {
    pub fn use_channel_type(&self) -> UseChannelType {
        self.route_table.use_channel_type
    }
    pub fn is_stop(&self) -> bool {
        !self.state.load(Ordering::Acquire)
    }
    pub fn stop(&self) {
        self.state.store(false, Ordering::Release);
    }
    /// 通过sub_udp_socket是否为空来判断是否为锥形网络
    pub fn is_cone(&self) -> bool {
        self.sub_udp_socket.read().is_empty()
    }
    pub fn is_main_tcp(&self) -> bool {
        self.is_tcp
    }
    pub fn is_udp_main(&self, route_key: &RouteKey) -> bool {
        !route_key.is_tcp() && route_key.index < self.main_udp_socket.len()
    }
    pub fn first_latency(&self) -> bool {
        self.route_table.first_latency
    }
    /// 切换NAT类型，不同的nat打洞模式会有不同
    pub fn switch(
        &self,
        nat_type: NatType,
        udp_socket_sender: &AcceptSocketSender<Option<Vec<mio::net::UdpSocket>>>,
    ) -> io::Result<()> {
        let mut write_guard = self.sub_udp_socket.write();
        match nat_type {
            NatType::Symmetric => {
                if !write_guard.is_empty() {
                    return Ok(());
                }
                let mut vec = Vec::with_capacity(SYMMETRIC_CHANNEL_NUM);
                for _ in 0..SYMMETRIC_CHANNEL_NUM {
                    let udp = UdpSocket::bind("0.0.0.0:0")?;
                    //副通道使用异步io
                    udp.set_nonblocking(true)?;
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
    pub fn change_status(
        &self,
        current_device: &AtomicCell<CurrentDeviceInfo>,
    ) -> CurrentDeviceInfo {
        let mut cur = current_device.load();
        loop {
            let status = if self.route_table.route_one(&cur.virtual_gateway).is_some() {
                //已连接
                if cur.status.online() {
                    return cur;
                }
                //状态变为已连接
                ConnectStatus::Connected
            } else {
                //未连接
                if cur.status.offline() {
                    return cur;
                }
                //状态变为未连接
                ConnectStatus::Connecting
            };
            let mut new_info = cur;
            new_info.status = status;
            match current_device.compare_exchange(cur, new_info) {
                Ok(_) => {
                    return new_info;
                }
                Err(c) => {
                    cur = c;
                }
            }
        }
    }
    pub fn channel_num(&self) -> usize {
        self.main_udp_socket.len()
    }
    /// 获取核心udp监听的端口，用于其他客户端连接
    pub fn main_local_udp_port(&self) -> io::Result<Vec<u16>> {
        let mut ports = Vec::new();
        for udp in self.main_udp_socket.iter() {
            ports.push(udp.local_addr()?.port())
        }
        Ok(ports)
    }
    pub fn send_tcp(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        if let Some(tcp) = self.tcp_map.read().get(&addr) {
            tcp.try_send(buf)
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
    pub fn send_main_udp(&self, index: usize, buf: &[u8], mut addr: SocketAddr) -> io::Result<()> {
        //核心udp socket都是ipv6模式,如果是v4地址则需要转换成v6
        //只有服务器地址可能需要这样转换
        if let SocketAddr::V4(ipv4) = addr {
            addr = SocketAddr::V6(SocketAddrV6::new(
                ipv4.ip().to_ipv6_mapped(),
                ipv4.port(),
                0,
                0,
            ));
        }
        self.main_udp_socket[index].send_to(buf, addr)?;
        Ok(())
    }
    /// 将数据发送到默认通道，一般发往服务器才用此方法
    pub fn send_default(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        if self.is_tcp {
            //服务端地址只在重连时检测变化
            self.send_tcp(buf, addr)
        } else {
            self.send_main_udp(0, buf, addr)
        }
    }
    /// 此方法仅用于对称网络打洞
    pub fn try_send_all(&self, buf: &[u8], addr: SocketAddr) {
        self.try_send_all_main(buf, addr);
        for udp in self.sub_udp_socket.read().iter() {
            if let Err(e) = udp.send_to(buf, addr) {
                log::warn!("{:?},add={:?}", e, addr);
            }
        }
    }
    pub fn try_send_all_main(&self, buf: &[u8], mut addr: SocketAddr) {
        if let SocketAddr::V4(ipv4) = addr {
            addr = SocketAddr::V6(SocketAddrV6::new(
                ipv4.ip().to_ipv6_mapped(),
                ipv4.port(),
                0,
                0,
            ));
        }
        for udp in &self.main_udp_socket {
            if let Err(e) = udp.send_to(buf, addr) {
                log::warn!("{:?},add={:?}", e, addr);
            }
        }
    }
    /// 发送网络数据
    pub fn send_ipv4_by_id(
        &self,
        buf: &[u8],
        id: &Ipv4Addr,
        server_addr: SocketAddr,
    ) -> io::Result<()> {
        if self.packet_loss_rate > 0 {
            if rand::thread_rng().gen_ratio(self.packet_loss_rate, PACKET_LOSS_RATE_DENOMINATOR) {
                return Ok(());
            }
        }
        if self.packet_delay > 0 {
            std::thread::sleep(Duration::from_millis(self.packet_delay as _));
        }
        if self.send_by_id(buf, id).is_err() && !self.route_table.use_channel_type.is_only_p2p() {
            self.send_default(buf, server_addr)
        } else {
            Ok(())
        }
    }
    /// 将数据发到指定id
    pub fn send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<()> {
        let route = self.route_table.get_route_by_id(id)?;
        self.send_by_key(buf, route.route_key())
    }
    /// 将数据发到指定路由
    pub fn send_by_key(&self, buf: &[u8], route_key: RouteKey) -> io::Result<()> {
        if route_key.is_tcp {
            self.send_tcp(buf, route_key.addr)
        } else {
            if let Some(main_udp) = self.main_udp_socket.get(route_key.index) {
                main_udp.send_to(buf, route_key.addr)?;
            } else {
                if let Some(udp) = self
                    .sub_udp_socket
                    .read()
                    .get(route_key.index - self.main_udp_socket.len())
                {
                    udp.send_to(buf, route_key.addr)?;
                } else {
                    Err(io::Error::from(io::ErrorKind::NotFound))?
                }
            }
            Ok(())
        }
    }
    pub fn remove_route(&self, ip: &Ipv4Addr, route_key: RouteKey) {
        if self.route_table.remove_route(ip, route_key) {
            if route_key.is_tcp {
                if let Some(tcp) = self.tcp_map.write().remove(&route_key.addr) {
                    if let Err(e) = tcp.shutdown() {
                        log::warn!("{:?}", e);
                    }
                }
            }
        }
    }
}

pub struct RouteTable {
    pub(crate) route_table:
        RwLock<HashMap<Ipv4Addr, (AtomicUsize, Vec<(Route, AtomicCell<Instant>)>)>>,
    first_latency: bool,
    channel_num: usize,
    use_channel_type: UseChannelType,
}

impl RouteTable {
    fn new(use_channel_type: UseChannelType, first_latency: bool, channel_num: usize) -> Self {
        Self {
            route_table: RwLock::new(HashMap::with_capacity(64)),
            use_channel_type,
            first_latency,
            channel_num,
        }
    }
}

impl RouteTable {
    fn get_route_by_id(&self, id: &Ipv4Addr) -> io::Result<Route> {
        if let Some((_count, v)) = self.route_table.read().get(id) {
            let len = v.len();
            if len == 0 {
                return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
            }
            // 因为列表是按延迟排序的，会一直变，直接取第一条是合理的
            let (route, time) = &v[0];

            // 刚加入的或者长时间没通信的不使用
            if route.rt != DEFAULT_RT && time.load().elapsed() < Duration::from_secs(5) {
                return Ok(*route);
            }
            // 如果指定路由不符合，则遍历路由表找到符合条件的
            if len > 1 {
                for (route, time) in v[1..].iter() {
                    if route.rt != DEFAULT_RT && time.load().elapsed() < Duration::from_secs(5) {
                        return Ok(*route);
                    }
                }
            }
            //加一条保底
            if route.is_p2p() && route.rt != DEFAULT_RT {
                return Ok(*route);
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub fn add_route_if_absent(&self, id: Ipv4Addr, route: Route) {
        self.add_route_(id, route, true)
    }
    pub fn add_route(&self, id: Ipv4Addr, route: Route) {
        self.add_route_(id, route, false)
    }
    fn add_route_(&self, id: Ipv4Addr, route: Route, only_if_absent: bool) {
        // 限制通道类型
        match self.use_channel_type {
            UseChannelType::P2p => {
                if route.metric != 1 {
                    return;
                }
            }
            _ => {}
        }
        let key = route.route_key();
        let mut route_table = self.route_table.write();
        let (_, list) = route_table
            .entry(id)
            .or_insert_with(|| (AtomicUsize::new(0), Vec::with_capacity(4)));
        let mut exist = false;
        let mut p2p_num = 0;
        for (x, time) in list.iter_mut() {
            if x.metric < route.metric && !self.first_latency {
                //非优先延迟的情况下 不能比当前的路径更长
                return;
            }
            if x.route_key() == key {
                if only_if_absent {
                    return;
                }
                x.metric = route.metric;
                x.rt = route.rt;
                exist = true;
                time.store(Instant::now());
                break;
            }
            if x.is_p2p() {
                p2p_num += 1;
            }
        }
        if exist {
            list.sort_by_key(|(k, _)| k.rt);
        } else {
            let limit_len = if self.first_latency {
                self.channel_num
            } else {
                if p2p_num >= self.channel_num {
                    // p2p通道满员了则不再添加
                    return;
                }
                if route.metric == 1 {
                    //非优先延迟的情况下 添加了直连的则排除非直连的
                    list.retain(|(k, _)| k.is_p2p());
                }
                self.channel_num - 1
            };
            list.sort_by_key(|(k, _)| k.rt);
            if list.len() > limit_len {
                list.truncate(limit_len);
            }
            list.push((route, AtomicCell::new(Instant::now())));
        }
    }
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
    pub fn need_punch(&self, id: &Ipv4Addr) -> bool {
        if let Some((_, v)) = self.route_table.read().get(id) {
            if v.iter().filter(|(k, _)| k.is_p2p()).count() >= self.channel_num {
                return false;
            }
        }
        true
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
            if let Some((route, _)) = routes.first() {
                if route.is_p2p() {
                    list.push((*ip, *route));
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
    pub fn remove_route(&self, id: &Ipv4Addr, route_key: RouteKey) -> bool {
        let mut write_guard = self.route_table.write();
        if let Some((_, routes)) = write_guard.get_mut(id) {
            routes.retain(|(x, _)| x.route_key() != route_key);
            if routes.is_empty() {
                write_guard.remove(id);
                true
            } else {
                false
            }
        } else {
            return true;
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
