use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;
use rand::Rng;

use crate::channel::punch::NatType;
use crate::channel::sender::{AcceptSocketSender, ChannelSender, PacketSender};
use crate::channel::{Route, RouteKey, UseChannelType, DEFAULT_RT};

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
        use_ipv6: bool,
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
            main_index: AtomicUsize::new(0),
            use_ipv6,
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
pub const SYMMETRIC_CHANNEL_NUM: usize = 100;
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
    main_index: AtomicUsize,
    use_ipv6: bool,
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
        if self.use_ipv6 {
            //如果是v4地址则需要转换成v6
            if let SocketAddr::V4(ipv4) = addr {
                addr = SocketAddr::V6(SocketAddrV6::new(
                    ipv4.ip().to_ipv6_mapped(),
                    ipv4.port(),
                    0,
                    0,
                ));
            }
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
            self.send_main_udp(self.main_index.load(Ordering::Relaxed), buf, addr)
        }
    }
    pub fn is_default_route(&self, route_key: RouteKey) -> bool {
        self.is_tcp == route_key.is_tcp && self.main_index.load(Ordering::Relaxed) == route_key.index
    }
    pub fn change_main_index(&self) {
        let index = (self.main_index.load(Ordering::Relaxed) + 1) % self.main_udp_socket.len();
        self.main_index.store(index, Ordering::Relaxed);
    }
    /// 此方法仅用于对称网络打洞
    pub fn try_send_all(&self, buf: &[u8], addr: SocketAddr) {
        self.try_send_all_main(buf, addr);
        for udp in self.sub_udp_socket.read().iter() {
            if let Err(e) = udp.send_to(buf, addr) {
                log::warn!("{:?},add={:?}", e, addr);
            }
            thread::sleep(Duration::from_millis(1));
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
    pub fn send_ipv4_by_id(
        &self,
        buf: &[u8],
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
    pub fn send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<()> {
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
        self.route_table.remove_route(ip, route_key)
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
    fn get_route_by_id(&self, index: usize, id: &Ipv4Addr) -> io::Result<Route> {
        if let Some((_count, v)) = self.route_table.read().get(id) {
            if self.first_latency {
                if let Some((route, _)) = v.first() {
                    return Ok(*route);
                }
            } else {
                let len = v.len();
                if len != 0 {
                    return Ok(v[index % len].0);
                }
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
                if !route.is_p2p() {
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
        }
        if exist {
            // 这个排序还有待优化，因为后加入的大概率排最后，被直接淘汰的概率也大，可能导致更好的通道被移除了
            list.sort_by_key(|(k, _)| k.rt);
            //如果延迟都稳定了，则去除多余通道
            for (route, _) in list.iter() {
                if route.rt == DEFAULT_RT {
                    return;
                }
            }
            //延迟优先模式需要更多的通道探测延迟最低的路线
            let limit_len = if self.first_latency {
                self.channel_num + 2
            } else {
                self.channel_num
            };
            self.truncate_(list, limit_len);
        } else {
            if !self.first_latency {
                if route.is_p2p() {
                    //非优先延迟的情况下 添加了直连的则排除非直连的
                    list.retain(|(k, _)| k.is_p2p());
                }
            };
            //增加路由表容量，避免波动
            let limit_len = self.channel_num * 2;
            list.sort_by_key(|(k, _)| k.rt);
            self.truncate_(list, limit_len);
            list.push((route, AtomicCell::new(Instant::now())));
        }
    }
    fn truncate_(&self, list: &mut Vec<(Route, AtomicCell<Instant>)>, len: usize) {
        if list.len() <= len {
            return;
        }
        if self.first_latency {
            //找到第一个p2p通道
            if let Some(index) =
                list.iter()
                    .enumerate()
                    .find_map(|(index, (route, _))| if route.is_p2p() { Some(index) } else { None })
            {
                if index >= len {
                    //保留第一个p2p通道
                    let route = list.remove(index);
                    list.truncate(len - 1);
                    list.push(route);
                    return;
                }
            }
        }
        list.truncate(len);
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
