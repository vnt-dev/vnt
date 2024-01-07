use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::net::{SocketAddrV6, TcpStream};
use std::net::{TcpListener, UdpSocket as StdUdpSocket};
#[cfg(any(unix))]
use std::os::fd::AsRawFd;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};
use tokio::net::UdpSocket;
use tokio::sync::watch::{channel, Receiver, Sender};

use crate::channel::punch::NatType;
use crate::channel::{Route, RouteKey, Status, TCP_ID, UDP_ID};
use crate::core::status::VntWorker;
use crate::handle::recv_handler::ChannelDataHandler;
use crate::handle::CurrentDeviceInfo;

pub struct ContextInner {
    //udp用于打洞、服务端通信(可选)
    pub(crate) main_channel: StdUdpSocket,
    //在udp的基础上，可以选择使用tcp和服务端通信
    pub(crate) main_tcp_channel: Option<Mutex<TcpStream>>,
    pub(crate) route_table: RwLock<HashMap<Ipv4Addr, Vec<(Route, AtomicCell<Instant>)>>>,
    pub(crate) status_receiver: Receiver<Status>,
    pub(crate) status_sender: Sender<Status>,
    pub(crate) udp_map: RwLock<HashMap<usize, Arc<UdpSocket>>>,
    pub(crate) tcp_map: RwLock<HashMap<usize, Arc<Mutex<TcpStream>>>>,
    pub(crate) channel_num: usize,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    first_latency: bool,
    is_close: AtomicBool,
    tcp_port: u16,
}

#[derive(Clone)]
pub struct Context {
    pub(crate) inner: Arc<ContextInner>,
}

impl Context {
    pub fn new(
        main_channel: StdUdpSocket,
        main_tcp_channel: Option<TcpStream>,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        _channel_num: usize,
        first_latency: bool,
        tcp_port: u16,
    ) -> Self {
        //当前版本只支持一个通道
        let channel_num = 1;
        let (status_sender, status_receiver) = channel(Status::Cone);
        let main_tcp_channel = main_tcp_channel.map(|e| Mutex::new(e));
        let inner = Arc::new(ContextInner {
            main_channel,
            main_tcp_channel,
            route_table: RwLock::new(HashMap::with_capacity(16)),
            status_receiver,
            status_sender,
            udp_map: RwLock::new(HashMap::with_capacity(16)),
            tcp_map: RwLock::new(HashMap::with_capacity(16)),
            channel_num,
            current_device,
            first_latency,
            is_close: AtomicBool::new(false),
            tcp_port,
        });
        Self { inner }
    }
}

impl Context {
    pub fn is_close(&self) -> bool {
        self.inner.is_close.load(Ordering::Relaxed)
    }
    pub fn is_cone(&self) -> bool {
        *self.inner.status_receiver.borrow() == Status::Cone
    }
    pub fn close(&self) -> io::Result<()> {
        let last = self.is_close();
        self.inner.is_close.store(true, Ordering::Release);
        let _ = self.inner.status_sender.send(Status::Close);
        if let Ok(port) = self.main_local_udp_port() {
            match StdUdpSocket::bind("127.0.0.1:0") {
                Ok(udp) => {
                    if let Err(e) = udp.send_to(
                        b"stop",
                        SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
                    ) {
                        log::error!("发送停止消息到udp失败:{:?}", e);
                    }
                }
                Err(e) => {
                    log::error!("发送停止-绑定udp失败:{:?}", e);
                }
            }
        }
        if let Some(tcp) = &self.inner.main_tcp_channel {
            if let Err(e) = tcp.lock().shutdown(Shutdown::Both) {
                log::error!("发送停止消息到tcp失败:{:?}", e);
            }
        }
        if !last {
            for (_, tcp) in self.inner.tcp_map.read().clone() {
                if let Err(e) = tcp.lock().shutdown(Shutdown::Both) {
                    log::error!("发送停止消息到tcp失败:{:?}", e);
                }
            }
            if let Err(e) = TcpStream::connect_timeout(
                &SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::LOCALHOST,
                    self.inner.tcp_port,
                    0,
                    0,
                )),
                Duration::from_secs(1),
            ) {
                log::error!("发送停止消息到tcp_listener失败:{:?}", e);
            }
        }
        Ok(())
    }
    pub fn is_main_tcp(&self) -> bool {
        self.inner.main_tcp_channel.is_some()
    }
    pub fn is_first_latency(&self) -> bool {
        self.inner.first_latency
    }
    pub fn switch(&self, nat_type: NatType) {
        match nat_type {
            NatType::Symmetric => {
                self.switch_to_symmetric();
            }
            NatType::Cone => {
                self.switch_to_cone();
            }
        }
    }
    pub fn switch_to_cone(&self) {
        let _ = self.inner.status_sender.send(Status::Cone);
    }
    pub fn switch_to_symmetric(&self) {
        let _ = self.inner.status_sender.send(Status::Symmetric);
    }
    pub fn main_local_udp_port(&self) -> io::Result<u16> {
        self.inner.main_channel.local_addr().map(|k| k.port())
    }
    fn insert_udp(&self, id: usize, udp: Arc<UdpSocket>) {
        self.inner.udp_map.write().insert(id, udp);
    }
    fn remove_udp(&self, id: usize) {
        self.inner.udp_map.write().remove(&id);
    }
    #[inline]
    pub fn send_main_udp(&self, buf: &[u8], mut addr: SocketAddr) -> io::Result<usize> {
        if let SocketAddr::V4(ipv4) = addr {
            addr = SocketAddr::V6(SocketAddrV6::new(
                ipv4.ip().to_ipv6_mapped(),
                ipv4.port(),
                0,
                0,
            ));
        }
        self.inner.main_channel.send_to(buf, addr)
    }
    #[inline]
    pub fn send_main_tcp(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(sender) = &self.inner.main_tcp_channel {
            Self::send_tcp(sender, buf)
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "tcp not found"));
        }
    }
    pub fn send_tcp(sender: &Mutex<TcpStream>, buf: &[u8]) -> io::Result<usize> {
        let mut stream = sender.lock();
        send_tcp(&mut stream, buf)
    }

    pub fn send_main(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if let Some(sender) = &self.inner.main_tcp_channel {
            let mut stream = sender.lock();
            let mut head = [0; 4];
            let len = buf.len();
            head[2] = (len >> 8) as u8;
            head[3] = (len & 0xFF) as u8;
            stream.write_all(&head)?;
            stream.write_all(buf)?;
            Ok(len)
        } else {
            self.send_main_udp(buf, addr)
        }
    }

    pub(crate) fn try_send_all(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        let table = self.inner.udp_map.read();
        if table.is_empty() {
            log::error!("udp列表为空,addr={}", addr);
            return Ok(());
        }
        for (_, udp) in table.iter() {
            //使用ipv6的udp发送ipv4报文会出错
            if let Err(e) = udp.try_send_to(buf, addr) {
                log::error!("{:?}", e);
            }
        }
        Ok(())
    }

    pub async fn send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<usize> {
        let route = self.get_route_by_id(id)?;
        self.send_by_key(buf, &route.route_key()).await
    }
    pub fn try_send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<usize> {
        let route = self.get_route_by_id(id)?;
        self.try_send_by_key(buf, &route.route_key())
    }
    fn get_route_by_id(&self, id: &Ipv4Addr) -> io::Result<Route> {
        if let Some(v) = self.inner.route_table.read().get(id) {
            if v.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
            }
            let (route, time) = &v[0];
            if route.rt == 199 {
                //这通常是刚加入路由，直接放弃使用,避免抖动
                return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
            }
            if !route.is_p2p() {
                //借道传输时，长时间不通信的通道不使用
                if time.load().elapsed() > Duration::from_secs(6) {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "route time out"));
                }
            }
            return Ok(*route);
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }

    pub async fn send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
        match route_key.index {
            TCP_ID => self.send_main_tcp(buf),
            UDP_ID => self.send_main_udp(buf, route_key.addr),
            _ => {
                if route_key.is_tcp {
                    if let Some(tcp) = self.get_tcp_by_route(route_key) {
                        return Self::send_tcp(&tcp, buf);
                    }
                } else {
                    if let Some(udp) = self.get_udp_by_route(route_key) {
                        return udp.send_to(buf, route_key.addr).await;
                    }
                }
                Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
            }
        }
    }
    pub fn try_send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
        match route_key.index {
            TCP_ID => self.send_main_tcp(buf),
            UDP_ID => self.send_main_udp(buf, route_key.addr),
            _ => {
                if route_key.is_tcp {
                    if let Some(tcp) = self.get_tcp_by_route(route_key) {
                        return Self::send_tcp(&tcp, buf);
                    }
                } else {
                    if let Some(udp) = self.get_udp_by_route(route_key) {
                        return udp.try_send_to(buf, route_key.addr);
                    }
                }
                Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
            }
        }
    }
    #[inline]
    fn get_udp_by_route(&self, route_key: &RouteKey) -> Option<Arc<UdpSocket>> {
        self.inner.udp_map.read().get(&route_key.index).cloned()
    }
    #[inline]
    fn get_tcp_by_route(&self, route_key: &RouteKey) -> Option<Arc<Mutex<TcpStream>>> {
        self.inner.tcp_map.read().get(&route_key.index).cloned()
    }

    pub fn add_route_if_absent(&self, id: Ipv4Addr, route: Route) {
        self.add_route_(id, route, true)
    }
    pub fn add_route(&self, id: Ipv4Addr, route: Route) {
        self.add_route_(id, route, false)
    }
    fn add_route_(&self, id: Ipv4Addr, route: Route, only_if_absent: bool) {
        let key = route.route_key();
        let mut route_table = self.inner.route_table.write();
        let list = route_table
            .entry(id)
            .or_insert_with(|| Vec::with_capacity(4));
        let mut exist = false;
        for (x, time) in list.iter_mut() {
            if x.metric < route.metric && !self.inner.first_latency {
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
            list.sort_by_key(|(k, _)| k.rt);
        } else {
            let max_len = if self.inner.first_latency {
                self.inner.channel_num + 1
            } else {
                if route.metric == 1 {
                    //非优先延迟的情况下 添加了直连的则排除非直连的
                    list.retain(|(k, _)| k.metric == 1);
                }
                self.inner.channel_num
            };
            list.sort_by_key(|(k, _)| k.rt);
            if list.len() > max_len {
                list.truncate(max_len);
            }
            list.push((route, AtomicCell::new(Instant::now())));
        }
    }
    pub fn route(&self, id: &Ipv4Addr) -> Option<Vec<Route>> {
        if let Some(v) = self.inner.route_table.read().get(id) {
            Some(v.iter().map(|(i, _)| *i).collect())
        } else {
            None
        }
    }
    pub fn route_one(&self, id: &Ipv4Addr) -> Option<Route> {
        if let Some(v) = self.inner.route_table.read().get(id) {
            v.first().map(|(i, _)| *i)
        } else {
            None
        }
    }
    pub fn route_to_id(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        let table = self.inner.route_table.read();
        for (k, v) in table.iter() {
            for (route, _) in v {
                if &route.route_key() == route_key && route.is_p2p() {
                    return Some(*k);
                }
            }
        }
        None
    }
    pub fn need_punch(&self, id: &Ipv4Addr) -> bool {
        if let Some(v) = self.inner.route_table.read().get(id) {
            if v.iter().filter(|(k, _)| k.is_p2p()).count() >= self.inner.channel_num {
                return false;
            }
        }
        true
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        let table = self.inner.route_table.read();
        table
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().map(|(i, _)| *i).collect()))
            .collect()
    }
    pub fn route_table_one(&self) -> Vec<(Ipv4Addr, Route)> {
        let mut list = Vec::with_capacity(8);
        let table = self.inner.route_table.read();
        for (k, v) in table.iter() {
            if let Some((route, _)) = v.first() {
                list.push((*k, *route));
            }
        }
        list
    }
    pub fn direct_route_table_one(&self) -> Vec<(Ipv4Addr, Route)> {
        let mut list = Vec::with_capacity(8);
        let table = self.inner.route_table.read();
        for (k, v) in table.iter() {
            if let Some((route, _)) = v.first() {
                if route.metric == 1 {
                    list.push((*k, *route));
                }
            }
        }
        list
    }

    pub fn remove_route(&self, id: &Ipv4Addr, route_key: RouteKey) {
        if let Some(routes) = self.inner.route_table.write().get_mut(id) {
            routes.retain(|(x, _)| x.route_key() != route_key);
        } else {
            return;
        }
    }
    pub fn update_read_time(&self, id: &Ipv4Addr, route_key: &RouteKey) {
        if let Some(routes) = self.inner.route_table.read().get(id) {
            for (route, time) in routes {
                if &route.route_key() == route_key {
                    time.store(Instant::now());
                    break;
                }
            }
        }
    }
}

pub struct Channel {
    context: Context,
    handler: ChannelDataHandler,
    tcp_listener: TcpListener,
}

impl Channel {
    pub fn new(context: Context, handler: ChannelDataHandler, tcp_listener: TcpListener) -> Self {
        Self {
            context,
            handler,
            tcp_listener,
        }
    }
}

impl Channel {
    fn start_tcp(mut tcp_stream: TcpStream, context: Context, handler: ChannelDataHandler) {
        let current_device = context.inner.current_device.clone();
        loop {
            if let Err(e) = tcp_stream.set_nodelay(true) {
                log::info!("set_nodelay:{:?}", e);
            }
            if let Err(e) = tcp_stream.set_write_timeout(Some(Duration::from_secs(5))) {
                log::info!("set_write_timeout:{:?}", e);
            }
            if let Err(e) = tcp_stream.set_read_timeout(Some(Duration::from_secs(10))) {
                log::info!("set_read_timeout:{:?}", e);
            }
            if let Err(e) = tcp_handle(TCP_ID, &mut tcp_stream, &context, &handler) {
                log::info!("tcp链接断开:{:?}", e);
            }
            if let Err(e) = tcp_stream.shutdown(Shutdown::Both) {
                log::info!("tcp链接关闭异常:{:?}", e);
            }
            loop {
                if context.is_close() {
                    return;
                }
                let device_info = current_device.load();
                match TcpStream::connect(device_info.connect_server) {
                    Ok(tcp) => {
                        tcp_stream = tcp.try_clone().unwrap();
                        let mut guard = context.inner.main_tcp_channel.as_ref().unwrap().lock();
                        *guard = tcp;
                        break;
                    }
                    Err(e) => {
                        log::info!("重连失败,{},{:?}", device_info.connect_server, e);
                        thread::sleep(Duration::from_secs(3));
                    }
                }
            }
        }
    }
    fn start_tcp_listen(
        worker: VntWorker,
        context: Context,
        handler: ChannelDataHandler,
        tcp_listener: TcpListener,
    ) {
        let counter = Arc::new(AtomicUsize::new(0));
        for stream in tcp_listener.incoming() {
            if context.is_close() {
                break;
            }
            if counter.load(Ordering::Relaxed) > 20 {
                continue;
            }
            match stream {
                Ok(stream) => {
                    let context = context.clone();
                    let handler = handler.clone();
                    let counter = counter.clone();
                    counter.fetch_add(1, Ordering::Relaxed);
                    thread::spawn(move || {
                        if let Err(e) = start_tcp_handle(stream, context, handler) {
                            log::error!("{:?}", e);
                        }
                        counter.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    log::error!("connection failed {:?}", e);
                }
            }
        }
        for (_, tcp) in context.inner.tcp_map.read().clone() {
            if let Err(e) = tcp.lock().shutdown(Shutdown::Both) {
                log::error!("发送停止消息到tcp失败:{:?}", e);
            }
        }
        worker.stop_all();
    }

    pub async fn start(
        self,
        mut worker: VntWorker,
        tcp: Option<TcpStream>,
        symmetric_channel_num: usize, //对称网络，则再加一组监听，提升打洞成功率
        relay: bool,
    ) {
        let handler = self.handler.clone();
        let context = self.context;
        let main_channel = context.inner.main_channel.try_clone().unwrap();
        if let Some(tcp_stream) = tcp {
            let context = context.clone();
            let handler = handler.clone();
            let main_channel_tcp = worker.worker("main_channel_tcp");
            thread::Builder::new()
                .name("channel_tcp".into())
                .spawn(move || {
                    Self::start_tcp(tcp_stream, context, handler);
                    drop(main_channel_tcp)
                })
                .unwrap();
        }
        {
            let worker = worker.worker("main_channel_udp");
            let context = context.clone();
            let main_channel = main_channel.try_clone().unwrap();
            let handler = handler.clone();
            thread::Builder::new()
                .name("channel_udp".into())
                .spawn(move || {
                    log::info!("启动udp v4");
                    Self::main_start_(worker, context, UDP_ID, main_channel, handler)
                })
                .unwrap();
        }
        if relay {
            worker.stop_wait().await;
            return;
        }
        {
            let context = context.clone();
            let handler = handler.clone();
            let tcp_listener = self.tcp_listener;
            let worker = worker.worker("tcp_listener");
            thread::Builder::new()
                .name("tcp_listener".into())
                .spawn(move || {
                    log::info!("启动tcp");
                    Self::start_tcp_listen(worker, context, handler, tcp_listener)
                })
                .unwrap();
        }
        let mut cur_status = Status::Cone;
        let mut status_receiver = context.inner.status_receiver.clone();
        let channel_num = context.inner.channel_num;
        loop {
            tokio::select! {
                _=worker.stop_wait()=>{
                    break;
                }
                rs=status_receiver.changed()=>{
                    match rs {
                        Ok(_) => {
                            let s = status_receiver.borrow().clone();
                            match s {
                                Status::Cone => {
                                    cur_status = Status::Cone;
                                }
                                Status::Symmetric => {
                                    if cur_status == Status::Symmetric {
                                        continue;
                                    }
                                    cur_status = Status::Symmetric;
                                    for _ in 0..symmetric_channel_num - channel_num {
                                        match UdpSocket::bind("0.0.0.0:0").await {
                                            Ok(udp) => {
                                                let udp = Arc::new(udp);
                                                let context = context.clone();
                                                tokio::spawn(Self::start_(worker.worker("symmetric_channel"),context, udp,handler.clone()));
                                            }
                                            Err(e) => {
                                                log::error!("{}",e);
                                            }
                                        }
                                    }
                                }
                                Status::Close => {
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
        }
        worker.stop_all();
    }
    fn main_start_(
        worker: VntWorker,
        context: Context,
        id: usize,
        udp: StdUdpSocket,
        handler: ChannelDataHandler,
    ) {
        let mut buf = [0; 4096];
        let head_reserve = handler.head_reserve;
        loop {
            match udp.recv_from(&mut buf[head_reserve..]) {
                Ok((len, addr)) => {
                    let end = head_reserve + len;
                    if &buf[head_reserve..end] == b"stop" {
                        if context.is_close() {
                            break;
                        }
                    }
                    handler.handle(
                        &mut buf,
                        head_reserve,
                        end,
                        RouteKey::new(false, id, addr),
                        &context,
                    );
                }
                Err(e) => {
                    log::error!("udp :{:?}", e);
                }
            }
        }

        worker.stop_all();
    }
    async fn start_(
        mut worker: VntWorker,
        context: Context,
        udp: Arc<UdpSocket>,
        handler: ChannelDataHandler,
    ) {
        let mut status_receiver = context.inner.status_receiver.clone();

        #[cfg(target_os = "windows")]
        let id = 3 + udp.as_raw_socket() as usize;
        #[cfg(any(unix))]
        let id = 3 + udp.as_raw_fd() as usize;

        context.insert_udp(id, udp.clone());
        let mut buf = [0; 4096];
        let head_reserve = handler.head_reserve;
        loop {
            tokio::select! {
                rs=udp.recv_from(&mut buf[head_reserve..])=>{
                      match rs {
                        Ok((len, addr)) => {
                            handler.handle(&mut buf, head_reserve, head_reserve + len, RouteKey::new(false,id, addr), &context);
                        }
                        Err(e) => {
                            log::error!("{:?}",e)
                        }
                    }
                }
                changed=status_receiver.changed()=>{
                        match changed {
                            Ok(_) => {
                                match *status_receiver.borrow() {
                                    Status::Cone => {
                                        break;
                                    }
                                    Status::Close=>{
                                        break;
                                    }
                                    Status::Symmetric => {}
                                }
                            }
                            Err(_) => {
                                break;
                            }
                        }
                }
                _=worker.stop_wait()=>{
                    break;
                }
            }
        }
        context.remove_udp(id);
    }
}
pub fn start_tcp_handle(
    mut stream: TcpStream,
    context: Context,
    handler: ChannelDataHandler,
) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    if let Err(e) = stream.set_nodelay(true) {
        log::error!("设置nodelay失败 {:?}", e);
    }
    let writer = stream.try_clone()?;
    #[cfg(target_os = "windows")]
    let id = 3 + stream.as_raw_socket() as usize;
    #[cfg(any(unix))]
    let id = 3 + stream.as_raw_fd() as usize;
    context
        .inner
        .tcp_map
        .write()
        .insert(id, Arc::new(Mutex::new(writer)));
    if let Err(e) = tcp_handle(id, &mut stream, &context, &handler) {
        log::error!("tcp_handle {:?}", e);
    }
    context.inner.tcp_map.write().remove(&id);
    Ok(())
}
pub fn tcp_handle(
    id: usize,
    tcp_r: &mut TcpStream,
    context: &Context,
    handler: &ChannelDataHandler,
) -> io::Result<()> {
    let mut head = [0; 4];
    let addr = tcp_r.peer_addr()?;
    let key = RouteKey::new(true, id, addr);
    let head_reserve = handler.head_reserve;
    loop {
        if context.is_close() {
            return Ok(());
        }
        let mut buf = [0; 4096];
        tcp_r.read_exact(&mut head)?;
        let len = (((head[2] as u16) << 8) | head[3] as u16) as usize;
        if len < 12 || len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "length overflow",
            ));
        }
        tcp_r.read_exact(&mut buf[head_reserve..head_reserve + len])?;
        handler.handle(&mut buf, head_reserve, head_reserve + len, key, context);
    }
}
pub fn send_tcp(stream: &mut TcpStream, buf: &[u8]) -> io::Result<usize> {
    let mut head = [0; 4];
    let len = buf.len();
    head[2] = (len >> 8) as u8;
    head[3] = (len & 0xFF) as u8;
    stream.write_all(&head)?;
    stream.write_all(buf)?;
    Ok(len)
}
