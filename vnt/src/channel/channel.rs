use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddrV6, TcpStream};
use std::net::UdpSocket as StdUdpSocket;
use std::net::{Ipv4Addr, Shutdown, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::watch::{channel, Receiver, Sender};

use crate::channel::punch::NatType;
use crate::channel::{Route, RouteKey, Status, TCP_ID, UDP_ID};
use crate::core::status::VntWorker;
use crate::handle::recv_handler::ChannelDataHandler;
use crate::handle::CurrentDeviceInfo;

pub struct ContextInner {
    //udp用于打洞、服务端通信(可选)
    pub(crate) main_channel: Arc<StdUdpSocket>,
    //在udp的基础上，可以选择使用tcp和服务端通信
    pub(crate) main_tcp_channel: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    pub(crate) route_table: RwLock<HashMap<Ipv4Addr, Vec<(Route, AtomicCell<Instant>)>>>,
    pub(crate) status_receiver: Receiver<Status>,
    pub(crate) status_sender: Sender<Status>,
    pub(crate) udp_map: RwLock<HashMap<usize, Arc<UdpSocket>>>,
    pub(crate) channel_num: usize,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    first_latency: bool,
}

#[derive(Clone)]
pub struct Context {
    pub(crate) inner: Arc<ContextInner>,
}

impl Context {
    pub fn new(
        main_channel: Arc<StdUdpSocket>,
        main_tcp_channel: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        _channel_num: usize,
        first_latency: bool,
    ) -> Self {
        //当前版本只支持一个通道
        let channel_num = 1;
        let (status_sender, status_receiver) = channel(Status::Cone);
        let inner = Arc::new(ContextInner {
            main_channel,
            main_tcp_channel,
            route_table: RwLock::new(HashMap::with_capacity(16)),
            status_receiver,
            status_sender,
            udp_map: RwLock::new(HashMap::with_capacity(16)),
            channel_num,
            current_device,
            first_latency,
        });
        Self { inner }
    }
}

impl Context {
    pub fn is_close(&self) -> bool {
        *self.inner.status_receiver.borrow() == Status::Close
    }
    pub fn is_cone(&self) -> bool {
        *self.inner.status_receiver.borrow() == Status::Cone
    }
    pub fn close(&self) -> io::Result<()> {
        let _ = self.inner.status_sender.send(Status::Close);
        if let Ok(port) = self.main_local_udp_port() {
            let _ = StdUdpSocket::bind("127.0.0.1:0")?.send_to(
                b"stop",
                SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            );
        }
        if let Some(tcp) = &self.inner.main_tcp_channel {
            let _ = tcp.send(vec![]);
        }
        Ok(())
    }
    pub fn is_main_tcp(&self) -> bool {
        self.inner.main_tcp_channel.is_some()
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
        if let SocketAddr::V4(ipv4) = addr{
            addr = SocketAddr::V6(SocketAddrV6::new(ipv4.ip().to_ipv6_mapped(), ipv4.port(),0,0));
        }
        self.inner.main_channel.send_to(buf, addr)
    }

    pub fn send_main(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if let Some(sender) = &self.inner.main_tcp_channel {
            if sender.try_send(buf.to_vec()).is_ok() {
                Ok(buf.len())
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "send_main err"))
            }
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
            TCP_ID => {
                if let Some(sender) = &self.inner.main_tcp_channel {
                    if sender.send(buf.to_vec()).is_ok() {
                        Ok(buf.len())
                    } else {
                        Err(io::Error::new(io::ErrorKind::Other, "send_by_key err"))
                    }
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "send_by_key err"))
                }
            }
            UDP_ID => self.send_main_udp(buf, route_key.addr),
            _ => {
                if let Some(udp) = self.get_udp_by_route(route_key) {
                    return udp.send_to(buf, route_key.addr).await;
                }
                Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
            }
        }
    }
    pub fn try_send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
        match route_key.index {
            TCP_ID => {
                if let Some(sender) = &self.inner.main_tcp_channel {
                    if sender.try_send(buf.to_vec()).is_ok() {
                        Ok(buf.len())
                    } else {
                        Err(io::Error::new(io::ErrorKind::Other, "send_by_key err"))
                    }
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "send_by_key err"))
                }
            }
            UDP_ID => self.send_main_udp(buf, route_key.addr),
            _ => {
                if let Some(udp) = self.get_udp_by_route(route_key) {
                    return udp.try_send_to(buf, route_key.addr);
                }
                Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
            }
        }
    }
    fn get_udp_by_route(&self, route_key: &RouteKey) -> Option<Arc<UdpSocket>> {
        self.inner.udp_map.read().get(&route_key.index).cloned()
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
            if x.metric < route.metric {
                //不能比当前的路径更长
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
            if route.metric == 1 && !self.inner.first_latency {
                //非优先延迟的情况下 添加了直连的则排除非直连的
                list.retain(|(k, _)| k.metric == 1);
            }
            list.sort_by_key(|(k, _)| k.rt);
            let max_len = self.inner.channel_num;
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
}

impl Channel {
    pub fn new(context: Context, handler: ChannelDataHandler) -> Self {
        Self { context, handler }
    }
}

#[derive(Clone)]
struct BufSenderGroup(
    usize,
    Vec<std::sync::mpsc::SyncSender<(Vec<u8>, usize, usize, RouteKey)>>,
);

struct BufReceiverGroup(Vec<std::sync::mpsc::Receiver<(Vec<u8>, usize, usize, RouteKey)>>);

impl BufSenderGroup {
    pub fn send(&mut self, val: (Vec<u8>, usize, usize, RouteKey)) -> bool {
        let index = self.0 % self.1.len();
        self.0 = self.0.wrapping_add(1);
        self.1[index].send(val).is_ok()
    }
}

fn buf_channel_group(size: usize) -> (BufSenderGroup, BufReceiverGroup) {
    let mut buf_sender_group = Vec::with_capacity(size);
    let mut buf_receiver_group = Vec::with_capacity(size);
    for _ in 0..size {
        let (buf_sender, buf_receiver) =
            std::sync::mpsc::sync_channel::<(Vec<u8>, usize, usize, RouteKey)>(1);
        buf_sender_group.push(buf_sender);
        buf_receiver_group.push(buf_receiver);
    }
    (
        BufSenderGroup(0, buf_sender_group),
        BufReceiverGroup(buf_receiver_group),
    )
}

impl Channel {
    fn tcp_handle(
        tcp_r: &mut TcpStream,
        context: Context,
        handler: ChannelDataHandler,
        head_reserve: usize,
    ) -> io::Result<()> {
        let mut head = [0; 4];
        let addr = tcp_r.peer_addr()?;
        let key = RouteKey::new(TCP_ID, addr);
        loop {
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
            handler.handle(&mut buf, head_reserve, head_reserve + len, key, &context);
        }
    }
    fn start_tcp(
        worker: VntWorker,
        mut tcp_stream: TcpStream,
        receiver: std::sync::mpsc::Receiver<Vec<u8>>,
        context: Context,
        handler: ChannelDataHandler,
        head_reserve: usize,
    ) {
        let current_device = context.inner.current_device.clone();
        {
            let mut tcp_r = tcp_stream.try_clone().unwrap();
            let context = context.clone();
            let handler = handler.clone();
            thread::Builder::new()
                .name("tcp_reader".into())
                .spawn(move || {
                    if let Err(e) = Self::tcp_handle(&mut tcp_r, context, handler, head_reserve) {
                        log::info!("tcp链接断开:{:?}", e);
                    }
                    if let Err(e) = tcp_r.shutdown(Shutdown::Both) {
                        log::info!("tcp链接关闭异常:{:?}", e);
                    }
                })
                .unwrap();
        }
        let mut head = [0; 4];
        loop {
            let data = match receiver.recv() {
                Ok(data) => data,
                Err(_) => {
                    break;
                }
            };
            let len = data.len();
            if len == 0 {
                break;
            }
            head[2] = (len >> 8) as u8;
            head[3] = (len & 0xFF) as u8;
            let mut err = false;
            if let Err(e) = tcp_stream.write_all(&head) {
                err = true;
                log::info!("发送失败,需要重连:{:?}", e);
            } else if let Err(e) = tcp_stream.write_all(&data) {
                err = true;
                log::info!("发送失败,需要重连:{:?}", e);
            }
            if err {
                if let Err(e) = tcp_stream.shutdown(Shutdown::Both) {
                    log::info!("tcp链接关闭异常:{:?}", e);
                }
                match TcpStream::connect(current_device.load().connect_server) {
                    Ok(tcp) => {
                        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                        tcp_stream = tcp;
                        let mut tcp_r = tcp_stream.try_clone().unwrap();
                        let context = context.clone();
                        let handler = handler.clone();
                        thread::Builder::new()
                            .name("tcp_reader".into())
                            .spawn(move || {
                                if let Err(e) =
                                    Self::tcp_handle(&mut tcp_r, context, handler, head_reserve)
                                {
                                    log::info!("重连后 tcp链接断开:{:?}", e);
                                }
                                if let Err(e) = tcp_r.shutdown(Shutdown::Both) {
                                    log::info!("重连后 tcp链接关闭异常:{:?}", e);
                                }
                            })
                            .unwrap();
                    }
                    Err(e) => {
                        log::info!("重连失败:{:?}", e);
                    }
                }
            }
        }
        if let Err(e) = tcp_stream.shutdown(Shutdown::Both) {
            log::info!("tcp链接关闭异常:{:?}", e);
        }
        worker.stop_all();
    }

    pub async fn start(
        self,
        mut worker: VntWorker,
        tcp: Option<(TcpStream, std::sync::mpsc::Receiver<Vec<u8>>)>,
        head_reserve: usize,          //头部预留字节
        symmetric_channel_num: usize, //对称网络，则再加一组监听，提升打洞成功率
        relay: bool,
        parallel: usize,
    ) {
        let handler = self.handler.clone();
        let context = self.context;
        let main_channel = context.inner.main_channel.clone();
        let buf_sender = if parallel > 1 {
            let (buf_sender, buf_receiver) = buf_channel_group(parallel);
            let mut num = 0;
            for buf_receiver in buf_receiver.0 {
                let context = context.clone();
                let handler = handler.clone();
                thread::Builder::new()
                    .name(format!("recv-handler-{}", num))
                    .spawn(move || {
                        while let Ok((mut buf, start, end, route_key)) = buf_receiver.recv() {
                            handler.handle(&mut buf, start, end, route_key, &context);
                        }
                        log::warn!("异步处理停止");
                    })
                    .unwrap();
                num += 1;
            }
            Some(buf_sender)
        } else {
            None
        };
        if let Some((tcp_stream, receiver)) = tcp {
            let context = context.clone();
            let handler = handler.clone();
            let main_channel_tcp = worker.worker("main_channel_tcp");
            thread::Builder::new()
                .name("main_channel_tcp".into())
                .spawn(move || {
                    Self::start_tcp(
                        main_channel_tcp,
                        tcp_stream,
                        receiver,
                        context,
                        handler,
                        head_reserve,
                    )
                })
                .unwrap();
        }
        {
            let worker = worker.worker("main_channel_1");
            let context = context.clone();
            let main_channel = main_channel.clone();
            let handler = handler.clone();
            let buf_sender = buf_sender.clone();
            thread::Builder::new()
                .name("ipv4-recv".into())
                .spawn(move || {
                    log::info!("启动udp v4");
                    Self::main_start_(
                        worker,
                        context,
                        UDP_ID,
                        main_channel,
                        handler,
                        buf_sender,
                        head_reserve,
                    )
                })
                .unwrap();
        }
        if relay {
            worker.stop_wait().await;
            return;
        }
        let mut cur_status = Status::Cone;
        let mut status_receiver = context.inner.status_receiver.clone();
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
                                    for _ in 0..symmetric_channel_num {
                                        match UdpSocket::bind("0.0.0.0:0").await {
                                            Ok(udp) => {
                                                let udp = Arc::new(udp);
                                                let context = context.clone();
                                                tokio::spawn(Self::start_(worker.worker("symmetric_channel"),context, udp,handler.clone(),buf_sender.clone(), head_reserve, false));
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
        udp: Arc<StdUdpSocket>,
        handler: ChannelDataHandler,
        buf_sender: Option<BufSenderGroup>,
        head_reserve: usize,
    ) {
        match buf_sender {
            None => {
                let mut buf = [0; 4096];
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
                                RouteKey::new(id, addr),
                                &context,
                            );
                        }
                        Err(e) => {
                            log::error!("udp :{:?}", e);
                        }
                    }
                }
            }
            Some(mut buf_sender) => loop {
                let mut buf = vec![0; 4096];
                match udp.recv_from(&mut buf[head_reserve..]) {
                    Ok((len, addr)) => {
                        let end = head_reserve + len;
                        if &buf[head_reserve..end] == b"stop" {
                            if context.is_close() {
                                break;
                            }
                        }
                        buf_sender.send((buf, head_reserve, end, RouteKey::new(id, addr)));
                    }
                    Err(e) => {
                        log::error!("udp :{:?}", e);
                    }
                }
            },
        }

        worker.stop_all();
    }
    async fn start_(
        mut worker: VntWorker,
        context: Context,
        udp: Arc<UdpSocket>,
        handler: ChannelDataHandler,
        buf_sender: Option<BufSenderGroup>,
        head_reserve: usize,
        is_core: bool,
    ) {
        let mut status_receiver = context.inner.status_receiver.clone();
        #[cfg(target_os = "windows")]
        use std::os::windows::io::AsRawSocket;
        #[cfg(target_os = "windows")]
        let id = 3 + udp.as_raw_socket() as usize;
        #[cfg(any(unix))]
        use std::os::fd::AsRawFd;
        #[cfg(any(unix))]
        let id = 3 + udp.as_raw_fd() as usize;

        context.insert_udp(id, udp.clone());
        match buf_sender {
            None => {
                let mut buf = [0; 4096];
                loop {
                    tokio::select! {
                        rs=udp.recv_from(&mut buf[head_reserve..])=>{
                              match rs {
                                Ok((len, addr)) => {
                                    handler.handle(&mut buf, head_reserve, head_reserve + len, RouteKey::new(id, addr), &context);
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
                                                if !is_core{
                                                    break;
                                                }
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
            }
            Some(mut buf_sender) => loop {
                let mut buf = vec![0; 4096];
                tokio::select! {
                    rs=udp.recv_from(&mut buf[head_reserve..])=>{
                         match rs {
                            Ok((len, addr)) => {
                                if !buf_sender.send((buf,head_reserve,head_reserve+len,RouteKey::new(id, addr))){
                                     log::error!("udp buf_sender发送数据失败");
                                     break;
                                }
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
                                            if !is_core{
                                                break;
                                            }
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
            },
        }
        context.remove_udp(id);
        if is_core {
            worker.stop_all();
        }
    }
}
