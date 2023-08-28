use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::watch::{channel, Receiver, Sender};
use crate::channel::{Route, RouteKey, Status};
use crate::channel::punch::NatType;
use crate::core::status::VntWorker;
use crate::handle::CurrentDeviceInfo;
use crate::handle::recv_handler::ChannelDataHandler;
use byte_pool::{Block, BytePool};
lazy_static::lazy_static! {
    static ref POOL:BytePool = BytePool::new();
}
pub struct ContextInner {
    //udp用于打洞、服务端通信(可选)
    pub(crate) main_channel: Arc<UdpSocket>,
    //在udp的基础上，可以选择使用tcp和服务端通信
    pub(crate) main_tcp_channel: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    pub(crate) route_table: DashMap<Ipv4Addr, Vec<Route>>,
    pub(crate) route_table_time: DashMap<(RouteKey, Ipv4Addr), AtomicCell<Instant>>,
    pub(crate) status_receiver: Receiver<Status>,
    pub(crate) status_sender: Sender<Status>,
    pub(crate) udp_map: DashMap<usize, Arc<UdpSocket>>,
    pub(crate) channel_num: usize,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
}

#[derive(Clone)]
pub struct Context {
    pub(crate) inner: Arc<ContextInner>,
}

impl Context {
    pub fn new(main_channel: Arc<UdpSocket>, main_tcp_channel: Option<tokio::sync::mpsc::Sender<Vec<u8>>>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>, _channel_num: usize) -> Self {
        //当前版本只支持一个通道
        let channel_num = 1;
        let (status_sender, status_receiver) = channel(Status::Cone);
        let inner = Arc::new(ContextInner {
            main_channel,
            main_tcp_channel,
            route_table: DashMap::with_capacity(16),
            route_table_time: DashMap::with_capacity(16),
            status_receiver,
            status_sender,
            udp_map: DashMap::new(),
            channel_num,
            current_device,
        });
        Self {
            inner
        }
    }
}

impl Context {
    pub fn is_close(&self) -> bool {
        *self.inner.status_receiver.borrow() == Status::Close
    }
    pub fn is_cone(&self) -> bool {
        *self.inner.status_receiver.borrow() == Status::Cone
    }
    pub fn close(&self) {
        let _ = self.inner.status_sender.send(Status::Close);
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
    pub fn main_local_port(&self) -> io::Result<u16> {
        self.inner.main_channel.local_addr().map(|k| k.port())
    }
    pub async fn send_main_udp(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.main_channel.send_to(buf, addr).await
    }
    pub async fn send_main(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if let Some(sender) = &self.inner.main_tcp_channel {
            if sender.send(buf.to_vec()).await.is_ok() {
                Ok(buf.len())
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "send_main err"))
            }
        } else {
            self.inner.main_channel.send_to(buf, addr).await
        }
    }
    pub fn try_send_main(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if let Some(sender) = &self.inner.main_tcp_channel {
            if sender.try_send(buf.to_vec()).is_ok() {
                Ok(buf.len())
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "try_send_main err"))
            }
        } else {
            self.inner.main_channel.try_send_to(buf, addr)
        }
    }

    pub(crate) async fn send_all(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        for udp_ref in self.inner.udp_map.iter() {
            let udp = udp_ref.clone();
            drop(udp_ref);
            udp.send_to(buf, addr).await?;
        }
        Ok(())
    }

    pub async fn send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<usize> {
        if let Some(v) = self.inner.route_table.get(id) {
            if v.value().is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
            }
            let route = v.value()[0];
            drop(v);
            if !route.is_p2p() {
                if let Some(time) = self.inner.route_table_time.get(&(route.route_key(), *id)) {
                    //借道传输时，长时间不通信的通道不使用
                    if time.value().load().elapsed() > Duration::from_secs(6) {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "route time out"));
                    }
                }
            }

            if let Some(udp_ref) = self.inner.udp_map.get(&route.index) {
                let udp = udp_ref.value().clone();
                drop(udp_ref);
                return udp.send_to(buf, route.addr).await;
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }

    pub fn try_send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<usize> {
        if let Some(v) = self.inner.route_table.get(id) {
            if v.value().is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
            }
            let route = v.value()[0];
            drop(v);
            if let Some(udp) = self.inner.udp_map.get(&route.index) {
                return udp.value().try_send_to(buf, route.addr);
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub async fn send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
        if route_key.index == 0 {
            if let Some(sender) = &self.inner.main_tcp_channel {
                let mut vec = vec![0; 4 + buf.len()];
                vec[4..].copy_from_slice(buf);
                return if sender.send(vec).await.is_ok() {
                    Ok(buf.len())
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "send_by_key err"))
                };
            }
        }
        if let Some(udp_ref) = self.inner.udp_map.get(&route_key.index) {
            let udp = udp_ref.value().clone();
            drop(udp_ref);
            return udp.send_to(buf, route_key.addr).await;
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub fn try_send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
        if route_key.index == 0 {
            if let Some(sender) = &self.inner.main_tcp_channel {
                let mut vec = vec![0; 4 + buf.len()];
                vec[4..].copy_from_slice(buf);
                return if sender.try_send(vec).is_ok() {
                    Ok(buf.len())
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "try_send_by_key err"))
                };
            }
        }
        if let Some(udp) = self.inner.udp_map.get(&route_key.index) {
            return udp.value().try_send_to(buf, route_key.addr);
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
        let key = route.route_key();
        let mut list = self.inner.route_table.entry(id).or_insert_with(|| Vec::with_capacity(4));
        let mut exist = false;
        for x in list.iter_mut() {
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
                break;
            }
        }
        if exist {
            list.sort_by_key(|k| k.sort_key());
        } else {
            if route.metric == 1 {
                //添加了直连的则排除非直连的
                list.retain(|k| k.metric == 1);
            }
            list.push(route);
            list.sort_by_key(|k| k.sort_key());
            let max_len = self.inner.channel_num + 1;
            if list.len() > max_len {
                list.truncate(max_len);
            }
        }
        self.inner.route_table_time.insert((key, id), AtomicCell::new(Instant::now()));
    }
    pub fn route(&self, id: &Ipv4Addr) -> Option<Vec<Route>> {
        if let Some(v) = self.inner.route_table.get(id) {
            Some(v.value().clone())
        } else {
            None
        }
    }
    pub fn route_one(&self, id: &Ipv4Addr) -> Option<Route> {
        if let Some(v) = self.inner.route_table.get(id) {
            v.value().first().map(|v| *v)
        } else {
            None
        }
    }
    pub fn route_to_id(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        for x in self.inner.route_table.iter() {
            for route in x.value() {
                if &route.route_key() == route_key && route.is_p2p() {
                    return Some(*x.key());
                }
            }
        }
        None
    }
    pub fn need_punch(&self, id: &Ipv4Addr) -> bool {
        if let Some(v) = self.inner.route_table.get(id) {
            if v.value().iter().filter(|k| k.is_p2p()).count() >= self.inner.channel_num {
                return false;
            }
        }
        true
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.inner.route_table.iter().map(|k| (k.key().clone(), k.value().clone())).collect()
    }
    pub fn route_table_one(&self) -> Vec<(Ipv4Addr, Route)> {
        let mut v = Vec::with_capacity(8);
        for x in self.inner.route_table.iter() {
            if let Some(route) = x.value().first() {
                v.push((*x.key(), *route));
            }
        }
        v
    }
    pub fn direct_route_table_one(&self) -> Vec<(Ipv4Addr, Route)> {
        let mut v = Vec::with_capacity(8);
        for x in self.inner.route_table.iter() {
            if let Some(route) = x.value().first() {
                if route.metric == 1 {
                    v.push((*x.key(), *route));
                }
            }
        }
        v
    }
    pub fn remove_route_all(&self, id: &Ipv4Addr) {
        if let Some((_, routes)) = self.inner.route_table.remove(id) {
            for x in routes {
                self.inner.route_table_time.remove(&(x.route_key(), *id));
            }
        }
    }
    pub fn remove_route(&self, id: &Ipv4Addr, route_key: RouteKey) {
        if let Some(v) = self.inner.route_table.get(id) {
            let mut routes = v.value().clone();
            drop(v);
            routes.retain(|x| x.route_key() != route_key);
            self.inner.route_table.insert(*id, routes);
        }
        self.inner.route_table_time.remove(&(route_key, *id));
    }
    pub fn update_read_time(&self, id: &Ipv4Addr, route_key: &RouteKey) {
        if let Some(time) = self.inner.route_table_time.get(&(*route_key, *id)) {
            time.value().store(Instant::now());
        }
    }
}

pub struct Channel {
    context: Context,
    handler: ChannelDataHandler,
}

impl Channel {
    pub fn new(context: Context,
               handler: ChannelDataHandler, ) -> Self {
        Self {
            context,
            handler,
        }
    }
}

#[derive(Clone)]
struct BufSenderGroup(usize, Vec<tokio::sync::mpsc::Sender<(Block<'static>, usize, usize, RouteKey)>>);

struct BufReceiverGroup(Vec<tokio::sync::mpsc::Receiver<(Block<'static>, usize, usize, RouteKey)>>);

impl BufSenderGroup {
    pub async fn send(&mut self, val: (Block<'static>, usize, usize, RouteKey)) -> bool {
        let index = self.0 % self.1.len();
        self.0 = self.0.wrapping_add(1);
        self.1[index].send(val).await.is_ok()
    }
}

fn buf_channel_group(size: usize) -> (BufSenderGroup, BufReceiverGroup) {
    let mut buf_sender_group = Vec::with_capacity(size);
    let mut buf_receiver_group = Vec::with_capacity(size);
    for _ in 0..size {
        let (buf_sender, buf_receiver) = tokio::sync::mpsc::channel::<(Block<'static, Vec<u8>>, usize, usize, RouteKey)>(10);
        buf_sender_group.push(buf_sender);
        buf_receiver_group.push(buf_receiver);
    }
    (BufSenderGroup(0, buf_sender_group), BufReceiverGroup(buf_receiver_group))
}

impl Channel {
    async fn tcp_handle(mut tcp_r: OwnedReadHalf, mut buf_sender: BufSenderGroup, head_reserve: usize) -> io::Result<()> {
        let mut head = [0; 4];
        let addr = tcp_r.peer_addr()?;
        let key = RouteKey::new(0, addr);
        loop {
            let mut buf = POOL.alloc(4096);
            tcp_r.read_exact(&mut head).await?;
            let len = (((head[2] as u16) << 8) | head[3] as u16) as usize;
            if len < 12 || len > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "length overflow",
                ));
            }
            tcp_r.read_exact(&mut buf[head_reserve..head_reserve + len]).await?;
            if !buf_sender.send((buf, head_reserve, head_reserve + len, key)).await {
                return Err(io::Error::new(io::ErrorKind::Other, "buf_sender发送数据失败"));
            }
        }
    }
    async fn start_tcp(mut worker: VntWorker, tcp_stream: TcpStream, mut receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
                       current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
                       buf_sender: BufSenderGroup, head_reserve: usize) {
        let (tcp_r, mut tcp_w) = tcp_stream.into_split();
        {
            let buf_sender = buf_sender.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::tcp_handle(tcp_r, buf_sender, head_reserve).await {
                    log::info!("tcp链接断开:{:?}",e);
                }
            });
        }
        let mut head = [0; 4];
        loop {
            tokio::select! {
                _=worker.stop_wait()=>{
                    break;
                }
                rs=receiver.recv()=>{
                    if let Some(data) = rs{
                        let len = data.len();
                        head[2] = (len >> 8) as u8;
                        head[3] = (len & 0xFF) as u8;
                        let mut err = false;
                        if let Err(e) = tcp_w.write_all(&head).await{
                            err = true;
                            log::info!("发送失败,需要重连:{:?}",e);
                        }else if let Err(e) = tcp_w.write_all(&data).await{
                            err = true;
                            log::info!("发送失败,需要重连:{:?}",e);
                        }
                        if err {
                            let _ = tcp_w.shutdown().await;
                            match TcpStream::connect(current_device.load().connect_server).await {
                                Ok(tcp_stream) => {
                                    let (r, w) = tcp_stream.into_split();
                                    tcp_w = w;
                                    let buf_sender = buf_sender.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = Self::tcp_handle(r, buf_sender, head_reserve).await {
                                            log::info!("tcp 链接断开:{:?}",e);
                                        }
                                    });
                                }
                                Err(e) => {
                                    log::info!("重连失败:{:?}",e);
                                }
                            };
                        }
                    }else{
                        break;
                    }
                }
            }
        }
        worker.stop_all();
    }

    pub async fn start(self,
                       mut worker: VntWorker,
                       tcp: Option<(TcpStream, tokio::sync::mpsc::Receiver<Vec<u8>>)>,
                       head_reserve: usize,//头部预留字节
                       symmetric_channel_num: usize,//对称网络，则再加一组监听，提升打洞成功率
                       relay: bool,
                       parallel: usize,
    ) {
        let handler = self.handler.clone();
        let context = self.context;
        let main_channel = context.inner.main_channel.clone();
        let buf_sender = if parallel > 1 || tcp.is_some() {
            let (buf_sender, buf_receiver) = buf_channel_group(parallel);
            for mut buf_receiver in buf_receiver.0 {
                let context = context.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    while let Some((mut buf, start, end, route_key)) = buf_receiver.recv().await {
                        handler.handle(&mut buf, start, end, route_key, &context).await;
                    }
                });
            }
            Some(buf_sender)
        } else {
            None
        };
        if let Some((tcp_stream, receiver)) = tcp {
            tokio::spawn(Self::start_tcp(worker.worker("main_channel_tcp"), tcp_stream, receiver, context.inner.current_device.clone(), buf_sender.clone().unwrap(), head_reserve));
        }
        tokio::spawn(Self::start_(worker.worker("main_channel_1"), context.clone(), main_channel.clone(), handler.clone(), buf_sender.clone(), head_reserve, true));
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
    async fn start_(mut worker: VntWorker, context: Context,
                    udp: Arc<UdpSocket>,
                    handler: ChannelDataHandler,
                    buf_sender: Option<BufSenderGroup>,
                    head_reserve: usize,
                    is_core: bool) {
        let mut status_receiver = context.inner.status_receiver.clone();
        #[cfg(target_os = "windows")]
        use std::os::windows::io::AsRawSocket;
        #[cfg(target_os = "windows")]
            let id = 1 + udp.as_raw_socket() as usize;
        #[cfg(any(unix))]
        use std::os::fd::AsRawFd;
        #[cfg(any(unix))]
            let id = 1 + udp.as_raw_fd() as usize;
        context.inner.udp_map.insert(id, udp.clone());
        match buf_sender {
            None => {
                let mut buf = [0; 4096];
                loop {
                    tokio::select! {
                        rs=udp.recv_from(&mut buf[head_reserve..])=>{
                              match rs {
                                Ok((len, addr)) => {
                                    handler.handle(&mut buf, head_reserve, head_reserve + len, RouteKey::new(id, addr), &context).await;
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
            Some(mut buf_sender) => {
                loop {
                    let mut buf = POOL.alloc(4096);
                    tokio::select! {
                        rs=udp.recv_from(&mut buf[head_reserve..])=>{
                             match rs {
                                Ok((len, addr)) => {
                                    if !buf_sender.send((buf,head_reserve,head_reserve+len,RouteKey::new(id, addr))).await{
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
                }
            }
        }
        context.inner.udp_map.remove(&id);
        if is_core {
            worker.stop_all();
        }
    }
}
