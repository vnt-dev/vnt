use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use crossbeam_skiplist::SkipMap;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::watch::{channel, Receiver, Sender};
use crate::channel::{Route, RouteKey, Status};
use crate::channel::punch::NatType;
use crate::core::status::VntWorker;
use crate::handle::CurrentDeviceInfo;
use crate::handle::recv_handler::ChannelDataHandler;

pub struct ContextInner {
    pub(crate) lock: Mutex<()>,
    //udp用于打洞、服务端通信(可选)
    pub(crate) main_channel: Arc<UdpSocket>,
    //在udp的基础上，可以选择使用tcp和服务端通信
    pub(crate) main_tcp_channel: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    pub(crate) route_table: SkipMap<Ipv4Addr, Vec<Route>>,
    pub(crate) route_table_time: SkipMap<(RouteKey, Ipv4Addr), AtomicCell<Instant>>,
    pub(crate) status_receiver: Receiver<Status>,
    pub(crate) status_sender: Sender<Status>,
    pub(crate) udp_map: SkipMap<usize, Arc<UdpSocket>>,
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
            lock: Mutex::new(()),
            main_channel,
            main_tcp_channel,
            route_table: SkipMap::new(),
            route_table_time: SkipMap::new(),
            status_receiver,
            status_sender,
            udp_map: SkipMap::new(),
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
    pub async fn send_main(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if let Some(sender) = &self.inner.main_tcp_channel {
            let mut vec = vec![0; 4 + buf.len()];
            vec[4..].copy_from_slice(buf);
            if sender.send(vec).await.is_ok() {
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
            let mut vec = vec![0; 4 + buf.len()];
            vec[4..].copy_from_slice(buf);
            if sender.try_send(vec).is_ok() {
                Ok(buf.len())
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "try_send_main err"))
            }
        } else {
            self.inner.main_channel.try_send_to(buf, addr)
        }
    }

    pub(crate) async fn send_all(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        for udp in self.inner.udp_map.iter() {
            udp.value().send_to(buf, addr).await?;
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
                    if time.value().load().elapsed() > Duration::from_secs(3) {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "route time out"));
                    }
                }
            }

            if let Some(udp) = self.inner.udp_map.get(&route.index) {
                return udp.value().send_to(buf, route.addr).await;
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
        if let Some(udp) = self.inner.udp_map.get(&route_key.index) {
            return udp.value().send_to(buf, route_key.addr).await;
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
        let guard = self.inner.lock.lock();
        let mut list = if let Some(entry) = self.inner.route_table.get(&id) {
            entry.value().clone()
        } else {
            Vec::with_capacity(4)
        };
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
        self.inner.route_table.insert(id, list);
        self.inner.route_table_time.insert((key, id), AtomicCell::new(Instant::now()));
        drop(guard);
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
            v.value().iter().max_by_key(|k| k.sort_key()).map(|k| *k)
        } else {
            None
        }
    }
    pub fn route_to_id(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        for x in self.inner.route_table_time.iter() {
            if &x.key().0 == route_key {
                return Some(x.key().1);
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
        let guard = self.inner.lock.lock();
        if let Some(v) = self.inner.route_table.remove(id) {
            for x in v.value() {
                self.inner.route_table_time.remove(&(x.route_key(), *id));
            }
        }
        drop(guard);
    }
    pub fn remove_route(&self, id: &Ipv4Addr, route_key: RouteKey) {
        let guard = self.inner.lock.lock();
        if let Some(v) = self.inner.route_table.get(id) {
            let mut routes = v.value().clone();
            drop(v);
            routes.retain(|x| x.route_key() != route_key);
            self.inner.route_table.insert(*id, routes);
            self.inner.route_table_time.remove(&(route_key, *id));
        }
        drop(guard);
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

impl Channel {
    async fn handle(handler: &mut ChannelDataHandler,
                    context: &Context,
                    id: usize,
                    result: io::Result<(usize, SocketAddr)>,
                    buf: &mut [u8], start: usize) {
        match result {
            Ok((len, addr)) => {
                handler.handle(buf, start, start + len, RouteKey::new(id, addr), context).await;
            }
            Err(e) => {
                log::error!("{:?}",e)
            }
        }
    }
    async fn tcp_handle(mut tcp_r: OwnedReadHalf, context: Context,
                        mut handler: ChannelDataHandler, head_reserve: usize, ) -> io::Result<()> {
        let mut buf = [0; 4096];
        let addr = tcp_r.peer_addr()?;
        let key = RouteKey::new(0, addr);
        loop {
            tcp_r.read_exact(&mut buf[head_reserve..head_reserve + 4]).await?;
            let len = 4 + (((buf[head_reserve + 2] as u16) << 8) | buf[head_reserve + 3] as u16) as usize;
            tcp_r.read_exact(&mut buf[head_reserve + 4..head_reserve + len]).await?;
            handler.handle(&mut buf[4..], head_reserve, head_reserve + len - 4, key, &context).await;
        }
    }
    async fn start_tcp(mut worker: VntWorker, tcp_stream: TcpStream, mut receiver: tokio::sync::mpsc::Receiver<Vec<u8>>, context: Context, handler: ChannelDataHandler, head_reserve: usize) {
        let (tcp_r, mut tcp_w) = tcp_stream.into_split();
        {
            let context = context.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::tcp_handle(tcp_r, context, handler, head_reserve).await {
                    log::info!("tcp链接断开:{:?}",e);
                }
            });
        }
        loop {
            tokio::select! {
                _=worker.stop_wait()=>{
                    break;
                }
                rs=receiver.recv()=>{
                    if let Some(mut data) = rs{
                        if data.len()<4{
                            continue
                        }
                        let len = data.len() - 4;
                        data[2] = (len >> 8) as u8;
                        data[3] = (len & 0xFF) as u8;
                        if let Err(e) = tcp_w.write_all(&data).await {
                            if context.is_close() {
                                break;
                            }
                            log::info!("发送失败,需要重连:{:?}",e);
                            let _ = tcp_w.shutdown().await;
                            match TcpStream::connect(context.inner.current_device.load().connect_server).await {
                                Ok(tcp_stream) => {
                                    let (r, w) = tcp_stream.into_split();
                                    tcp_w = w;
                                    let context = context.clone();
                                    let handler = handler.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = Self::tcp_handle(r, context, handler, head_reserve).await {
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
    ) {
        let context = self.context;
        let main_channel = context.inner.main_channel.clone();
        let handler = self.handler.clone();
        if let Some((tcp_stream, receiver)) = tcp {
            tokio::spawn(Self::start_tcp(worker.worker("main_channel_tcp"), tcp_stream, receiver, context.clone(), handler.clone(), head_reserve));
        }
        tokio::spawn(Self::start_(worker.worker("main_channel_1"), context.clone(), handler.clone(), main_channel.clone(), head_reserve, true));
        // tokio::spawn(Self::start_(worker.worker("main_channel_2"), context.clone(), handler, main_channel, head_reserve, true));
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
                                                let handler = self.handler.clone();
                                                tokio::spawn(Self::start_(worker.worker("symmetric_channel"),context, handler, udp, head_reserve, false));
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
                    mut handler: ChannelDataHandler,
                    udp: Arc<UdpSocket>,
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
        let mut buf = [0; 4096];
        loop {
            tokio::select! {
                rs=udp.recv_from(&mut buf[head_reserve..])=>{
                    Self::handle(&mut handler,&context,id,rs,&mut buf,head_reserve).await;
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
        context.inner.udp_map.remove(&id);
        if is_core {
            worker.stop_all();
        }
    }
}
