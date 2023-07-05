use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use crossbeam_skiplist::SkipMap;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::watch::{channel, Receiver, Sender};
use crate::channel::{Route, RouteKey, Status};
use crate::channel::punch::NatType;
use crate::core::status::SwitchWorker;
use crate::handle::recv_handler::ChannelDataHandler;

pub struct ContextInner {
    pub(crate) lock: Mutex<()>,
    pub(crate) count: AtomicUsize,
    pub(crate) main_channel: Arc<UdpSocket>,
    pub(crate) route_table: SkipMap<Ipv4Addr, Vec<Route>>,
    pub(crate) route_table_time: SkipMap<(RouteKey, Ipv4Addr), AtomicCell<Instant>>,
    pub(crate) status_receiver: Receiver<Status>,
    pub(crate) status_sender: Sender<Status>,
    pub(crate) udp_map: SkipMap<usize, Arc<UdpSocket>>,
    pub(crate) channel_num: usize,
}

#[derive(Clone)]
pub struct Context {
    pub(crate) inner: Arc<ContextInner>,
}

impl Context {
    pub fn new(main_channel: Arc<UdpSocket>, _channel_num: usize) -> Self {
        //当前版本只支持一个通道
        let channel_num = 1;
        let (status_sender, status_receiver) = channel(Status::Cone);
        let inner = Arc::new(ContextInner {
            lock: Mutex::new(()),
            count: AtomicUsize::new(0),
            main_channel,
            route_table: SkipMap::new(),
            route_table_time: SkipMap::new(),
            status_receiver,
            status_sender,
            udp_map: SkipMap::new(),
            channel_num,
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
        self.inner.main_channel.send_to(buf, addr).await
    }

    pub(crate) async fn send_all(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        for udp in self.inner.udp_map.iter() {
            udp.value().send_to(buf, addr).await?;
        }
        Ok(())
    }
    pub fn try_send_main(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.main_channel.try_send_to(buf, addr)
    }
    pub async fn send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<usize> {
        if let Some(v) = self.inner.route_table.get(id) {
            let route = match v.value().len() {
                0 => {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
                }
                1 => v.value()[0],
                len => v.value()[self.inner.count.fetch_add(1, Ordering::Relaxed) % len]
            };
            drop(v);
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
            let route = v.value()[self.inner.count.fetch_add(1, Ordering::Relaxed) % v.value().len()];
            drop(v);
            if let Some(udp) = self.inner.udp_map.get(&route.index) {
                return udp.value().try_send_to(buf, route.addr);
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub async fn send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
        if let Some(udp) = self.inner.udp_map.get(&route_key.index) {
            return udp.value().send_to(buf, route_key.addr).await;
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub fn try_send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
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
                    udp: &Arc<UdpSocket>,
                    context: &Context,
                    id: usize,
                    result: io::Result<(usize, SocketAddr)>,
                    buf: &mut [u8], start: usize) {
        match result {
            Ok((len, addr)) => {
                handler.handle(buf, start, start + len, RouteKey::new(id, addr), &udp, context).await;
            }
            Err(e) => {
                log::error!("{:?}",e)
            }
        }
    }
    pub async fn start(self,
                       mut worker: SwitchWorker,
                       head_reserve: usize,//头部预留字节
                       symmetric_channel_num: usize,//对称网络，则再加一组监听，提升打洞成功率
    ) {
        let context = self.context;
        let main_channel = context.inner.main_channel.clone();
        let handler = self.handler.clone();
        tokio::spawn(Self::start_(worker.clone(), context.clone(), handler.clone(), main_channel.clone(), head_reserve, true));
        tokio::spawn(Self::start_(worker.clone(), context.clone(), handler, main_channel, head_reserve, true));
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
                            match *status_receiver.borrow() {
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
                                                tokio::spawn(Self::start_(worker.clone(),context, handler, udp, head_reserve, false));
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
    async fn start_(mut worker: SwitchWorker, context: Context,
                    mut handler: ChannelDataHandler,
                    udp: Arc<UdpSocket>,
                    head_reserve: usize,
                    is_core: bool) {
        let mut status_receiver = context.inner.status_receiver.clone();
        #[cfg(target_os = "windows")]
        use std::os::windows::io::AsRawSocket;
        #[cfg(target_os = "windows")]
            let id = udp.as_raw_socket() as usize;
        #[cfg(any(unix))]
        use std::os::fd::AsRawFd;
        #[cfg(any(unix))]
            let id = udp.as_raw_fd() as usize;
        context.inner.udp_map.insert(id, udp.clone());
        let mut buf = [0; 4096];
        loop {
            tokio::select! {
                rs=udp.recv_from(&mut buf[head_reserve..])=>{
                    Self::handle(&mut handler,&udp,&context,id,rs,&mut buf,head_reserve).await;
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
