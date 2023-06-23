use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::sync::watch::{channel, Receiver, Sender};
use crate::channel::{Route, RouteKey, Status};
use crate::channel::punch::NatType;
use crate::handle::recv_handler::ChannelDataHandler;

#[derive(Clone)]
pub struct Context {
    pub(crate) count: Arc<AtomicUsize>,
    pub(crate) main_channel: Arc<UdpSocket>,
    pub(crate) route_table: Arc<DashMap<Ipv4Addr, Vec<Route>>>,
    pub(crate) route_table_time: Arc<SkipMap<(RouteKey, Ipv4Addr), AtomicI64>>,
    pub(crate) status_receiver: Receiver<Status>,
    pub(crate) status_sender: Arc<Sender<Status>>,
    pub(crate) udp_map: Arc<SkipMap<usize, Arc<UdpSocket>>>,
    pub(crate) channel_num: usize,
    pub(crate) notify: Arc<Notify>,
}

impl Context {
    pub fn new(main_channel: Arc<UdpSocket>, _channel_num: usize) -> Self {
        //当前版本只支持一个通道
        let channel_num = 1;
        let (status_sender, status_receiver) = channel(Status::Cone);
        let status_sender = Arc::new(status_sender);
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            main_channel,
            route_table: Arc::new(DashMap::with_capacity(16)),
            route_table_time: Arc::new(SkipMap::new()),
            status_receiver,
            status_sender,
            udp_map: Arc::new(SkipMap::new()),
            channel_num,
            notify: Arc::new(Notify::new()),
        }
    }
}

impl Context {
    pub fn is_close(&self) -> bool {
        *self.status_receiver.borrow() == Status::Close
    }
    pub fn is_cone(&self) -> bool {
        *self.status_receiver.borrow() == Status::Cone
    }
    pub fn close(&self) {
        let _ = self.status_sender.send(Status::Close);
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
        let _ = self.status_sender.send(Status::Cone);
    }
    pub fn switch_to_symmetric(&self) {
        let _ = self.status_sender.send(Status::Symmetric);
    }
    pub fn main_local_port(&self) -> io::Result<u16> {
        self.main_channel.local_addr().map(|k| k.port())
    }
    pub async fn send_main(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.main_channel.send_to(buf, addr).await
    }

    pub(crate) async fn send_all(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        for udp in self.udp_map.iter() {
            udp.value().send_to(buf, addr).await?;
        }
        Ok(())
    }
    pub fn try_send_main(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.main_channel.try_send_to(buf, addr)
    }
    pub async fn send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<usize> {
        if let Some(v) = self.route_table.get(id) {
            let route = match v.len() {
                0 => {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
                }
                1 => &v[0],
                len => &v[self.count.fetch_add(1, Ordering::Relaxed) % len]
            };
            if let Some(udp) = self.udp_map.get(&route.index) {
                return udp.value().send_to(buf, route.addr).await;
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub fn try_send_by_id(&self, buf: &[u8], id: &Ipv4Addr) -> io::Result<usize> {
        if let Some(v) = self.route_table.get(id) {
            if v.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
            }
            let route = &v[self.count.fetch_add(1, Ordering::Relaxed) % v.len()];
            if let Some(udp) = self.udp_map.get(&route.index) {
                return udp.value().try_send_to(buf, route.addr);
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub async fn send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
        if let Some(udp) = self.udp_map.get(&route_key.index) {
            return udp.value().send_to(buf, route_key.addr).await;
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }
    pub fn try_send_by_key(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<usize> {
        if let Some(udp) = self.udp_map.get(&route_key.index) {
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
        let mut ref_mut = self.route_table.entry(id.clone()).or_insert(Vec::with_capacity(4));
        let mut exist = false;
        for x in ref_mut.iter_mut() {
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
        if !exist {
            if route.metric == 1 {
                //添加了直连的则排除非直连的
                ref_mut.retain(|k| k.metric == 1);
            }
            ref_mut.push(route);
            let max_len = self.channel_num;
            if ref_mut.len() > max_len {
                ref_mut.sort_by_key(|k| k.sort_key());
                ref_mut.truncate(max_len);
            }
        }
        self.route_table_time.insert((key, id), AtomicI64::new(chrono::Local::now().timestamp_millis()));
        self.notify.notify_one();
    }
    pub fn route(&self, id: &Ipv4Addr) -> Option<Vec<Route>> {
        if let Some(v) = self.route_table.get(id) {
            Some(v.value().clone())
        } else {
            None
        }
    }
    pub fn route_one(&self, id: &Ipv4Addr) -> Option<Route> {
        if let Some(v) = self.route_table.get(id) {
            v.value().iter().max_by_key(|k| k.sort_key()).map(|k| *k)
        } else {
            None
        }
    }
    pub fn route_to_id(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        for x in self.route_table_time.iter() {
            if &x.key().0 == route_key {
                return Some(x.key().1);
            }
        }
        None
    }
    pub fn need_punch(&self, id: &Ipv4Addr) -> bool {
        if let Some(v) = self.route_table.get(id) {
            if v.iter().filter(|k| k.is_p2p()).count() >= self.channel_num {
                return false;
            }
        }
        true
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.route_table.iter().map(|k| (k.key().clone(), k.value().clone())).collect()
    }
    pub fn route_table_one(&self) -> Vec<(Ipv4Addr, Route)> {
        let mut v = Vec::with_capacity(8);
        for x in self.route_table.iter() {
            if let Some(route) = x.value().iter().max_by_key(|k| k.sort_key()) {
                v.push((*x.key(), *route));
            }
        }
        v
    }
    pub fn direct_route_table_one(&self) -> Vec<(Ipv4Addr, Route)> {
        let mut v = Vec::with_capacity(8);
        for x in self.route_table.iter() {
            if let Some(route) = x.value().iter().max_by_key(|k| k.sort_key()) {
                if route.metric == 1 {
                    v.push((*x.key(), *route));
                }
            }
        }
        v
    }
    pub fn remove_route_all(&self, id: &Ipv4Addr) {
        if let Some((_, v)) = self.route_table.remove(id) {
            for x in v {
                self.route_table_time.remove(&(x.route_key(), id.clone()));
            }
        }
    }
    pub fn remove_route(&self, id: &Ipv4Addr, route_key: RouteKey) {
        if let Some(mut v) = self.route_table.get_mut(id) {
            v.retain(|x| x.route_key() != route_key);
            self.route_table_time.remove(&(route_key, id.clone()));
        }
    }
    pub fn update_read_time(&self, id: &Ipv4Addr, route_key: &RouteKey) {
        if let Some(time) = self.route_table_time.get(&(*route_key, *id)) {
            time.value().store(chrono::Local::now().timestamp_millis(), Ordering::Relaxed);
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
                       head_reserve: usize,//头部预留字节
                       symmetric_channel_num: usize,//对称网络，则再加一组监听，提升打洞成功率
    ) {
        let mut context = self.context;
        let main_channel = context.main_channel.clone();
        let handler = self.handler.clone();
        tokio::spawn(Self::start_(context.clone(), handler, main_channel, head_reserve, true));
        let mut cur_status = Status::Cone;
        loop {
            match context.status_receiver.changed().await {
                Ok(_) => {
                    match *context.status_receiver.borrow() {
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
                                        tokio::spawn(Self::start_(context, handler, udp, head_reserve, false));
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
    async fn start_(context: Context,
                    mut handler: ChannelDataHandler,
                    udp: Arc<UdpSocket>,
                    head_reserve: usize,
                    is_core: bool) {
        let mut status_receiver = context.status_receiver.clone();
        #[cfg(target_os = "windows")]
        use std::os::windows::io::AsRawSocket;
        #[cfg(target_os = "windows")]
            let id = udp.as_raw_socket() as usize;
        #[cfg(any(unix))]
        use std::os::fd::AsRawFd;
        #[cfg(any(unix))]
            let id = udp.as_raw_fd() as usize;
        context.udp_map.insert(id, udp.clone());
        let mut buf = [0; 65546];
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
            }
        }
        context.udp_map.remove(&id);
    }
}


// pub async fn start<H: ChannelDataHandler + Clone>(mut handler: H,
//                                                   mut status_receiver: Receiver<Status>,
//                                                   head_reserve: usize,
//                                                   core_channel_num: usize,
//                                                   symmetric_channel_num: usize) -> io::Result<()> {
//     for _ in 0..core_channel_num {
//         let d = channel(1);
//     }
//     let udp = UdpSocket::bind("0.0.0.0:0").await?;
//     let d = status_receiver.changed().await;
//     match d {
//         Ok(_) => {
//             match *status_receiver.borrow() {
//                 Status::Cone => {}
//                 Status::Symmetric => {}
//                 Status::Close => {}
//             }
//         }
//         Err(_) => {}
//     }
//     let mut buf = [0; 65546];
//     let result = udp.recv_from(&mut buf[head_reserve..]).await;
//     match result {
//         Ok((len, addr)) => {}
//         Err(e) => {}
//     }
//     Ok(())
// }
//
// pub struct Channel<H: ChannelDataHandler + Clone> {
//     handler: H,
//
// }