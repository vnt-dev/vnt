use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::channel::context::Context;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::sender::AcceptSocketSender;
use crate::channel::tcp_channel::tcp_listen;
use crate::channel::udp_channel::udp_listen;
use crate::util::{io_convert, StopManager};

pub mod context;
pub mod handler;
pub mod idle;
pub mod notify;
pub mod punch;
pub mod sender;
pub mod tcp_channel;
pub mod udp_channel;

const BUFFER_SIZE: usize = 1024 * 16;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Status {
    Cone,
    Symmetric,
    Close,
}

#[derive(Copy, Clone, Debug)]
pub struct Route {
    pub is_tcp: bool,
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

impl Route {
    pub fn new(is_tcp: bool, index: usize, addr: SocketAddr, metric: u8, rt: i64) -> Self {
        Self {
            is_tcp,
            index,
            addr,
            metric,
            rt,
        }
    }
    pub fn from(route_key: RouteKey, metric: u8, rt: i64) -> Self {
        Self {
            is_tcp: route_key.is_tcp,
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt,
        }
    }
    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            is_tcp: self.is_tcp,
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
    is_tcp: bool,
    index: usize,
    pub addr: SocketAddr,
}

impl RouteKey {
    pub(crate) fn new(is_tcp: bool, index: usize, addr: SocketAddr) -> Self {
        Self {
            is_tcp,
            index,
            addr,
        }
    }
    pub fn is_tcp(&self) -> bool {
        self.is_tcp
    }
    pub fn index(&self) -> usize {
        self.index
    }
}

pub fn init_context(
    ports: Vec<u16>,
    first_latency: bool,
    is_tcp: bool,
) -> io::Result<(Context, mio::net::TcpListener)> {
    assert!(!ports.is_empty(), "not channel");
    let mut udps = Vec::with_capacity(ports.len());
    for port in &ports {
        //监听v6+v4双栈，主通道使用同步io
        let address: SocketAddr = format!("[::]:{}", port).parse().unwrap();
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
        io_convert(socket.set_only_v6(false), |_| {
            format!("set_only_v6 failed: {}", &address)
        })?;
        io_convert(socket.bind(&address.into()), |_| {
            format!("bind failed: {}", &address)
        })?;
        let main_channel: UdpSocket = socket.into();
        main_channel.set_write_timeout(Some(Duration::from_secs(5)))?;
        udps.push(main_channel);
    }
    let context = Context::new(udps, first_latency, is_tcp);

    let port = context.main_local_udp_port()?[0];
    //监听v6+v4双栈，tcp通道使用异步io
    let address: SocketAddr = format!("[::]:{}", port).parse().unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
    io_convert(socket.set_only_v6(false), |_| {
        format!("set_only_v6 failed: {}", &address)
    })?;

    if let Err(e) = socket.bind(&address.into()) {
        if ports[0] == 0 {
            //端口可能冲突，则使用任意端口
            log::warn!("监听tcp端口失败 {:?},重试一次", address);
            let address: SocketAddr = format!("[::]:{}", 0).parse().unwrap();
            io_convert(socket.bind(&address.into()), |_| {
                format!("bind failed: {}", &address)
            })?;
        } else {
            //手动指定的ip,直接报错
            io_convert(Err(e), |_| format!("bind failed: {}", &address))?;
        }
    }
    socket.listen(2)?;
    socket.set_nonblocking(true)?;
    socket.set_nodelay(false)?;
    let tcp_listener = mio::net::TcpListener::from_std(socket.into());
    Ok((context, tcp_listener))
}

pub fn init_channel<H>(
    tcp_listener: mio::net::TcpListener,
    context: Context,
    stop_manager: StopManager,
    recv_handler: H,
) -> io::Result<(
    AcceptSocketSender<Option<Vec<mio::net::UdpSocket>>>,
    AcceptSocketSender<(mio::net::TcpStream, SocketAddr, Option<Vec<u8>>)>,
)>
where
    H: RecvChannelHandler,
{
    // udp监听，udp_socket_sender 用于NAT类型切换
    let udp_socket_sender =
        udp_listen(stop_manager.clone(), recv_handler.clone(), context.clone())?;
    // 建立tcp监听，tcp_socket_sender 用于tcp 直连
    let tcp_socket_sender = tcp_listen(
        tcp_listener,
        stop_manager.clone(),
        recv_handler.clone(),
        context.clone(),
    )?;

    Ok((udp_socket_sender, tcp_socket_sender))
}
