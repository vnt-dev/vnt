use std::{io, thread};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use crossbeam::atomic::AtomicCell;
use crossbeam_skiplist::SkipMap;
use socket2::{SockAddr, Socket};
use tokio::net::{TcpListener, UdpSocket};
use p2p_channel::channel::sender::Sender;
use crate::handle::CurrentDeviceInfo;
use crate::ip_proxy::icmp_proxy::IcmpProxy;
use crate::ip_proxy::tcp_proxy::TcpProxy;
use crate::ip_proxy::udp_proxy::UdpProxy;

pub mod icmp_proxy;
pub mod tcp_proxy;
pub mod udp_proxy;

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
}

#[derive(Clone)]
pub struct IpProxyMap {
    pub(crate) tcp_proxy_port: u16,
    pub(crate) udp_proxy_port: u16,
    //真实源地址 -> (绑定地址,目的地址)
    pub(crate) tcp_proxy_map: Arc<SkipMap<SocketAddrV4, (SocketAddrV4, SocketAddrV4)>>,
    pub(crate) udp_proxy_map: Arc<SkipMap<SocketAddrV4, (SocketAddrV4, SocketAddrV4)>>,
    // icmp用Identifier来区分，没有Identifier的一律不转发
    pub(crate) icmp_proxy_map: Arc<SkipMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
    icmp_sockets: HashMap<Ipv4Addr, Arc<Socket>>,
}

impl IpProxyMap {
    pub fn send_icmp(&self, buf: &[u8], src: &Ipv4Addr, dest: &Ipv4Addr) -> io::Result<usize> {
        if let Some(socket) = self.icmp_sockets.get(src) {
            socket.send_to(buf, &SockAddr::from(SocketAddrV4::new(*dest, 0)))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, format!("not found src:{},dest:{}", src, dest)))
        }
    }
}

pub async fn init_proxy(sender: Sender<Ipv4Addr>, bind_ips: Vec<Ipv4Addr>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) -> io::Result<IpProxyMap> {
    let mut icmp_sockets = HashMap::new();
    let tcp_proxy_map: Arc<SkipMap<SocketAddrV4, (SocketAddrV4, SocketAddrV4)>> = Arc::new(SkipMap::new());
    let udp_proxy_map: Arc<SkipMap<SocketAddrV4, (SocketAddrV4, SocketAddrV4)>> = Arc::new(SkipMap::new());
    let icmp_proxy_map: Arc<SkipMap<(Ipv4Addr, u16, u16), Ipv4Addr>> = Arc::new(SkipMap::new());
    let tcp_listener = TcpListener::bind("0.0.0.0:0").await?;
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let tcp_proxy_port = tcp_listener.local_addr()?.port();
    let udp_proxy_port = udp_socket.local_addr()?.port();

    {
        let tcp_proxy_map = tcp_proxy_map.clone();
        tokio::spawn(async {
            let tcp_proxy = TcpProxy::new(tcp_listener, tcp_proxy_map);
            tcp_proxy.start().await
        });
    }
    {
        let udp_proxy_map = udp_proxy_map.clone();
        tokio::spawn(async {
            let udp_proxy = UdpProxy::new(udp_socket, udp_proxy_map);
            udp_proxy.start().await
        });
    }
    for ip in bind_ips {
        let addr = SocketAddrV4::new(ip, 0);
        let icmp_proxy_map = icmp_proxy_map.clone();
        let icmp_proxy = IcmpProxy::new(addr, icmp_proxy_map, sender.try_clone()?, current_device.clone())?;
        icmp_sockets.insert(ip, icmp_proxy.icmp_socket());
        thread::spawn(move || {
            icmp_proxy.start();
        });
    }

    Ok(IpProxyMap {
        tcp_proxy_port,
        udp_proxy_port,
        tcp_proxy_map,
        udp_proxy_map,
        icmp_proxy_map,
        icmp_sockets,
    })
}