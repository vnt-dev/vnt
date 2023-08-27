use std::{io, thread};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;
use socket2::{SockAddr, Socket};
use tokio::net::{TcpListener, UdpSocket};
use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
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
    //真实源地址 -> 目的地址
    pub(crate) tcp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
    pub(crate) udp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
    // icmp用Identifier来区分，没有Identifier的一律不转发
    pub(crate) icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
    icmp_socket: Arc<Socket>,
}

impl IpProxyMap {
    pub fn send_icmp(&self, buf: &[u8], dest: &Ipv4Addr) -> io::Result<usize> {
        self.icmp_socket.send_to(buf, &SockAddr::from(SocketAddrV4::new(*dest, 0)))
    }
}

pub async fn init_proxy(sender: ChannelSender, current_device: Arc<AtomicCell<CurrentDeviceInfo>>, client_cipher: Cipher,) -> io::Result<(TcpProxy, UdpProxy, IpProxyMap)> {
    let tcp_proxy_map: Arc<DashMap<SocketAddrV4,  SocketAddrV4>> = Arc::new(DashMap::new());
    let udp_proxy_map: Arc<DashMap<SocketAddrV4,  SocketAddrV4>> = Arc::new(DashMap::new());
    let icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>> = Arc::new(DashMap::new());
    let tcp_listener = TcpListener::bind("0.0.0.0:0").await?;
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let tcp_proxy_port = tcp_listener.local_addr()?.port();
    let udp_proxy_port = udp_socket.local_addr()?.port();
    let tcp_proxy = TcpProxy::new(tcp_listener, tcp_proxy_map.clone());
    let udp_proxy = UdpProxy::new(udp_socket, udp_proxy_map.clone());
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let icmp_proxy = IcmpProxy::new(addr, icmp_proxy_map.clone(),
                                    sender.clone(), current_device.clone(),client_cipher)?;
    let icmp_socket = icmp_proxy.icmp_socket();
    thread::spawn(move || {
        icmp_proxy.start();
    });

    Ok((tcp_proxy, udp_proxy, IpProxyMap {
        tcp_proxy_port,
        udp_proxy_port,
        tcp_proxy_map,
        udp_proxy_map,
        icmp_proxy_map,
        icmp_socket,
    }))
}