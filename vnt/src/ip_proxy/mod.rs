use crate::ip_proxy::tcp_proxy::TcpProxy;
use crate::ip_proxy::udp_proxy::UdpProxy;
use dashmap::DashMap;
#[cfg(not(target_os = "android"))]
use socket2::{SockAddr, Socket};
#[cfg(not(target_os = "android"))]
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::{io, thread};
use tokio::net::{TcpListener, UdpSocket};

#[cfg(not(target_os = "android"))]
pub mod icmp_proxy;
pub mod tcp_proxy;
pub mod udp_proxy;

pub trait DashMapNew {
    fn new0() -> Self;
    fn new_cap(capacity: usize) -> Self;
}

impl<'a, K: 'a + Eq + std::hash::Hash, V: 'a> DashMapNew for DashMap<K, V> {
    fn new0() -> Self {
        Self::new_cap(0)
    }

    fn new_cap(capacity: usize) -> Self {
        let shard_amount = (thread::available_parallelism().map_or(4, |v| {
            // https://github.com/rust-lang/rust/issues/115868
            let n: usize = v.get() * 4;
            if n == 0 {
                log::warn!("available_parallelism=0");
                println!("warn available_parallelism=0");
            }
            if n < 4 {
                return 4;
            }
            n
        }))
        .next_power_of_two();
        DashMap::with_capacity_and_shard_amount(capacity, shard_amount)
    }
}

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
    #[cfg(not(target_os = "android"))]
    pub(crate) icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
    #[cfg(not(target_os = "android"))]
    icmp_socket: Arc<Socket>,
}

impl IpProxyMap {
    #[cfg(not(target_os = "android"))]
    pub fn send_icmp(&self, buf: &[u8], dest: &Ipv4Addr) -> io::Result<usize> {
        self.icmp_socket
            .send_to(buf, &SockAddr::from(SocketAddrV4::new(*dest, 0)))
    }
}

pub async fn init_proxy(
    #[cfg(not(target_os = "android"))] sender: crate::channel::sender::ChannelSender,
    #[cfg(not(target_os = "android"))] current_device: Arc<
        crossbeam_utils::atomic::AtomicCell<crate::handle::CurrentDeviceInfo>,
    >,
    #[cfg(not(target_os = "android"))] client_cipher: crate::cipher::Cipher,
) -> io::Result<(TcpProxy, UdpProxy, IpProxyMap)> {
    let tcp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>> = Arc::new(DashMap::new0());
    let udp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>> = Arc::new(DashMap::new0());
    #[cfg(not(target_os = "android"))]
    let icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>> = Arc::new(DashMap::new0());
    let tcp_listener = TcpListener::bind("0.0.0.0:0").await?;
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let tcp_proxy_port = tcp_listener.local_addr()?.port();
    let udp_proxy_port = udp_socket.local_addr()?.port();
    let tcp_proxy = TcpProxy::new(tcp_listener, tcp_proxy_map.clone());
    let udp_proxy = UdpProxy::new(udp_socket, udp_proxy_map.clone());
    #[cfg(not(target_os = "android"))]
    let icmp_socket = {
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        let icmp_proxy = icmp_proxy::IcmpProxy::new(
            addr,
            icmp_proxy_map.clone(),
            sender.clone(),
            current_device.clone(),
            client_cipher,
        )?;
        let icmp_socket = icmp_proxy.icmp_socket();
        thread::spawn(move || {
            icmp_proxy.start();
        });
        icmp_socket
    };

    Ok((
        tcp_proxy,
        udp_proxy,
        IpProxyMap {
            tcp_proxy_port,
            udp_proxy_port,
            tcp_proxy_map,
            udp_proxy_map,
            #[cfg(not(target_os = "android"))]
            icmp_proxy_map,
            #[cfg(not(target_os = "android"))]
            icmp_socket,
        },
    ))
}
