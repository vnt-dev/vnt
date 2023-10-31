use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;
use packet::ip::ipv4;
use tokio::net::UdpSocket;

use packet::ip::ipv4::packet::IpV4Packet;

use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::handle::CurrentDeviceInfo;
#[cfg(not(target_os = "android"))]
use crate::ip_proxy::icmp_proxy::IcmpHandler;
use crate::ip_proxy::tcp_proxy::{TcpHandler, TcpProxy};
use crate::ip_proxy::udp_proxy::{UdpHandler, UdpProxy};
use crate::protocol;
use crate::protocol::{NetPacket, Version, MAX_TTL};

#[cfg(not(target_os = "android"))]
pub mod icmp_proxy;
pub mod tcp_proxy;
pub mod udp_proxy;

pub trait DashMapNew {
    fn new0() -> Self;
    fn new_cap(capacity: usize) -> Self;
}

pub trait ProxyHandler {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool>;
    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()>;
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
    #[cfg(not(target_os = "android"))]
    pub(crate) icmp_handler: IcmpHandler,
    pub(crate) tcp_handler: TcpHandler,
    pub(crate) udp_handler: UdpHandler,
}

#[cfg(not(target_os = "android"))]
pub async fn init_proxy(
    sender: ChannelSender,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
) -> io::Result<(TcpProxy, UdpProxy, IpProxyMap)> {
    let tcp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>> = Arc::new(DashMap::new0());
    let udp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>> = Arc::new(DashMap::new0());

    let icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>> = Arc::new(DashMap::new0());
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let tcp_proxy = TcpProxy::new(addr, tcp_proxy_map.clone()).await?;
    let tcp_handler = tcp_proxy.tcp_handler();
    let udp_proxy = UdpProxy::new(udp_socket, udp_proxy_map.clone())?;
    let udp_handler = udp_proxy.udp_handler();

    let icmp_handler = {
        let icmp_proxy = icmp_proxy::IcmpProxy::new(
            addr,
            icmp_proxy_map.clone(),
            sender.clone(),
            current_device.clone(),
            client_cipher.clone(),
        )?;
        let icmp_handler = icmp_proxy.icmp_handler();
        thread::spawn(move || {
            icmp_proxy.start();
        });
        icmp_handler
    };

    Ok((
        tcp_proxy,
        udp_proxy,
        IpProxyMap {
            tcp_handler,
            udp_handler,
            icmp_handler,
        },
    ))
}

#[cfg(target_os = "android")]
pub async fn init_proxy() -> io::Result<(TcpProxy, UdpProxy, IpProxyMap)> {
    let tcp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>> = Arc::new(DashMap::new0());
    let udp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>> = Arc::new(DashMap::new0());
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let tcp_proxy = TcpProxy::new(addr, tcp_proxy_map.clone()).await?;
    let tcp_handler = tcp_proxy.tcp_handler();
    let udp_proxy = UdpProxy::new(udp_socket, udp_proxy_map.clone())?;
    let udp_handler = udp_proxy.udp_handler();

    Ok((
        tcp_proxy,
        udp_proxy,
        IpProxyMap {
            tcp_handler,
            udp_handler,
        },
    ))
}

pub fn send(
    buf: &mut [u8],
    data_len: usize,
    dest_ip: Ipv4Addr,
    sender: &ChannelSender,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    client_cipher: &Cipher,
) {
    let current_device = current_device.load();
    let virtual_ip = current_device.virtual_ip();

    let mut net_packet = NetPacket::new0(12 + data_len, buf).unwrap();
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(protocol::Protocol::IpTurn);
    net_packet.set_transport_protocol(protocol::ip_turn_packet::Protocol::Ipv4.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_source(virtual_ip);
    net_packet.set_destination(dest_ip);
    if let Err(e) = client_cipher.encrypt_ipv4(&mut net_packet) {
        log::warn!("加密失败:{}", e);
        return;
    }
    if sender
        .try_send_by_id(net_packet.buffer(), &dest_ip)
        .is_err()
    {
        let connect_server = current_device.connect_server;
        if let Err(e) = sender.send_main(net_packet.buffer(), connect_server) {
            log::warn!("发送到目标失败:{},{}", e, connect_server);
        }
    }
}

impl ProxyHandler for IpProxyMap {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        match ipv4.protocol() {
            ipv4::protocol::Protocol::Tcp => {
                self.tcp_handler.recv_handle(ipv4, source, destination)
            }
            ipv4::protocol::Protocol::Udp => {
                self.udp_handler.recv_handle(ipv4, source, destination)
            }
            #[cfg(not(target_os = "android"))]
            ipv4::protocol::Protocol::Icmp => {
                self.icmp_handler.recv_handle(ipv4, source, destination)
            }
            _ => {
                log::warn!(
                    "不支持的ip代理ipv4协议{:?}:{}->{}->{}",
                    ipv4.protocol(),
                    source,
                    destination,
                    ipv4.destination_ip()
                );
                Ok(false)
            }
        }
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        match ipv4.protocol() {
            ipv4::protocol::Protocol::Tcp => self.tcp_handler.send_handle(ipv4),
            ipv4::protocol::Protocol::Udp => self.udp_handler.send_handle(ipv4),
            _ => Ok(()),
        }
    }
}
