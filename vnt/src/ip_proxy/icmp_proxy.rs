use anyhow::Context;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use packet::icmp::icmp;
use packet::icmp::icmp::HeaderOther;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::channel::context::ChannelContext;
use crate::channel::socket::{LocalInterface, VntSocketTrait};
use crate::cipher::Cipher;
use crate::handle::CurrentDeviceInfo;
use crate::ip_proxy::ProxyHandler;
use crate::protocol;
use crate::protocol::{NetPacket, MAX_TTL};
#[derive(Clone)]
pub struct IcmpProxy {
    icmp_socket: Arc<std::net::UdpSocket>,
    // 对端-> 真实来源
    nat_map: Arc<Mutex<HashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>>,
}

impl IcmpProxy {
    pub async fn new(
        context: ChannelContext,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        client_cipher: Cipher,
        default_interface: &LocalInterface,
    ) -> anyhow::Result<Self> {
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let icmp_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )
        .context("new Socket RAW ICMPV4 failed")?;
        #[cfg(target_os = "android")]
        let icmp_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::ICMPV4),
        )
        .context("new Socket DGRAM ICMPV4 failed")?;
        let addr: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        icmp_socket
            .bind(&socket2::SockAddr::from(addr))
            .context("bind Socket ICMPV4 failed")?;
        icmp_socket.set_nonblocking(true)?;
        if let Err(e) = icmp_socket.set_ip_unicast_if(default_interface) {
            log::warn!("set_ip_unicast_if {:?}", e)
        }
        let std_socket: std::net::UdpSocket = icmp_socket.into();

        let tokio_icmp_socket = UdpSocket::from_std(std_socket.try_clone()?)?;
        let nat_map: Arc<Mutex<HashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(16)));
        {
            let nat_map = nat_map.clone();
            tokio::spawn(async {
                if let Err(e) = icmp_proxy(
                    tokio_icmp_socket,
                    nat_map,
                    context,
                    current_device,
                    client_cipher,
                )
                .await
                {
                    log::warn!("icmp_proxy:{:?}", e);
                }
            });
        }
        Ok(Self {
            icmp_socket: Arc::new(std_socket),
            nat_map,
        })
    }
}

async fn icmp_proxy(
    icmp_socket: UdpSocket,
    // 对端-> 真实来源
    nat_map: Arc<Mutex<HashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>>,
    context: ChannelContext,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
) -> io::Result<()> {
    let mut buf = [0u8; 65535 - 20 - 8];
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    let start = 12;
    #[cfg(target_os = "android")]
    let start = 12 + 20;
    loop {
        let (len, addr) = icmp_socket.recv_from(&mut buf[start..]).await?;
        if let IpAddr::V4(peer_ip) = addr.ip() {
            #[cfg(target_os = "android")]
            {
                let buf = &mut buf[12..];
                // ipv4 头部20字节
                buf[0] = 0b0100_0110;
                //写入总长度
                buf[2..4].copy_from_slice(&((20 + len) as u16).to_be_bytes());

                let mut ipv4 = IpV4Packet::unchecked(buf);
                ipv4.set_flags(2);
                ipv4.set_ttl(1);
                ipv4.set_protocol(packet::ip::ipv4::protocol::Protocol::Icmp);
                ipv4.set_source_ip(peer_ip);
            }
            recv_handle(
                &mut buf,
                start + len,
                peer_ip,
                &nat_map,
                &context,
                &current_device,
                &client_cipher,
            );
        }
    }
}

fn recv_handle(
    buf: &mut [u8],
    data_len: usize,
    peer_ip: Ipv4Addr,
    nat_map: &Mutex<HashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
    context: &ChannelContext,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    client_cipher: &Cipher,
) {
    match IpV4Packet::new(&mut buf[12..data_len]) {
        Ok(mut ipv4_packet) => match icmp::IcmpPacket::new(ipv4_packet.payload()) {
            Ok(icmp_packet) => match icmp_packet.header_other() {
                HeaderOther::Identifier(id, seq) => {
                    if let Some(dest_ip) = nat_map.lock().get(&(peer_ip, id, seq)).cloned() {
                        ipv4_packet.set_destination_ip(dest_ip);
                        ipv4_packet.update_checksum();

                        let current_device = current_device.load();
                        let virtual_ip = current_device.virtual_ip();

                        let mut net_packet = NetPacket::new0(data_len, buf).unwrap();
                        net_packet.set_default_version();
                        net_packet.set_protocol(protocol::Protocol::IpTurn);
                        net_packet.set_transport_protocol(
                            protocol::ip_turn_packet::Protocol::Ipv4.into(),
                        );
                        net_packet.first_set_ttl(MAX_TTL);
                        net_packet.set_source(virtual_ip);
                        net_packet.set_destination(dest_ip);
                        if let Err(e) = client_cipher.encrypt_ipv4(&mut net_packet) {
                            log::warn!("加密失败:{}", e);
                            return;
                        }
                        if let Err(e) = context.send_ipv4_by_id(
                            &net_packet,
                            &dest_ip,
                            current_device.connect_server,
                            current_device.status.online(),
                        ) {
                            log::warn!("发送到目标失败:{}", e);
                        }
                    }
                }
                h => {
                    log::debug!("不支持的icmp代理 {:?},{:?}", peer_ip, h)
                }
            },
            Err(e) => {
                log::warn!("icmp {:?}", e)
            }
        },
        Err(e) => {
            log::warn!("icmp {:?}", e)
        }
    }
}

/// icmp用Identifier来区分，没有Identifier的一律不转发
impl ProxyHandler for IcmpProxy {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        if ipv4.offset() != 0 || ipv4.flags() & 1 == 1 {
            // ip分片的直接丢弃
            return Ok(true);
        }
        let dest_ip = ipv4.destination_ip();
        //转发到代理目标地址
        let icmp_packet = icmp::IcmpPacket::new(ipv4.payload())?;
        match icmp_packet.header_other() {
            HeaderOther::Identifier(id, seq) => {
                self.nat_map.lock().insert((dest_ip, id, seq), source);
                self.icmp_socket.send_to(
                    ipv4.payload(),
                    SocketAddr::from(SocketAddrV4::new(dest_ip, 0)),
                )?;
            }
            header_other => {
                log::warn!(
                    "不支持的ip代理Icmp协议:{}->{}->{},{:?}",
                    source,
                    destination,
                    dest_ip,
                    header_other
                );
            }
        }
        Ok(true)
    }

    fn send_handle(&self, _ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        Ok(())
    }
}
