use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;
use socket2::{Domain, SockAddr, Socket, Type};

use packet::icmp::icmp;
use packet::icmp::icmp::HeaderOther;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::handle::CurrentDeviceInfo;
use crate::ip_proxy::{send, ProxyHandler};

pub struct IcmpProxy {
    icmp_socket: Arc<Socket>,
    // 对端-> 真实来源
    icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
    sender: ChannelSender,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
}

impl IcmpProxy {
    pub fn new(
        addr: SocketAddrV4,
        icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
        sender: ChannelSender,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        client_cipher: Cipher,
    ) -> io::Result<IcmpProxy> {
        let icmp_socket = Arc::new(Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?);
        icmp_socket.bind(&SockAddr::from(addr))?;
        Ok(IcmpProxy {
            icmp_socket,
            icmp_proxy_map,
            sender,
            current_device,
            client_cipher,
        })
    }
    pub fn icmp_handler(&self) -> IcmpHandler {
        IcmpHandler(self.icmp_socket.clone(), self.icmp_proxy_map.clone())
    }
    pub fn start(self) {
        let mut buf = [0u8; 4096];
        let data: &mut [MaybeUninit<u8>] = unsafe { std::mem::transmute(&mut buf[12..]) };

        loop {
            match self.recv(data) {
                Ok((len, peer_ip)) => {
                    match peer_ip {
                        IpAddr::V4(peer_ip) => {
                            match IpV4Packet::new(&mut buf[12..12 + len]) {
                                Ok(mut ipv4_packet) => {
                                    match icmp::IcmpPacket::new(ipv4_packet.payload()) {
                                        Ok(icmp_packet) => {
                                            match icmp_packet.header_other() {
                                                HeaderOther::Identifier(id, seq) => {
                                                    if let Some(entry) =
                                                        self.icmp_proxy_map.get(&(peer_ip, id, seq))
                                                    {
                                                        //将数据发送到真实的来源
                                                        let dest_ip = *entry.value();
                                                        drop(entry);
                                                        ipv4_packet.set_destination_ip(dest_ip);
                                                        ipv4_packet.update_checksum();
                                                        send(
                                                            &mut buf,
                                                            len,
                                                            dest_ip,
                                                            &self.sender,
                                                            &self.current_device,
                                                            &self.client_cipher,
                                                        );
                                                    }
                                                }
                                                _ => {
                                                    continue;
                                                }
                                            }
                                        }
                                        Err(_) => {}
                                    };
                                }
                                Err(_) => {}
                            }
                        }
                        IpAddr::V6(_) => {}
                    }
                }
                Err(e) => {
                    log::warn!("icmp代理异常:{:?}", e);
                }
            }
        }
    }
    fn recv(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<(usize, IpAddr)> {
        let (size, addr) = self.icmp_socket.recv_from(buf)?;
        let addr = match addr.as_socket() {
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Some(add) => add.ip(),
        };
        Ok((size, addr))
    }
}
/// icmp用Identifier来区分，没有Identifier的一律不转发
#[derive(Clone)]
pub struct IcmpHandler(Arc<Socket>, Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>);

impl ProxyHandler for IcmpHandler {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        let dest_ip = ipv4.destination_ip();
        //转发到代理目标地址
        let icmp_packet = icmp::IcmpPacket::new(ipv4.payload())?;
        match icmp_packet.header_other() {
            HeaderOther::Identifier(id, seq) => {
                self.1.insert((dest_ip, id, seq), source);
                self.0.send_to(
                    ipv4.payload(),
                    &SockAddr::from(SocketAddrV4::new(dest_ip, 0)),
                )?;
            }
            _ => {
                log::warn!(
                    "不支持的ip代理Icmp协议:{}->{}->{}",
                    source,
                    destination,
                    dest_ip
                );
            }
        }
        Ok(true)
    }

    fn send_handle(&self, _ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        Ok(())
    }
}
