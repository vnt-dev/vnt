use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;

use socket2::{Domain, SockAddr, Socket, Type};

use packet::icmp::icmp;
use packet::icmp::icmp::HeaderOther;
use packet::ip::ipv4;
use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::{MAX_TTL, NetPacket, Protocol, Version};
use crate::protocol::body::ENCRYPTION_RESERVED;

pub struct IcmpProxy {
    icmp_socket: Arc<Socket>,
    // 对端-> 真实来源
    icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
    sender: ChannelSender,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
}

impl IcmpProxy {
    pub fn new(addr: SocketAddrV4, icmp_proxy_map: Arc<DashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
               sender: ChannelSender, current_device: Arc<AtomicCell<CurrentDeviceInfo>>, client_cipher: Cipher) -> io::Result<IcmpProxy> {
        let icmp_socket = Arc::new(Socket::new(Domain::IPV4, Type::RAW, Some(socket2::Protocol::ICMPV4))?);
        icmp_socket.bind(&SockAddr::from(addr))?;
        Ok(IcmpProxy {
            icmp_socket,
            icmp_proxy_map,
            sender,
            current_device,
            client_cipher,
        })
    }
    pub fn icmp_socket(&self) -> Arc<Socket> {
        self.icmp_socket.clone()
    }
    pub fn start(self) {
        let mut buf = [0 as u8; 1500];
        let data: &mut [MaybeUninit<u8>] =
            unsafe { std::mem::transmute(&mut buf[..]) };

        loop {
            match self.recv(data) {
                Ok((len, peer_ip)) => {
                    match peer_ip {
                        IpAddr::V4(peer_ip) => {
                            match ipv4::packet::IpV4Packet::new(&mut buf[..len]) {
                                Ok(mut ipv4_packet) => {
                                    match icmp::IcmpPacket::new(ipv4_packet.payload()) {
                                        Ok(icmp_packet) => {
                                            match icmp_packet.header_other() {
                                                HeaderOther::Identifier(id, seq) => {
                                                    if let Some(entry) = self.icmp_proxy_map.get(&(peer_ip, id, seq)) {
                                                        //将数据发送到真实的来源
                                                        let dest_ip = *entry.value();
                                                        drop(entry);
                                                        ipv4_packet.set_destination_ip(dest_ip);
                                                        ipv4_packet.update_checksum();
                                                        let current_device = self.current_device.load();
                                                        let virtual_ip = current_device.virtual_ip();
                                                        let connect_server = current_device.connect_server;
                                                        let mut net_packet = NetPacket::new_encrypt(vec![0u8; 12 + len + ENCRYPTION_RESERVED]).unwrap();
                                                        net_packet.set_version(Version::V1);
                                                        net_packet.set_protocol(Protocol::IpTurn);
                                                        net_packet.set_transport_protocol(crate::protocol::ip_turn_packet::Protocol::Ipv4.into());
                                                        net_packet.first_set_ttl(MAX_TTL);
                                                        net_packet.set_source(virtual_ip);
                                                        net_packet.set_destination(dest_ip);
                                                        net_packet.set_payload(ipv4_packet.buffer).unwrap();
                                                        if let Err(e) = self.client_cipher.encrypt_ipv4(&mut net_packet) {
                                                            log::warn!("加密失败:{}",e);
                                                            continue;
                                                        }
                                                        if self.sender.try_send_by_id(net_packet.buffer(), &dest_ip).is_err() {
                                                            let _ = self.sender.try_send_main(net_packet.buffer(), connect_server);
                                                        }
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
                    log::warn!("icmp代理异常:{:?}",e);
                }
            }
        }
    }
    fn recv(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<(usize, IpAddr)> {
        let (size, addr) = self.icmp_socket.recv_from(buf)?;
        let addr = match addr.as_socket() {
            None => {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
            Some(add) => {
                add.ip()
            }
        };
        Ok((size, addr))
    }
    // fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<usize> {
    //     self.icmp_socket.send_to(buf, &SockAddr::from(addr))
    // }
}