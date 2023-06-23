use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use crossbeam::atomic::AtomicCell;

use crossbeam_skiplist::SkipMap;
use socket2::{Domain, SockAddr, Socket, Type};

use packet::icmp::icmp;
use packet::icmp::icmp::HeaderOther;
use packet::ip::ipv4;
use crate::channel::sender::ChannelSender;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::{MAX_TTL, NetPacket, Protocol, Version};

pub struct IcmpProxy {
    icmp_socket: Arc<Socket>,
    // 对端-> 真实来源
    icmp_proxy_map: Arc<SkipMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
    sender: ChannelSender,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
}

impl IcmpProxy {
    pub fn new(addr: SocketAddrV4, icmp_proxy_map: Arc<SkipMap<(Ipv4Addr, u16, u16), Ipv4Addr>>, sender: ChannelSender, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) -> io::Result<IcmpProxy> {
        let icmp_socket = Arc::new(Socket::new(Domain::IPV4, Type::RAW, Some(socket2::Protocol::ICMPV4))?);
        icmp_socket.bind(&SockAddr::from(addr))?;
        // // 设置 SIO_RCVALL 参数
        // #[cfg(windows)]
        // {
        //     use std::os::windows::io::AsRawSocket;
        //     let raw_fd = icmp_socket.as_raw_socket();
        //     let mut rcvall: winapi::shared::minwindef::DWORD = 1;
        //     let mut bytes_returned: winapi::shared::minwindef::DWORD = 0;
        //     let result = unsafe {
        //         winapi::um::winsock2::WSAIoctl(
        //             raw_fd as _,
        //             winapi::shared::mstcpip::SIO_RCVALL,
        //             &mut rcvall as *mut winapi::shared::minwindef::DWORD as *mut std::ffi::c_void,
        //             std::mem::size_of::<winapi::shared::minwindef::DWORD>() as winapi::shared::minwindef::DWORD,
        //             std::ptr::null_mut(),
        //             0,
        //             &mut bytes_returned as winapi::shared::minwindef::LPDWORD,
        //             std::ptr::null_mut(),
        //             None,
        //         )
        //     };
        //     if result != 0 {
        //         return Err(io::Error::from_raw_os_error(unsafe { winapi::um::winsock2::WSAGetLastError() }));
        //     }
        // }
        Ok(IcmpProxy {
            icmp_socket,
            icmp_proxy_map,
            sender,
            current_device,
        })
    }
    pub fn icmp_socket(&self) ->Arc<Socket>{
        self.icmp_socket.clone()
    }
    pub fn start(self) {
        let mut buf = [0 as u8; 1500];
        let data: &mut [MaybeUninit<u8>] =
            unsafe { std::mem::transmute(&mut buf[..]) };
        let mut net_packet = NetPacket::new([0u8; 4 + 8 + 1500]).unwrap();
        net_packet.set_version(Version::V1);
        net_packet.set_protocol(Protocol::IpTurn);
        net_packet.set_transport_protocol(ipv4::protocol::Protocol::Ipv4.into());
        net_packet.set_ttl(MAX_TTL);
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
                                                        ipv4_packet.set_destination_ip(dest_ip);
                                                        ipv4_packet.update_checksum();
                                                        let virtual_ip = self.current_device.load().virtual_ip();
                                                        net_packet.set_source(virtual_ip);
                                                        net_packet.set_destination(dest_ip);
                                                        let data_len = ipv4_packet.buffer.len();
                                                        net_packet.set_payload(ipv4_packet.buffer);
                                                        let _ = self.sender.try_send_by_id(&net_packet.buffer()[..(12 + data_len)], &dest_ip);
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