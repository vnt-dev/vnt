use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use parking_lot::Mutex;

use packet::icmp::icmp;
use packet::icmp::icmp::HeaderOther;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::channel::context::Context;
use crate::cipher::Cipher;
use crate::handle::CurrentDeviceInfo;
use crate::ip_proxy::ProxyHandler;
use crate::protocol;
use crate::protocol::{NetPacket, Version, MAX_TTL};
use crate::util::StopManager;
#[derive(Clone)]
pub struct IcmpProxy {
    icmp_socket: Arc<std::net::UdpSocket>,
    // 对端-> 真实来源
    nat_map: Arc<Mutex<HashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>>,
}

impl IcmpProxy {
    pub fn new(
        context: Context,
        stop_manager: StopManager,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        client_cipher: Cipher,
    ) -> io::Result<Self> {
        let icmp_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        let addr: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        icmp_socket.bind(&socket2::SockAddr::from(addr))?;
        icmp_socket.set_nonblocking(true)?;
        let std_socket: std::net::UdpSocket = icmp_socket.into();
        let mio_icmp_socket = UdpSocket::from_std(std_socket.try_clone()?);
        let nat_map: Arc<Mutex<HashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(16)));
        {
            let nat_map = nat_map.clone();
            thread::spawn(move || {
                if let Err(e) = icmp_proxy(
                    mio_icmp_socket,
                    nat_map,
                    context,
                    stop_manager,
                    current_device,
                    client_cipher,
                ) {
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

const SERVER_VAL: usize = 0;
const SERVER: Token = Token(SERVER_VAL);
const NOTIFY_VAL: usize = 1;
const NOTIFY: Token = Token(NOTIFY_VAL);

fn icmp_proxy(
    mut icmp_socket: UdpSocket,
    // 对端-> 真实来源
    nat_map: Arc<Mutex<HashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>>,
    context: Context,
    stop_manager: StopManager,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
) -> io::Result<()> {
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut icmp_socket, SERVER, Interest::READABLE)?;
    let mut events = Events::with_capacity(32);
    let stop = Waker::new(poll.registry(), NOTIFY)?;
    let _worker = stop_manager.add_listener("icmp_proxy".into(), move || {
        if let Err(e) = stop.wake() {
            log::warn!("stop icmp_proxy:{:?}", e);
        }
    })?;
    let mut buf = [0u8; 65535 - 20 - 8];
    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                SERVER => loop {
                    let (len, addr) = match icmp_socket.recv_from(&mut buf[12..]) {
                        Ok(rs) => rs,
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                break;
                            }
                            log::warn!("icmp_socket {:?}", e);
                            break;
                        }
                    };
                    if let IpAddr::V4(peer_ip) = addr.ip() {
                        recv_handle(
                            &mut buf,
                            12 + len,
                            peer_ip,
                            &nat_map,
                            &context,
                            &current_device,
                            &client_cipher,
                        );
                    }
                },
                NOTIFY => {
                    return Ok(());
                }
                _ => {}
            }
        }
    }
}

fn recv_handle(
    buf: &mut [u8],
    data_len: usize,
    peer_ip: Ipv4Addr,
    nat_map: &Mutex<HashMap<(Ipv4Addr, u16, u16), Ipv4Addr>>,
    context: &Context,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    client_cipher: &Cipher,
) {
    match IpV4Packet::new(&mut buf[12..data_len]) {
        Ok(mut ipv4_packet) => match icmp::IcmpPacket::new(ipv4_packet.payload()) {
            Ok(icmp_packet) => match icmp_packet.header_other() {
                HeaderOther::Identifier(id, seq) => {
                    if let Some(dest_ip) = nat_map.lock().remove(&(peer_ip, id, seq)) {
                        ipv4_packet.set_destination_ip(dest_ip);
                        ipv4_packet.update_checksum();

                        let current_device = current_device.load();
                        let virtual_ip = current_device.virtual_ip();

                        let mut net_packet = NetPacket::new0(data_len, buf).unwrap();
                        net_packet.set_version(Version::V1);
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
                        if context.send_by_id(net_packet.buffer(), &dest_ip).is_err() {
                            let connect_server = current_device.connect_server;
                            if let Err(e) =
                                context.send_default(net_packet.buffer(), connect_server)
                            {
                                log::warn!("发送到目标失败:{},{}", e, connect_server);
                            }
                        }
                    }
                }
                _ => {}
            },
            Err(_) => {}
        },
        Err(_) => {}
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
