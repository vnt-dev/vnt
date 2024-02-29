use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{collections::HashMap, io, net::SocketAddr, rc::Rc, thread};

use mio::{net::UdpSocket, Events, Interest, Poll, Token};
use mio::{Registry, Waker};
use parking_lot::Mutex;

use packet::ip::ipv4::packet::IpV4Packet;
use packet::udp::udp::UdpPacket;

use crate::ip_proxy::ProxyHandler;
use crate::util::{Scheduler, StopManager};

const SERVER_VAL: usize = 0;
const SERVER: Token = Token(SERVER_VAL);
const NOTIFY_VAL: usize = 1;
const NOTIFY: Token = Token(NOTIFY_VAL);
// 开了ip代理后使用mstsc，mstsc会误以为在真实局域网，从而不维护udp心跳，导致断连，所以这里尽量长一点过期时间
const NAT_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const NAT_FAST_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const NAT_MAX: usize = 5_000;

#[derive(Clone)]
pub struct UdpProxy {
    port: u16,
    nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
}

impl UdpProxy {
    pub fn new(scheduler: Scheduler, stop_manager: StopManager) -> io::Result<Self> {
        let nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(16)));
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", 0).parse().unwrap())?;
        let port = udp.local_addr()?.port();
        {
            let nat_map = nat_map.clone();
            thread::spawn(move || {
                if let Err(e) = udp_proxy(udp, nat_map, scheduler, stop_manager) {
                    log::warn!("udp_proxy:{:?}", e);
                }
            });
        }
        Ok(Self { port, nat_map })
    }
}

impl ProxyHandler for UdpProxy {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        let dest_ip = ipv4.destination_ip();
        //转发到代理目标地址
        let mut udp_packet = UdpPacket::new(source, destination, ipv4.payload_mut())?;
        let source_port = udp_packet.source_port();
        let dest_port = udp_packet.destination_port();
        udp_packet.set_destination_port(self.port);
        udp_packet.update_checksum();
        ipv4.set_destination_ip(destination);
        ipv4.update_checksum();
        let key = SocketAddrV4::new(source, source_port);
        self.nat_map
            .lock()
            .insert(key.into(), SocketAddrV4::new(dest_ip, dest_port).into());
        Ok(false)
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        let src_ip = ipv4.source_ip();
        let dest_ip = ipv4.destination_ip();
        let dest_addr = {
            let udp_packet = UdpPacket::new(src_ip, dest_ip, ipv4.payload_mut())?;
            SocketAddrV4::new(dest_ip, udp_packet.destination_port())
        };
        if let Some(source_addr) = self.nat_map.lock().get(&dest_addr) {
            let source_ip = *source_addr.ip();
            let mut udp_packet = UdpPacket::new(source_ip, dest_ip, ipv4.payload_mut())?;
            udp_packet.set_source_port(source_addr.port());
            udp_packet.update_checksum();
            ipv4.set_source_ip(source_ip);
            ipv4.update_checksum();
        }
        Ok(())
    }
}

fn udp_proxy(
    mut udp: UdpSocket,
    nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
    scheduler: Scheduler,
    stop_manager: StopManager,
) -> io::Result<()> {
    let mut poll = Poll::new()?;

    poll.registry()
        .register(&mut udp, SERVER, Interest::READABLE)?;
    let mut events = Events::with_capacity(32);
    let mut buf = [0; 65536];
    let mut token_map: HashMap<Token, (Rc<UdpSocket>, SocketAddrV4, Instant)> =
        HashMap::with_capacity(64);
    let mut udp_map: HashMap<SocketAddrV4, (Rc<UdpSocket>, Instant)> = HashMap::with_capacity(64);
    let mut timeout = false;
    let waker = Arc::new(Waker::new(poll.registry(), NOTIFY)?);
    let stop = waker.clone();
    let _worker = stop_manager.add_listener("udp_proxy".into(), move || {
        if let Err(e) = stop.wake() {
            log::warn!("stop udp_proxy:{:?}", e);
        }
    })?;
    loop {
        let mut check = false;
        if token_map.is_empty() {
            poll.poll(&mut events, None)?;
        } else {
            //所有事件 50分钟超时
            if let Err(e) = poll.poll(&mut events, Some(Duration::from_secs(50 * 60))) {
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                    token_map.clear();
                    udp_map.clear();
                    continue;
                }
                return Err(e);
            }
        }
        for event in events.iter() {
            match event.token() {
                SERVER => server_handle(
                    poll.registry(),
                    &udp,
                    &nat_map,
                    &mut token_map,
                    &mut udp_map,
                    &mut buf,
                ),
                NOTIFY => {
                    if stop_manager.is_stop() {
                        return Ok(());
                    }
                    check = true;
                }
                token => {
                    if let Err(e) = readable_handle(&udp, &mut token_map, &token, &mut buf) {
                        log::error!("发送目标失败:{:?}", e);
                        if let Some((_, src_addr, _)) = token_map.remove(&token) {
                            udp_map.remove(&src_addr);
                        }
                    }
                }
            }
        }
        if check {
            //超时校验
            if token_map.len() > NAT_MAX / 2 {
                check_handle(&mut token_map, &mut udp_map, NAT_FAST_TIMEOUT)
            } else {
                check_handle(&mut token_map, &mut udp_map, NAT_TIMEOUT)
            }
            timeout = false;
        }
        if !token_map.is_empty() && !timeout {
            //注册超时监听
            timeout = true;
            let waker = waker.clone();
            scheduler.timeout(NAT_FAST_TIMEOUT, move |_| {
                let _ = waker.wake();
            });
        }
    }
}

fn check_handle(
    token_map: &mut HashMap<Token, (Rc<UdpSocket>, SocketAddrV4, Instant)>,
    udp_map: &mut HashMap<SocketAddrV4, (Rc<UdpSocket>, Instant)>,
    timeout: Duration,
) {
    let mut remove_list = Vec::new();
    for (token, (_, addr, time)) in token_map.iter() {
        if time.elapsed() > timeout {
            if let Some((_, time)) = udp_map.get(addr) {
                if time.elapsed() > timeout {
                    //映射超时，需要移除
                    remove_list.push(*token);
                }
            }
        }
    }
    for token in remove_list {
        if let Some((_, src_addr, _)) = token_map.remove(&token) {
            udp_map.remove(&src_addr);
        }
    }
}

fn server_handle(
    registry: &Registry,
    udp: &UdpSocket,
    nat_map: &Mutex<HashMap<SocketAddrV4, SocketAddrV4>>,
    token_map: &mut HashMap<Token, (Rc<UdpSocket>, SocketAddrV4, Instant)>,
    udp_map: &mut HashMap<SocketAddrV4, (Rc<UdpSocket>, Instant)>,
    buf: &mut [u8],
) {
    loop {
        let (len, src_addr) = match udp.recv_from(buf) {
            Ok((len, src_addr)) => match src_addr {
                SocketAddr::V4(addr) => (len, addr),
                SocketAddr::V6(_) => {
                    continue;
                }
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                log::error!("接收数据失败:{:?}", e);
                break;
            }
        };
        if let Some((dest_udp, time)) = udp_map.get_mut(&src_addr) {
            //发送失败就当丢包了
            let _ = dest_udp.send(&buf[..len]);
            *time = Instant::now();
        } else if let Some(dest_addr) = nat_map.lock().get(&src_addr).cloned() {
            if token_map.len() >= NAT_MAX {
                log::error!(
                    "UDP NAT_MAX:src_addr={:?},dest_addr={:?}",
                    src_addr,
                    dest_addr
                );
                continue;
            }
            match udp_connect(src_addr.port(), dest_addr.into()) {
                Ok((token_val, mut dest_udp)) => {
                    let token = Token(token_val);
                    if let Err(e) = registry.register(&mut dest_udp, token, Interest::READABLE) {
                        log::error!("register失败:{:?},addr={:?}", e, dest_addr);
                        continue;
                    }
                    if dest_udp.send(&buf[..len]).is_ok() {
                        let dest_udp = Rc::new(dest_udp);
                        token_map.insert(token, (dest_udp.clone(), src_addr, Instant::now()));
                        udp_map.insert(src_addr, (dest_udp, Instant::now()));
                    }
                }
                Err(e) => {
                    log::error!("绑定目标地址失败:{:?}", e);
                    continue;
                }
            };
        }
    }
}

/// 得到一个 fd不为SERVER_VAL或者NOTYFY_VAL的socket
fn udp_connect(src_port: u16, addr: SocketAddr) -> io::Result<(usize, UdpSocket)> {
    loop {
        let udp = if let Ok(udp) =
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, src_port).into())
        {
            udp
        } else {
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?
        };
        #[cfg(windows)]
        let fd = udp.as_raw_socket() as usize;
        #[cfg(unix)]
        let fd = udp.as_raw_fd() as usize;
        if fd == SERVER_VAL || fd == NOTIFY_VAL {
            continue;
        }
        // 只接收目标的数据
        udp.connect(addr)?;
        return Ok((fd, udp));
    }
}

fn readable_handle(
    udp: &UdpSocket,
    token_map: &mut HashMap<Token, (Rc<UdpSocket>, SocketAddrV4, Instant)>,
    token: &Token,
    buf: &mut [u8],
) -> io::Result<()> {
    if let Some((dest_udp, src_addr, time)) = token_map.get_mut(&token) {
        loop {
            let len = match dest_udp.recv(buf) {
                Ok(rs) => rs,
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(e);
                }
            };
            if len == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            let _ = udp.send_to(&buf[..len], (*src_addr).into());
        }
        *time = Instant::now();
    }
    Ok(())
}
