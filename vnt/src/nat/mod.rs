use anyhow::{anyhow, Context};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use rand::prelude::SliceRandom;
use rand::Rng;

use crate::channel::punch::{NatInfo, NatType, PunchModel};
use crate::channel::socket::LocalInterface;
#[cfg(feature = "upnp")]
use crate::util::UPnP;

mod stun;

pub fn local_ipv4_() -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

pub fn local_ipv4() -> Option<Ipv4Addr> {
    match local_ipv4_() {
        Ok(ipv4) => Some(ipv4),
        Err(e) => {
            log::warn!("获取ipv4失败：{:?}", e);
            None
        }
    }
}

pub fn local_ipv6_() -> io::Result<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0")?;
    socket.connect("[2001:4860:4860:0000:0000:0000:0000:8888]:80")?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(_) => Ok(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(ip) => Ok(ip),
    }
}

pub fn local_ipv6() -> Option<Ipv6Addr> {
    match local_ipv6_() {
        Ok(ipv6) => {
            if is_ipv6_global(&ipv6) {
                return Some(ipv6);
            }
        }
        Err(e) => {
            log::warn!("获取ipv6失败：{:?}", e);
        }
    }
    None
}

pub const fn is_ipv4_global(ipv4: &Ipv4Addr) -> bool {
    !(ipv4.octets()[0] == 0 // "This network"
        || ipv4.is_private()
        || ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0b1100_0000 == 0b0100_0000)//ipv4.is_shared()
        || ipv4.is_loopback()
        || ipv4.is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        // .9 and .10 are documented as globally reachable so they're excluded
        || (
        ipv4.octets()[0] == 192 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 0
            && ipv4.octets()[3] != 9 && ipv4.octets()[3] != 10
    )
        || ipv4.is_documentation()
        || ipv4.octets()[0] == 198 && (ipv4.octets()[1] & 0xfe) == 18//ipv4.is_benchmarking()
        || ipv4.octets()[0] & 240 == 240 && !ipv4.is_broadcast()//ipv4.is_reserved()
        || ipv4.is_broadcast())
}

pub const fn is_ipv6_global(ipv6addr: &Ipv6Addr) -> bool {
    !(ipv6addr.is_unspecified()
        || ipv6addr.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ipv6addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(ipv6addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ipv6addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ipv6addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
        && !(
        // Port Control Protocol Anycast (`2001:1::1`)
        u128::from_be_bytes(ipv6addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
            // Traversal Using Relays around NAT Anycast (`2001:1::2`)
            || u128::from_be_bytes(ipv6addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
            // AMT (`2001:3::/32`)
            || matches!(ipv6addr.segments(), [0x2001, 3, _, _, _, _, _, _])
            // AS112-v6 (`2001:4:112::/48`)
            || matches!(ipv6addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
            // ORCHIDv2 (`2001:20::/28`)
            || matches!(ipv6addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
    ))
        || (ipv6addr.segments()[0] == 0x2001) && (ipv6addr.segments()[1] == 0xdb8)//ipv6addr.is_documentation()
        || (ipv6addr.segments()[0] & 0xfe00) == 0xfc00//ipv6addr.is_unique_local()
        || (ipv6addr.segments()[0] & 0xffc0) == 0xfe80) //ipv6addr.is_unicast_link_local())
}

#[derive(Clone)]
pub struct NatTest {
    stun_server: Vec<String>,
    info: Arc<Mutex<NatInfo>>,
    time: Arc<AtomicCell<Instant>>,
    udp_ports: Vec<u16>,
    tcp_port: u16,
    #[cfg(feature = "upnp")]
    upnp: UPnP,
    pub(crate) update_local_ipv4: bool,
}

impl NatTest {
    pub fn new(
        _channel_num: usize,
        stun_server: Vec<String>,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        udp_ports: Vec<u16>,
        tcp_port: u16,
        update_local_ipv4: bool,
        punch_model: PunchModel,
    ) -> NatTest {
        let ports = vec![0; udp_ports.len()];
        let nat_info = NatInfo::new(
            Vec::new(),
            ports,
            0,
            local_ipv4,
            ipv6,
            udp_ports.clone(),
            tcp_port,
            0,
            NatType::Cone,
            punch_model,
        );
        let info = Arc::new(Mutex::new(nat_info));
        #[cfg(feature = "upnp")]
        let upnp = UPnP::default();
        #[cfg(feature = "upnp")]
        for port in &udp_ports {
            upnp.add_udp_port(*port);
        }
        #[cfg(feature = "upnp")]
        upnp.add_tcp_port(tcp_port);
        let instant = Instant::now();
        NatTest {
            stun_server,
            info,
            time: Arc::new(AtomicCell::new(
                instant
                    .checked_sub(Duration::from_secs(100))
                    .unwrap_or(instant),
            )),
            udp_ports,
            tcp_port,
            #[cfg(feature = "upnp")]
            upnp,
            update_local_ipv4,
        }
    }
    pub fn can_update(&self) -> bool {
        let last = self.time.load();
        last.elapsed() > Duration::from_secs(10)
            && self.time.compare_exchange(last, Instant::now()).is_ok()
    }

    pub fn nat_info(&self) -> NatInfo {
        self.info.lock().clone()
    }
    pub fn is_local_udp(&self, ipv4: Ipv4Addr, port: u16) -> bool {
        for x in &self.udp_ports {
            if x == &port {
                let guard = self.info.lock();
                if let Some(ip) = guard.local_ipv4 {
                    if ipv4 == ip {
                        return true;
                    }
                }
                break;
            }
        }
        false
    }
    pub fn is_local_tcp(&self, ipv4: Ipv4Addr, port: u16) -> bool {
        if self.tcp_port == port {
            let guard = self.info.lock();
            if let Some(ip) = guard.local_ipv4 {
                if ipv4 == ip {
                    return true;
                }
            }
        }
        false
    }
    pub fn is_local_address(&self, is_tcp: bool, addr: SocketAddr) -> bool {
        let port = addr.port();
        let check_ip = || {
            let guard = self.info.lock();
            match addr.ip() {
                IpAddr::V4(ipv4) => {
                    if let Some(ip) = guard.local_ipv4 {
                        if ipv4 == ip {
                            return true;
                        }
                    }
                }
                IpAddr::V6(ipv6) => {
                    if let Some(ip) = guard.ipv6 {
                        if ipv6 == ip {
                            return true;
                        }
                    }
                }
            }
            false
        };
        if is_tcp {
            if self.tcp_port == port {
                return check_ip();
            }
        } else {
            for x in &self.udp_ports {
                if x == &port {
                    return check_ip();
                }
            }
        }
        false
    }
    pub fn update_addr(&self, index: usize, ip: Ipv4Addr, port: u16) -> bool {
        let mut guard = self.info.lock();
        guard.update_addr(index, ip, port)
    }
    pub fn update_tcp_port(&self, port: u16) {
        let mut guard = self.info.lock();
        guard.update_tcp_port(port)
    }
    pub fn re_test(
        &self,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        default_interface: &LocalInterface,
    ) -> anyhow::Result<NatInfo> {
        let mut stun_server = self.stun_server.clone();
        if stun_server.len() > 5 {
            stun_server.shuffle(&mut rand::thread_rng());
            stun_server.truncate(5);
            log::info!("stun_server truncate {:?}", stun_server);
        }
        let (nat_type, public_ips, port_range) =
            stun::stun_test_nat(stun_server, default_interface)?;
        if public_ips.is_empty() {
            Err(anyhow!("public_ips.is_empty"))?
        }
        let mut guard = self.info.lock();
        guard.nat_type = nat_type;
        guard.public_ips = public_ips;
        guard.public_port_range = port_range;
        if local_ipv4.is_some() {
            guard.local_ipv4 = local_ipv4;
        }
        guard.ipv6 = ipv6;

        Ok(guard.clone())
    }
    #[cfg(feature = "upnp")]
    pub fn reset_upnp(&self) {
        let local_ipv4 = self.info.lock().local_ipv4.clone();
        if let Some(local_ipv4) = local_ipv4 {
            self.upnp.reset(local_ipv4)
        }
    }
    pub fn send_data(&self) -> anyhow::Result<(Vec<u8>, SocketAddr)> {
        let len = self.stun_server.len();
        let stun_server = if len == 1 {
            &self.stun_server[0]
        } else {
            let index = rand::thread_rng().gen_range(0..self.stun_server.len());
            &self.stun_server[index]
        };
        let addr = stun_server
            .to_socket_addrs()?
            .next()
            .with_context(|| format!("stun error {:?}", stun_server))?;
        Ok((stun::send_stun_request(), addr))
    }
    pub fn recv_data(
        &self,
        index: usize,
        source_addr: SocketAddr,
        buf: &[u8],
    ) -> anyhow::Result<bool> {
        if buf[0] == 0x01 && buf[1] == 0x01 {
            if let Some(addr) = stun::recv_stun_response(buf) {
                if let Err(e) = self.recv_data_(index, source_addr, addr) {
                    log::warn!("{:?}", e);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn recv_data_(
        &self,
        index: usize,
        source_addr: SocketAddr,
        addr: SocketAddr,
    ) -> anyhow::Result<()> {
        if let SocketAddr::V4(addr) = addr {
            let mut check_fail = true;
            let source_ip = match source_addr.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(ip) => {
                    if let Some(ip) = ip.to_ipv4() {
                        ip
                    } else {
                        return Ok(());
                    }
                }
            };
            'a: for stun_server in &self.stun_server {
                for x in stun_server.to_socket_addrs()? {
                    if source_addr.port() == x.port() {
                        if let IpAddr::V4(ip) = x.ip() {
                            if ip == source_ip {
                                check_fail = false;
                                break 'a;
                            }
                        };
                    }
                }
            }
            if !check_fail {
                if is_ipv4_global(addr.ip()) {
                    if self.update_addr(index, *addr.ip(), addr.port()) {
                        log::info!("回应地址{:?},来源stun {:?}", addr, source_addr)
                    }
                }
            }
        }
        Ok(())
    }
}
