use std::io;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Sub;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::channel::punch::{NatInfo, NatType};
use crate::proto::message::PunchNatType;

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
        Ok(ipv6) => Some(ipv6),
        Err(e) => {
            log::warn!("获取ipv6失败：{:?}", e);
            None
        }
    }
}

#[derive(Clone)]
pub struct NatTest {
    stun_server: Vec<String>,
    info: Arc<Mutex<NatInfo>>,
    time: Arc<AtomicCell<Instant>>,
}

impl From<NatType> for PunchNatType {
    fn from(value: NatType) -> Self {
        match value {
            NatType::Symmetric => PunchNatType::Symmetric,
            NatType::Cone => PunchNatType::Cone,
        }
    }
}

impl Into<NatType> for PunchNatType {
    fn into(self) -> NatType {
        match self {
            PunchNatType::Symmetric => NatType::Symmetric,
            PunchNatType::Cone => NatType::Cone,
        }
    }
}

impl NatTest {
    pub fn new(
        _channel_num: usize,
        mut stun_server: Vec<String>,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        udp_ports: Vec<u16>,
        tcp_port: u16,
    ) -> NatTest {
        let server = stun_server[0].clone();
        stun_server.resize(3, server);
        let ports = vec![0; udp_ports.len()];
        let nat_info = NatInfo::new(
            Vec::new(),
            ports,
            0,
            local_ipv4,
            ipv6,
            udp_ports,
            tcp_port,
            NatType::Cone,
        );
        let info = Arc::new(Mutex::new(nat_info));
        NatTest {
            stun_server,
            info,
            time: Arc::new(AtomicCell::new(
                Instant::now().sub(Duration::from_secs(100)),
            )),
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
    pub fn update_addr(&self, index: usize, ip: Ipv4Addr, port: u16) {
        let mut guard = self.info.lock();
        guard.update_addr(index, ip, port)
    }
    pub fn re_test(
        &self,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> io::Result<NatInfo> {
        let (nat_type, public_ips, port_range) = stun::stun_test_nat(self.stun_server.clone())?;
        let mut guard = self.info.lock();
        guard.nat_type = nat_type;
        guard.public_ips = public_ips;
        guard.public_port_range = port_range;
        guard.local_ipv4 = local_ipv4;
        guard.ipv6 = ipv6;

        Ok(guard.clone())
    }
}
