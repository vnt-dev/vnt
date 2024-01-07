use std::io;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::channel::punch::{NatInfo, NatType};
use crate::proto::message::PunchNatType;

mod stun_test;

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
        mut stun_server: Vec<String>,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        udp_port: u16,
        tcp_port: u16,
    ) -> NatTest {
        let server = stun_server[0].clone();
        stun_server.resize(3, server);
        let nat_info = NatInfo::new(
            vec![public_ip],
            public_port,
            0,
            local_ipv4,
            ipv6,
            udp_port,
            tcp_port,
            NatType::Cone,
        );
        let info = Arc::new(Mutex::new(nat_info));
        NatTest {
            stun_server,
            info,
            time: Arc::new(AtomicCell::new(Instant::now())),
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
    pub fn update_addr(&self, ip: Ipv4Addr, port: u16) {
        let mut guard = self.info.lock();
        guard.update_addr(ip, port)
    }
    pub async fn re_test(
        &self,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        udp_port: u16,
        tcp_port: u16,
    ) -> NatInfo {
        let info = NatTest::re_test_(
            &self.stun_server,
            public_ip,
            public_port,
            local_ipv4,
            ipv6,
            udp_port,
            tcp_port,
        )
        .await;
        log::info!("探测nat类型={:?}", info);
        *self.info.lock() = info.clone();
        info
    }
    async fn re_test_(
        stun_server: &Vec<String>,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        udp_port: u16,
        tcp_port: u16,
    ) -> NatInfo {
        return match stun_test::stun_test_nat(stun_server.clone()).await {
            Ok((nat_type, mut public_ips, port_range)) => {
                if !public_ips.contains(&public_ip) {
                    public_ips.push(public_ip)
                }
                NatInfo::new(
                    public_ips,
                    public_port,
                    port_range,
                    local_ipv4,
                    ipv6,
                    udp_port,
                    tcp_port,
                    nat_type,
                )
            }
            Err(e) => {
                log::warn!("{:?}", e);
                NatInfo::new(
                    vec![public_ip],
                    public_port,
                    0,
                    local_ipv4,
                    ipv6,
                    udp_port,
                    tcp_port,
                    NatType::Cone,
                )
            }
        };
    }
}
