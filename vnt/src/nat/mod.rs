use std::io;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::channel::punch::{NatInfo, NatType};
use crate::proto::message::PunchNatType;

mod stun_test;

pub fn local_ipv4() -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

pub fn local_ipv6() -> io::Result<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0")?;
    socket.connect("[2001:4860:4860::8888]:80")?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(_) => Ok(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(ip) => Ok(ip),
    }
}

pub fn local_ipv4_addr(port: u16) -> SocketAddrV4 {
    match local_ipv4() {
        Ok(ipv4) => SocketAddrV4::new(ipv4, port),
        Err(e) => {
            log::warn!("获取本地ipv4地址失败:{}", e);
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
        }
    }
}

pub fn local_ipv6_addr(port: u16) -> SocketAddrV6 {
    match local_ipv6() {
        Ok(ipv6) => SocketAddrV6::new(ipv6, port, 0, 0),
        Err(e) => {
            log::warn!("获取本地ipv6地址失败:{}", e);
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)
        }
    }
}

#[derive(Clone)]
pub struct NatTest {
    stun_server: Vec<String>,
    info: Arc<Mutex<NatInfo>>,
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
        local_ipv4_addr: SocketAddrV4,
        ipv6_addr: SocketAddrV6,
    ) -> NatTest {
        let server = stun_server[0].clone();
        stun_server.resize(3, server);
        let nat_info = NatInfo::new(
            vec![public_ip],
            public_port,
            0,
            local_ipv4_addr,
            ipv6_addr,
            NatType::Cone,
        );
        let info = Arc::new(Mutex::new(nat_info));
        NatTest { stun_server, info }
    }
    pub fn nat_info(&self) -> NatInfo {
        self.info.lock().clone()
    }
    pub fn update_addr(&self, ip: Ipv4Addr, port: u16) {
        if !ip.is_multicast()
            && !ip.is_broadcast()
            && !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_private()
            && port != 0
        {
            let mut guard = self.info.lock();
            guard.public_port = port;
            if !guard.public_ips.contains(&ip) {
                guard.public_ips.push(ip);
            }
        }
    }
    pub async fn re_test(
        &self,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ipv4_addr: SocketAddrV4,
        ipv6_addr: SocketAddrV6,
    ) -> NatInfo {
        let info = NatTest::re_test_(
            &self.stun_server,
            public_ip,
            public_port,
            local_ipv4_addr,
            ipv6_addr,
        )
        .await;
        *self.info.lock() = info.clone();
        info
    }
    async fn re_test_(
        stun_server: &Vec<String>,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ipv4_addr: SocketAddrV4,
        ipv6_addr: SocketAddrV6,
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
                    local_ipv4_addr,
                    ipv6_addr,
                    nat_type,
                )
            }
            Err(e) => {
                log::warn!("{:?}", e);
                NatInfo::new(
                    vec![public_ip],
                    public_port,
                    0,
                    local_ipv4_addr,
                    ipv6_addr,
                    NatType::Cone,
                )
            }
        };
    }
}
