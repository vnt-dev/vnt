use crate::proto::message::PunchNatType;
use parking_lot::Mutex;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub mod check;

use std::net::UdpSocket;
use crate::channel::punch::{NatInfo, NatType};

pub fn local_ip() -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(ip) => {
            Ok(ip)
        }
        IpAddr::V6(_) => {
            Ok(Ipv4Addr::UNSPECIFIED)
        }
    }
}

#[derive(Clone)]
pub struct NatTest {
    nat_test_server: Arc<Vec<SocketAddr>>,
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
        nat_test_server: Vec<SocketAddr>,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ip: Ipv4Addr,
        local_port: u16,
    ) -> NatTest {
        let info = NatTest::re_test_(
            &nat_test_server,
            public_ip,
            public_port,
            local_ip,
            local_port,
        );
        NatTest {
            nat_test_server: Arc::new(nat_test_server),
            info: Arc::new(Mutex::new(info)),
        }
    }
    pub fn nat_info(&self) -> NatInfo {
        self.info.lock().clone()
    }
    pub fn re_test(
        &self,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ip: Ipv4Addr,
        local_port: u16,
    ) -> NatInfo {
        let info = NatTest::re_test_(
            &self.nat_test_server,
            public_ip,
            public_port,
            local_ip,
            local_port,
        );
        *self.info.lock() = info.clone();
        info
    }
    fn re_test_(
        nat_test_server: &Vec<SocketAddr>,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ip: Ipv4Addr,
        local_port: u16,
    ) -> NatInfo {
        return match check::public_ip_list(nat_test_server) {
            Ok((nat_type, ips, port_range)) => {
                let mut public_ips = Vec::new();
                public_ips.push(Ipv4Addr::from(public_ip));
                for ip in ips {
                    if ip != public_ip {
                        public_ips.push(ip);
                    }
                }
                NatInfo::new(
                    public_ips,
                    public_port,
                    port_range,
                    local_ip,
                    local_port,
                    nat_type,
                )
            }
            Err(e) => {
                log::warn!("{:?}", e);
                NatInfo::new(
                    vec![public_ip],
                    public_port,
                    0,
                    local_ip,
                    local_port,
                    NatType::Cone,
                )
            }
        };
    }
}
