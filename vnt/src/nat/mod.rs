use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::net::UdpSocket;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::channel::punch::{NatInfo, NatType};
use crate::proto::message::PunchNatType;

mod stun_test;

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
    pub async fn new(
        mut stun_server: Vec<String>,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ip: Ipv4Addr,
        local_port: u16,
    ) -> NatTest {
        let server = stun_server[0].clone();
        stun_server.resize(3, server);
        let info = NatTest::re_test_(
            &stun_server,
            public_ip,
            public_port,
            local_ip,
            local_port,
        ).await;
        NatTest {
            stun_server,
            info: Arc::new(Mutex::new(info)),
        }
    }
    pub fn nat_info(&self) -> NatInfo {
        self.info.lock().clone()
    }
    pub fn update_addr(&self, ip: Ipv4Addr, port: u16) {
        let mut guard = self.info.lock();
        guard.public_port = port;
        if !guard.public_ips.contains(&ip) {
            guard.public_ips.push(ip);
        }
    }
    pub async fn re_test(
        &self,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ip: Ipv4Addr,
        local_port: u16,
    ) -> NatInfo {
        let info = NatTest::re_test_(
            &self.stun_server,
            public_ip,
            public_port,
            local_ip,
            local_port,
        ).await;
        *self.info.lock() = info.clone();
        info
    }
    async fn re_test_(
        stun_server: &Vec<String>,
        public_ip: Ipv4Addr,
        public_port: u16,
        local_ip: Ipv4Addr,
        local_port: u16,
    ) -> NatInfo {
        return match stun_test::stun_test_nat(stun_server.clone()).await {
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
