use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::{Div, Mul};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use rand::prelude::SliceRandom;
use rand::Rng;

use crate::channel::context::ChannelContext;
use crate::channel::sender::ConnectUtil;
use crate::handle::CurrentDeviceInfo;
use crate::nat::{is_ipv4_global, NatTest};
use crate::proto::message::{PunchNatModel, PunchNatType};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum PunchModel {
    All,
    IPv4,
    IPv6,
    IPv4Tcp,
    IPv4Udp,
    IPv6Tcp,
    IPv6Udp,
}

impl PunchModel {
    pub fn use_tcp(&self) -> bool {
        self != &PunchModel::IPv4Udp && self != &PunchModel::IPv6Udp
    }
    pub fn use_udp(&self) -> bool {
        self != &PunchModel::IPv4Tcp && self != &PunchModel::IPv6Tcp
    }
    pub fn use_ipv6(&self) -> bool {
        self == &PunchModel::All
            || self == &PunchModel::IPv6
            || self == &PunchModel::IPv6Tcp
            || self == &PunchModel::IPv6Udp
    }
    pub fn use_ipv4(&self) -> bool {
        self == &PunchModel::All
            || self == &PunchModel::IPv4
            || self == &PunchModel::IPv4Tcp
            || self == &PunchModel::IPv4Udp
    }
}

impl FromStr for PunchModel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "ipv4" => Ok(PunchModel::IPv4),
            "ipv6" => Ok(PunchModel::IPv6),
            "ipv4-tcp" => Ok(PunchModel::IPv4Tcp),
            "ipv4-udp" => Ok(PunchModel::IPv4Udp),
            "ipv6-tcp" => Ok(PunchModel::IPv6Tcp),
            "ipv6-udp" => Ok(PunchModel::IPv6Udp),
            "all" => Ok(PunchModel::All),
            _ => Err(format!(
                "not match '{}', enum: ipv4/ipv4-tcp/ipv4-udp/ipv6/ipv6-tcp/ipv6-udp/all",
                s
            )),
        }
    }
}

impl Default for PunchModel {
    fn default() -> Self {
        PunchModel::All
    }
}
impl From<PunchModel> for PunchNatModel {
    fn from(value: PunchModel) -> Self {
        match value {
            PunchModel::All => PunchNatModel::All,
            PunchModel::IPv4 => PunchNatModel::IPv4,
            PunchModel::IPv6 => PunchNatModel::IPv6,
            PunchModel::IPv4Tcp => PunchNatModel::IPv4Tcp,
            PunchModel::IPv4Udp => PunchNatModel::IPv4Udp,
            PunchModel::IPv6Tcp => PunchNatModel::IPv6Tcp,
            PunchModel::IPv6Udp => PunchNatModel::IPv6Udp,
        }
    }
}

impl Into<PunchModel> for PunchNatModel {
    fn into(self) -> PunchModel {
        match self {
            PunchNatModel::All => PunchModel::All,
            PunchNatModel::IPv4 => PunchModel::IPv4,
            PunchNatModel::IPv6 => PunchModel::IPv6,
            PunchNatModel::IPv4Tcp => PunchModel::IPv4Tcp,
            PunchNatModel::IPv4Udp => PunchModel::IPv4Udp,
            PunchNatModel::IPv6Tcp => PunchModel::IPv6Tcp,
            PunchNatModel::IPv6Udp => PunchModel::IPv6Udp,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NatInfo {
    pub public_ips: Vec<Ipv4Addr>,
    pub public_ports: Vec<u16>,
    pub public_port_range: u16,
    pub nat_type: NatType,
    pub(crate) local_ipv4: Option<Ipv4Addr>,
    pub(crate) ipv6: Option<Ipv6Addr>,
    pub udp_ports: Vec<u16>,
    pub tcp_port: u16,
    pub public_tcp_port: u16,
    pub punch_model: PunchModel,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum NatType {
    Symmetric,
    Cone,
}

impl NatType {
    pub fn is_cone(&self) -> bool {
        self == &NatType::Cone
    }
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

impl NatInfo {
    pub fn new(
        mut public_ips: Vec<Ipv4Addr>,
        public_ports: Vec<u16>,
        public_port_range: u16,
        mut local_ipv4: Option<Ipv4Addr>,
        mut ipv6: Option<Ipv6Addr>,
        udp_ports: Vec<u16>,
        tcp_port: u16,
        public_tcp_port: u16,
        mut nat_type: NatType,
        punch_model: PunchModel,
    ) -> Self {
        public_ips.retain(|ip| {
            !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
        });
        if public_ips.len() > 1 {
            nat_type = NatType::Symmetric;
        }
        if let Some(ip) = local_ipv4 {
            if ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() || ip.is_loopback() {
                local_ipv4 = None
            }
        }
        if let Some(ip) = ipv6 {
            if ip.is_multicast() || ip.is_unspecified() || ip.is_loopback() {
                ipv6 = None
            }
        }
        Self {
            public_ips,
            public_ports,
            public_port_range,
            local_ipv4,
            ipv6,
            udp_ports,
            tcp_port,
            public_tcp_port,
            nat_type,
            punch_model,
        }
    }
    pub fn update_addr(&mut self, index: usize, ip: Ipv4Addr, port: u16) -> bool {
        let mut updated = false;
        if port != 0 {
            if let Some(public_port) = self.public_ports.get_mut(index) {
                if *public_port != port {
                    updated = true;
                    log::info!("端口变化={}:{} index={}", ip, port, index)
                }
                *public_port = port;
            }
        }
        if is_ipv4_global(&ip) {
            if !self.public_ips.contains(&ip) {
                self.public_ips.push(ip);
                updated = true;
                log::info!("ip变化={},{:?}", ip, self.public_ips)
            }
        }
        updated
    }
    pub fn update_tcp_port(&mut self, port: u16) {
        self.public_tcp_port = port;
    }
    pub fn local_ipv4(&self) -> Option<Ipv4Addr> {
        self.local_ipv4
    }
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }
    pub fn local_udp_ipv4addr(&self, index: usize) -> Option<SocketAddr> {
        let len = self.udp_ports.len();
        if len == 0 {
            return None;
        }
        if let Some(local_ipv4) = self.local_ipv4 {
            Some(SocketAddr::V4(SocketAddrV4::new(
                local_ipv4,
                self.udp_ports[index % len],
            )))
        } else {
            None
        }
    }
    pub fn local_udp_ipv6addr(&self, index: usize) -> Option<SocketAddr> {
        let len = self.udp_ports.len();
        if len == 0 {
            return None;
        }
        if let Some(ipv6) = self.ipv6 {
            Some(SocketAddr::V6(SocketAddrV6::new(
                ipv6,
                self.udp_ports[index % len],
                0,
                0,
            )))
        } else {
            None
        }
    }

    pub fn local_tcp_ipv6addr(&self) -> Option<SocketAddr> {
        if self.tcp_port == 0 {
            return None;
        }
        if let Some(ipv6) = self.ipv6 {
            Some(SocketAddr::V6(SocketAddrV6::new(ipv6, self.tcp_port, 0, 0)))
        } else {
            None
        }
    }
    pub fn local_tcp_ipv4addr(&self) -> Option<SocketAddr> {
        if self.tcp_port == 0 {
            return None;
        }
        if let Some(ipv4) = self.local_ipv4 {
            Some(SocketAddr::V4(SocketAddrV4::new(ipv4, self.tcp_port)))
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct Punch {
    context: ChannelContext,
    port_vec: Vec<u16>,
    port_index: HashMap<Ipv4Addr, usize>,
    punch_model: PunchModel,
    connect_util: ConnectUtil,
    nat_test: NatTest,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
}

impl Punch {
    pub fn new(
        context: ChannelContext,
        punch_model: PunchModel,
        connect_util: ConnectUtil,
        nat_test: NatTest,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ) -> Self {
        let mut port_vec: Vec<u16> = (1..65535).collect();
        port_vec.push(65535);
        let mut rng = rand::thread_rng();
        port_vec.shuffle(&mut rng);
        Punch {
            context,
            port_vec,
            port_index: HashMap::new(),
            punch_model,
            connect_util,
            nat_test,
            current_device,
        }
    }
}

impl Punch {
    fn connect_tcp(&self, buf: &[u8], addr: SocketAddr) {
        if self.nat_test.is_local_address(true, addr) {
            return;
        }
        if addr.ip().is_unspecified() || addr.port() == 0 {
            return;
        }
        self.connect_util.try_connect_tcp_punch(buf.to_vec(), addr);
    }
    pub fn punch(
        &mut self,
        buf: &[u8],
        id: Ipv4Addr,
        mut nat_info: NatInfo,
        punch_tcp: bool,
        count: usize,
    ) -> io::Result<()> {
        if self.context.route_table.no_need_punch(&id) {
            log::info!("已打洞成功,无需打洞:{:?}", id);
            return Ok(());
        }
        let device_info = self.current_device.load();

        nat_info
            .public_ips
            .retain(|ip| is_ipv4_global(ip) && device_info.not_in_network(*ip));
        nat_info.public_ports.retain(|port| *port != 0);
        nat_info.udp_ports.retain(|port| *port != 0);

        nat_info.local_ipv4 = nat_info
            .local_ipv4
            .filter(|ip| device_info.not_in_network(*ip));
        if punch_tcp && self.punch_model.use_tcp() && nat_info.punch_model.use_tcp() {
            //向tcp发起连接
            if self.punch_model.use_ipv6() && nat_info.punch_model.use_ipv6() {
                if let Some(ipv6_addr) = nat_info.local_tcp_ipv6addr() {
                    self.connect_tcp(buf, ipv6_addr)
                }
            }
            if self.punch_model.use_ipv4() && nat_info.punch_model.use_ipv4() {
                if let Some(ipv4_addr) = nat_info.local_tcp_ipv4addr() {
                    self.connect_tcp(buf, ipv4_addr)
                }
                for ip in &nat_info.public_ips {
                    let addr = SocketAddr::V4(SocketAddrV4::new(*ip, nat_info.tcp_port));
                    self.connect_tcp(buf, addr);
                }
                if nat_info.nat_type.is_cone() && nat_info.public_tcp_port != 0 {
                    for ip in &nat_info.public_ips {
                        let addr = SocketAddr::V4(SocketAddrV4::new(*ip, nat_info.public_tcp_port));
                        self.connect_tcp(buf, addr);
                    }
                }
            }
        }
        if !self.punch_model.use_udp() || !nat_info.punch_model.use_udp() {
            return Ok(());
        }
        let channel_num = self.context.channel_num();
        let main_len = self.context.main_len();

        if self.punch_model.use_ipv6() && nat_info.punch_model.use_ipv6() {
            for index in channel_num..main_len {
                if let Some(ipv6_addr) = nat_info.local_udp_ipv6addr(index) {
                    if !self.nat_test.is_local_address(false, ipv6_addr) {
                        let rs = self.context.send_main_udp(index, buf, ipv6_addr);
                        log::info!("发送到ipv6地址:{:?},rs={:?} {}", ipv6_addr, rs, id);
                    }
                }
            }
        }
        if !self.punch_model.use_ipv4() || !nat_info.punch_model.use_ipv4() {
            return Ok(());
        }
        for index in 0..channel_num {
            if let Some(ipv4_addr) = nat_info.local_udp_ipv4addr(index) {
                if !self.nat_test.is_local_address(false, ipv4_addr) {
                    let _ = self.context.send_main_udp(index, buf, ipv4_addr);
                }
            }
        }
        // 可能是开放了端口的，需要打洞
        for index in 0..channel_num {
            for port in &nat_info.udp_ports {
                if *port == 0 {
                    continue;
                }
                for ip in &nat_info.public_ips {
                    if ip.is_unspecified() {
                        continue;
                    }
                    let addr = SocketAddrV4::new(*ip, *port);
                    let _ = self.context.send_main_udp(index, buf, addr.into());
                    thread::sleep(Duration::from_millis(3));
                }
            }
        }

        match nat_info.nat_type {
            NatType::Symmetric => {
                // 假设对方绑定n个端口，通过NAT对外映射出n个 公网ip:公网端口，自己随机尝试k次的情况下
                // 猜中的概率 p = 1-((65535-n)/65535)*((65535-n-1)/(65535-1))*...*((65535-n-k+1)/(65535-k+1))
                // n取76，k取600，猜中的概率就超过50%了
                // 前提 自己是锥形网络，否则猜中了也通信不了

                //预测范围内最多发送max_k1个包
                let max_k1 = 60;
                //全局最多发送max_k2个包
                let mut max_k2: usize = rand::thread_rng().gen_range(600..800);
                if count > 2 {
                    //递减探测规模
                    max_k2 = max_k2.mul(2).div(count).max(max_k1 as usize);
                }
                let port = nat_info.public_ports.get(0).map(|e| *e).unwrap_or(0);
                if nat_info.public_port_range < max_k1 * 3 {
                    //端口变化不大时，在预测的范围内随机发送
                    let min_port = if port > nat_info.public_port_range {
                        port - nat_info.public_port_range
                    } else {
                        1
                    };
                    let (max_port, overflow) = port.overflowing_add(nat_info.public_port_range);
                    let max_port = if overflow { 65535 } else { max_port };
                    let k = if max_port - min_port + 1 > max_k1 {
                        max_k1 as usize
                    } else {
                        (max_port - min_port + 1) as usize
                    };
                    let mut nums: Vec<u16> = (min_port..=max_port).collect();
                    nums.shuffle(&mut rand::thread_rng());
                    self.punch_symmetric(&nums[..k], buf, &nat_info.public_ips, max_k1 as usize)?;
                }
                let start = *self.port_index.entry(id.clone()).or_insert(0);
                let mut end = start + max_k2;
                if end > self.port_vec.len() {
                    end = self.port_vec.len();
                }
                let mut index = start
                    + self.punch_symmetric(
                        &self.port_vec[start..end],
                        buf,
                        &nat_info.public_ips,
                        max_k2,
                    )?;
                if index >= self.port_vec.len() {
                    index = 0
                }
                self.port_index.insert(id, index);
            }
            NatType::Cone => {
                let is_cone = self.context.is_cone();
                'a: for index in 0..nat_info.public_ports.len().min(channel_num) {
                    for ip in &nat_info.public_ips {
                        let port = nat_info.public_ports[index];
                        if port == 0 || ip.is_unspecified() {
                            continue;
                        }
                        let addr = SocketAddr::V4(SocketAddrV4::new(*ip, port));
                        if is_cone {
                            self.context.send_main_udp(index, buf, addr)?;
                        } else {
                            //只有一方是对称，则对称方要使用全部端口发送数据，符合上述计算的概率
                            self.context.try_send_all(buf, addr);
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    if !is_cone {
                        //对称网络数据只发一遍
                        break 'a;
                    }
                }
            }
        }
        Ok(())
    }

    fn punch_symmetric(
        &self,
        ports: &[u16],
        buf: &[u8],
        ips: &Vec<Ipv4Addr>,
        max: usize,
    ) -> io::Result<usize> {
        let mut count = 0;
        for (index, port) in ports.iter().enumerate() {
            for pub_ip in ips {
                count += 1;
                if count == max {
                    return Ok(index);
                }
                let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, *port));
                self.context.send_main_udp(0, buf, addr)?;
                thread::sleep(Duration::from_millis(3));
            }
        }
        Ok(ports.len())
    }
}
