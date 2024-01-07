use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::str::FromStr;
use std::time::Duration;
use std::{io, thread};

use rand::prelude::SliceRandom;

use crate::channel::channel::{send_tcp, start_tcp_handle, Context};
use crate::handle::recv_handler::ChannelDataHandler;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum PunchModel {
    IPv4,
    IPv6,
    All,
}

impl FromStr for PunchModel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "ipv4" => Ok(PunchModel::IPv4),
            "ipv6" => Ok(PunchModel::IPv6),
            _ => Ok(PunchModel::All),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NatInfo {
    pub public_ips: Vec<Ipv4Addr>,
    pub public_port: u16,
    pub public_port_range: u16,
    pub nat_type: NatType,
    pub(crate) local_ipv4: Option<Ipv4Addr>,
    pub(crate) ipv6: Option<Ipv6Addr>,
    pub(crate) udp_port: u16,
    pub tcp_port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum NatType {
    Symmetric,
    Cone,
}

impl NatInfo {
    pub fn new(
        mut public_ips: Vec<Ipv4Addr>,
        public_port: u16,
        public_port_range: u16,
        mut local_ipv4: Option<Ipv4Addr>,
        mut ipv6: Option<Ipv6Addr>,
        udp_port: u16,
        tcp_port: u16,
        mut nat_type: NatType,
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
            public_port,
            public_port_range,
            local_ipv4,
            ipv6,
            udp_port,
            tcp_port,
            nat_type,
        }
    }
    pub fn update_addr(&mut self, ip: Ipv4Addr, port: u16) {
        if !ip.is_multicast()
            && !ip.is_broadcast()
            && !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_private()
            && port != 0
        {
            self.public_port = port;
            if !self.public_ips.contains(&ip) {
                self.public_ips.push(ip);
            }
        }
    }
    pub fn local_ipv4(&self) -> Option<Ipv4Addr> {
        self.local_ipv4
    }
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }
    pub fn local_udp_ipv4addr(&self) -> Option<SocketAddr> {
        if self.udp_port == 0 {
            return None;
        }
        if let Some(local_ipv4) = self.local_ipv4 {
            Some(SocketAddr::V4(SocketAddrV4::new(local_ipv4, self.udp_port)))
        } else {
            None
        }
    }
    pub fn local_udp_ipv6addr(&self) -> Option<SocketAddr> {
        if self.udp_port == 0 {
            return None;
        }
        if let Some(ipv6) = self.ipv6 {
            Some(SocketAddr::V6(SocketAddrV6::new(ipv6, self.udp_port, 0, 0)))
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
    context: Context,
    port_vec: Vec<u16>,
    port_index: HashMap<Ipv4Addr, usize>,
    punch_model: PunchModel,
    is_tcp: bool,
    handler: ChannelDataHandler,
}

impl Punch {
    pub fn new(
        context: Context,
        punch_model: PunchModel,
        is_tcp: bool,
        handler: ChannelDataHandler,
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
            is_tcp,
            handler,
        }
    }
}

impl Punch {
    fn connect_tcp(&self, buf: &[u8], addr: &SocketAddr) -> bool {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
            Ok(mut tcp_stream) => {
                let context = self.context.clone();
                let handler = self.handler.clone();
                match send_tcp(&mut tcp_stream, buf) {
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("发送到tcp失败,addr={},err={}", addr, e);
                        return false;
                    }
                }
                thread::spawn(move || {
                    if let Err(e) = start_tcp_handle(tcp_stream, context, handler) {
                        log::error!("{:?}", e);
                    }
                });
                return true;
            }
            Err(e) => {
                log::warn!("连接到tcp失败,addr={},err={}", addr, e);
            }
        }
        false
    }
    pub async fn punch(&mut self, buf: &[u8], id: Ipv4Addr, nat_info: NatInfo) -> io::Result<()> {
        if !self.context.need_punch(&id) {
            return Ok(());
        }
        if self.is_tcp {
            //向tcp发起连接
            if let Some(ipv6_addr) = nat_info.local_tcp_ipv6addr() {
                if self.connect_tcp(buf, &ipv6_addr) {
                    return Ok(());
                }
            }
            log::info!("local_tcp_ipv4addr={:?}", nat_info.local_tcp_ipv4addr());
            //向tcp发起连接
            if let Some(ipv4_addr) = nat_info.local_tcp_ipv4addr() {
                if self.connect_tcp(buf, &ipv4_addr) {
                    return Ok(());
                }
            }
            if nat_info.nat_type == NatType::Cone && nat_info.public_ips.len() == 1 {
                let addr =
                    SocketAddr::V4(SocketAddrV4::new(nat_info.public_ips[0], nat_info.tcp_port));
                if self.connect_tcp(buf, &addr) {
                    return Ok(());
                }
            }
        }
        if let Some(ipv4_addr) = nat_info.local_udp_ipv4addr() {
            let _ = self.context.send_main_udp(buf, ipv4_addr);
        }
        if self.punch_model != PunchModel::IPv4 {
            if let Some(ipv6_addr) = nat_info.local_udp_ipv6addr() {
                let rs = self.context.send_main_udp(buf, ipv6_addr);
                log::info!("发送到ipv6地址:{:?},rs={:?}", ipv6_addr, rs);
                if rs.is_ok() && self.punch_model == PunchModel::IPv6 {
                    return Ok(());
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
                let max_k2 = 800;
                if nat_info.public_port_range < max_k1 * 3 {
                    //端口变化不大时，在预测的范围内随机发送
                    let min_port = if nat_info.public_port > nat_info.public_port_range {
                        nat_info.public_port - nat_info.public_port_range
                    } else {
                        1
                    };
                    let (max_port, overflow) = nat_info
                        .public_port
                        .overflowing_add(nat_info.public_port_range);
                    let max_port = if overflow { 65535 } else { max_port };
                    let k = if max_port - min_port + 1 > max_k1 {
                        max_k1 as usize
                    } else {
                        (max_port - min_port + 1) as usize
                    };
                    let mut nums: Vec<u16> = (min_port..max_port).collect();
                    nums.push(max_port);
                    {
                        let mut rng = rand::thread_rng();
                        nums.shuffle(&mut rng);
                    }
                    self.punch_symmetric(&nums[..k], buf, &nat_info.public_ips, max_k1 as usize)
                        .await?;
                }
                let start = *self.port_index.entry(id.clone()).or_insert(0);
                let mut end = start + max_k2;
                let mut index = end;
                if end >= self.port_vec.len() {
                    end = self.port_vec.len();
                    index = 0
                }
                self.punch_symmetric(
                    &self.port_vec[start..end],
                    buf,
                    &nat_info.public_ips,
                    max_k2,
                )
                .await?;
                self.port_index.insert(id, index);
            }
            NatType::Cone => {
                if nat_info.public_port != 0 {
                    let is_cone = self.context.is_cone();
                    for ip in nat_info.public_ips {
                        let addr = SocketAddr::V4(SocketAddrV4::new(ip, nat_info.public_port));
                        self.context.send_main_udp(buf, addr)?;
                        if !is_cone {
                            //只有一方是对称，则对称方要使用全部端口发送数据，符合上述计算的概率
                            self.context.try_send_all(buf, addr)?;
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn punch_symmetric(
        &self,
        ports: &[u16],
        buf: &[u8],
        ips: &Vec<Ipv4Addr>,
        max: usize,
    ) -> io::Result<()> {
        let mut count = 0;
        for port in ports {
            for pub_ip in ips {
                count += 1;
                if count == max {
                    return Ok(());
                }
                let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, *port));
                self.context.send_main_udp(buf, addr)?;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        Ok(())
    }
}
