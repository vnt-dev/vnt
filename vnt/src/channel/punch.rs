use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::time::Duration;

use rand::prelude::SliceRandom;

use crate::channel::channel::Context;

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
    pub local_ipv4_addr: SocketAddrV4,
    pub ipv6_addr: SocketAddrV6,
    pub nat_type: NatType,
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
        local_ipv4_addr: SocketAddrV4,
        ipv6_addr: SocketAddrV6,
        mut nat_type: NatType,
    ) -> Self {
        public_ips.retain(|ip| !ip.is_loopback() && !ip.is_private() && !ip.is_unspecified());
        if public_ips.len() > 1 {
            nat_type = NatType::Symmetric;
        }
        Self {
            public_ips,
            public_port,
            public_port_range,
            local_ipv4_addr,
            ipv6_addr,
            nat_type,
        }
    }
}

#[derive(Clone)]
pub struct Punch {
    context: Context,
    port_vec: Vec<u16>,
    port_index: HashMap<Ipv4Addr, usize>,
    punch_model: PunchModel,
}

impl Punch {
    pub fn new(context: Context, punch_model: PunchModel) -> Self {
        let mut port_vec: Vec<u16> = (1..65535).collect();
        port_vec.push(65535);
        let mut rng = rand::thread_rng();
        port_vec.shuffle(&mut rng);
        Punch {
            context,
            port_vec,
            port_index: HashMap::new(),
            punch_model,
        }
    }
}

impl Punch {
    pub async fn punch(&mut self, buf: &[u8], id: Ipv4Addr, nat_info: NatInfo) -> io::Result<()> {
        if !self.context.need_punch(&id) {
            return Ok(());
        }
        if !nat_info.local_ipv4_addr.ip().is_unspecified() && nat_info.local_ipv4_addr.port() != 0 {
            let _ = self
                .context
                .send_main_udp(buf, SocketAddr::V4(nat_info.local_ipv4_addr));
        }
        if self.punch_model != PunchModel::IPv4
            && !nat_info.ipv6_addr.ip().is_unspecified()
            && nat_info.ipv6_addr.port() != 0
        {
            let rs = self
                .context
                .send_main_udp(buf, SocketAddr::V6(nat_info.ipv6_addr));
            log::info!("发送到ipv6地址:{:?},rs={:?}", nat_info.ipv6_addr, rs);
            if rs.is_ok() && self.punch_model == PunchModel::IPv6 {
                return Ok(());
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
