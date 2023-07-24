use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use rand::prelude::SliceRandom;

use crate::channel::channel::Context;

#[derive(Clone, Debug)]
pub struct NatInfo {
    pub public_ips: Vec<Ipv4Addr>,
    pub public_port: u16,
    pub public_port_range: u16,
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub nat_type: NatType,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum NatType {
    Symmetric,
    Cone,
}

impl NatInfo {
    pub fn new(mut public_ips: Vec<Ipv4Addr>,
               public_port: u16,
               public_port_range: u16,
               local_ip: Ipv4Addr,
               local_port: u16,
               nat_type: NatType, ) -> Self {
        public_ips.retain(|ip| {
            !ip.is_loopback() && !ip.is_private()
        });
        Self {
            public_ips,
            public_port,
            public_port_range,
            local_ip,
            local_port,
            nat_type,
        }
    }
}

#[derive(Clone)]
pub struct Punch {
    context: Context,
    port_vec: Vec<u16>,
    port_index: HashMap<Ipv4Addr, usize>,
}

impl Punch {
    pub fn new(context: Context) -> Self {
        let mut port_vec: Vec<u16> = (1..65535).collect();
        port_vec.push(65535);
        let mut rng = rand::thread_rng();
        port_vec.shuffle(&mut rng);
        Punch {
            context,
            port_vec,
            port_index: HashMap::new(),
        }
    }
}

impl Punch {
    pub async fn punch(&mut self, buf: &[u8], id: Ipv4Addr, nat_info: NatInfo) -> io::Result<()> {
        if !self.context.need_punch(&id) {
            return Ok(());
        }
        if !nat_info.local_ip.is_unspecified() || nat_info.local_port != 0 {
            let _ = self.context.send_main_udp(buf, SocketAddr::V4(SocketAddrV4::new(nat_info.local_ip, nat_info.local_port))).await;
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
                    let (max_port, overflow) = nat_info.public_port.overflowing_add(nat_info.public_port_range);
                    let max_port = if overflow {
                        65535
                    } else {
                        max_port
                    };
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
                    self.punch_symmetric(&nums[..k], buf, &nat_info.public_ips, max_k1 as usize).await?;
                }
                let start = *self.port_index.entry(id.clone()).or_insert(0);
                let mut end = start + max_k2;
                let mut index = end;
                if end >= self.port_vec.len() {
                    end = self.port_vec.len();
                    index = 0
                }
                self.punch_symmetric(&self.port_vec[start..end], buf, &nat_info.public_ips, max_k2).await?;
                self.port_index.insert(id, index);
            }
            NatType::Cone => {
                let is_cone = self.context.is_cone();
                for ip in nat_info.public_ips {
                    let addr = SocketAddr::V4(SocketAddrV4::new(ip, nat_info.public_port));
                    if is_cone {
                        self.context.send_main_udp(buf, addr).await?;
                    } else {
                        //只有一方是对称，则对称方要使用全部端口发送数据，符合上述计算的概率
                        self.context.send_all(buf, addr).await?;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        }
        Ok(())
    }

    async fn punch_symmetric(&self, ports: &[u16], buf: &[u8], ips: &Vec<Ipv4Addr>, max: usize) -> io::Result<()> {
        let mut count = 0;
        for port in ports {
            for pub_ip in ips {
                count += 1;
                if count == max {
                    return Ok(());
                }
                let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, *port));
                self.context.send_main_udp(buf, addr).await?;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        Ok(())
    }
}
