use ipnet::Ipv4Net;
use parking_lot::Mutex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

pub(crate) mod internal_nat;

#[derive(Clone, Debug)]
pub struct NetInput {
    pub net: Ipv4Net,
    pub target_ip: Ipv4Addr,
}
impl FromStr for NetInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').map(|x| x.trim()).collect();
        if parts.len() != 2 {
            return Err("格式错误，应为 net,target_ip  例如: 192.168.0.0/24,10.26.0.2".into());
        }

        let net = Ipv4Net::from_str(parts[0]).map_err(|e| format!("网络段格式错误: {}", e))?;

        let target_ip =
            Ipv4Addr::from_str(parts[1]).map_err(|e| format!("目标 IP 格式错误: {}", e))?;

        Ok(NetInput { net, target_ip })
    }
}
impl fmt::Display for NetInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{}", self.net, self.target_ip)
    }
}
impl Serialize for NetInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NetInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Default)]
pub struct SubnetExternalRoute {
    route_table: Arc<Mutex<Vec<NetInput>>>,
}
impl SubnetExternalRoute {
    pub fn new(mut route_table: Vec<NetInput>) -> Self {
        route_table.sort_by_key(|r| std::cmp::Reverse(r.net.prefix_len()));
        SubnetExternalRoute {
            route_table: Arc::new(Mutex::new(route_table)),
        }
    }
    pub fn set_route_table(&self, mut route_table: Vec<NetInput>) {
        route_table.sort_by_key(|r| std::cmp::Reverse(r.net.prefix_len()));
        *self.route_table.lock() = route_table;
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        let route_table = self.route_table.lock();
        if route_table.is_empty() {
            return None;
        }
        for net in route_table.iter() {
            if net.net.contains(ip) {
                return Some(net.target_ip);
            }
        }
        None
    }
    pub fn all_route(&self) -> Vec<NetInput> {
        self.route_table.lock().clone()
    }
    pub fn reset_route(&self, route_table: Vec<NetInput>) {
        *self.route_table.lock() = route_table;
    }
}

#[derive(Clone)]
pub struct AllowSubnetExternalRoute {
    route_table: Arc<Vec<Ipv4Net>>,
}
impl AllowSubnetExternalRoute {
    pub fn new(mut route_table: Vec<Ipv4Net>) -> Self {
        route_table.sort_by_key(|r| r.prefix_len());
        Self {
            route_table: Arc::new(route_table),
        }
    }
    pub fn allow(&self, ip: &Ipv4Addr) -> bool {
        if self.route_table.is_empty() {
            return false;
        }
        for net in self.route_table.iter() {
            if net.contains(ip) {
                return true;
            }
        }
        false
    }
}
