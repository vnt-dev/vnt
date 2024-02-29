use std::net::Ipv4Addr;
use std::sync::Arc;

// 目标ip，子网掩码，网关

#[derive(Clone)]
pub struct ExternalRoute {
    route_table: Vec<(u32, u32, Ipv4Addr)>,
}

impl ExternalRoute {
    pub fn new(route_table: Vec<(u32, u32, Ipv4Addr)>) -> Self {
        Self { route_table }
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        if self.route_table.is_empty() {
            return None;
        }
        let ip = u32::from_be_bytes(ip.octets());
        for (dest, mask, gateway) in self.route_table.iter() {
            if *mask & ip == *mask & *dest {
                return Some(*gateway);
            }
        }
        None
    }
    pub fn to_route(&self) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        self.route_table
            .iter()
            .map(|(dest, mask, _)| (Ipv4Addr::from(*dest & *mask), Ipv4Addr::from(*mask)))
            .collect::<Vec<(Ipv4Addr, Ipv4Addr)>>()
    }
}

#[derive(Clone)]
pub struct AllowExternalRoute {
    route_table: Arc<Vec<(u32, u32)>>,
}

impl AllowExternalRoute {
    pub fn new(route_table: Vec<(u32, u32)>) -> Self {
        Self {
            route_table: Arc::new(route_table),
        }
    }
    pub fn allow(&self, ip: &Ipv4Addr) -> bool {
        if self.route_table.is_empty() {
            return false;
        }
        let ip = u32::from_be_bytes(ip.octets());
        for (dest, mask) in self.route_table.iter() {
            if *mask & ip == *mask & *dest {
                return true;
            }
        }
        false
    }
}
