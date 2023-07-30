use std::net::Ipv4Addr;
use std::sync::Arc;

// 目标ip，子网掩码，网关

#[derive(Clone)]
pub struct ExternalRoute {
    route_table: Arc<Vec<(u32, u32, Ipv4Addr)>>,
}

impl ExternalRoute {
    pub fn new(route_table: Vec<(u32, u32, Ipv4Addr)>) -> Self {
        Self {
            route_table: Arc::new(route_table)
        }
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        let ip = u32::from_be_bytes(ip.octets());
        for (dest, mask, gateway) in self.route_table.iter() {
            if *mask & ip == *mask & *dest {
                return Some(*gateway);
            }
        }
        None
    }
}

#[derive(Clone)]
pub struct AllowExternalRoute {
    route_table: Arc<Vec<(u32, u32)>>,
}

impl AllowExternalRoute {
    pub fn new(route_table: Vec<(u32, u32)>) -> Self {
        Self {
            route_table: Arc::new(route_table)
        }
    }
    pub fn allow(&self, ip: &Ipv4Addr) -> bool {
        let ip = u32::from_be_bytes(ip.octets());
        for (dest, mask) in self.route_table.iter() {
            if *mask & ip == *mask & *dest {
                return true;
            }
        }
        false
    }
}