use std::net::Ipv4Addr;

// 目标ip，子网掩码，网关

pub struct ExternalRoute {
    route_table: Vec<(u32, u32, Ipv4Addr)>,
}

impl ExternalRoute {
    pub fn new(route_table: Vec<(u32, u32, Ipv4Addr)>) -> Self {
        Self {
            route_table
        }
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        let ip = u32::from_be_bytes(ip.octets());
        for (dest, mask, gateway) in &self.route_table {
            if *mask & ip == *mask & *dest {
                return Some(*gateway);
            }
        }
        None
    }
}