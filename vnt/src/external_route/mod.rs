use std::net::Ipv4Addr;
use std::sync::Arc;

// 目标网段，子网掩码，网关
#[derive(Clone)]
pub struct ExternalRoute {
    route_table: Vec<(u32, u32, Ipv4Addr)>,
}

impl ExternalRoute {
    pub fn new(mut route_table: Vec<(u32, u32, Ipv4Addr)>) -> Self {
        for (dest, mask, _) in &mut route_table {
            *dest = *mask & *dest;
        }
        route_table.sort_by(|(dest1, _, _), (dest2, _, _)| dest2.cmp(dest1));
        Self { route_table }
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        if self.route_table.is_empty() {
            return None;
        }
        let ip = u32::from_be_bytes(ip.octets());
        for (dest, mask, gateway) in self.route_table.iter() {
            if *mask & ip == *dest {
                return Some(*gateway);
            }
        }
        None
    }
    pub fn to_route(&self) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        self.route_table
            .iter()
            .map(|(dest, mask, _)| (Ipv4Addr::from(*dest), Ipv4Addr::from(*mask)))
            .collect::<Vec<(Ipv4Addr, Ipv4Addr)>>()
    }
}

// 目标网段，子网掩码
#[derive(Clone)]
pub struct AllowExternalRoute {
    route_table: Arc<Vec<(u32, u32)>>,
}

impl AllowExternalRoute {
    pub fn new(mut route_table: Vec<(u32, u32)>) -> Self {
        for (dest, mask) in &mut route_table {
            *dest = *mask & *dest;
        }
        route_table.sort_by(|(dest1, _), (dest2, _)| dest2.cmp(dest1));
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
