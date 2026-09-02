use ipnet::Ipv4Net;
use parking_lot::Mutex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

pub(crate) mod internal_nat;
pub(crate) mod subnet_mapping;
pub(crate) mod subnet_packet;

pub use subnet_mapping::{SubnetMapping, SubnetMappingTable, advertised_subnets};

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone)]
pub struct SubnetExternalRoute {
    route_table: Arc<Mutex<SubnetRouteTables>>,
    changes: tokio::sync::watch::Sender<Vec<NetInput>>,
}

#[derive(Default)]
struct SubnetRouteTables {
    static_routes: Vec<NetInput>,
    automatic_routes: Vec<NetInput>,
    effective_routes: Vec<NetInput>,
}

impl Default for SubnetExternalRoute {
    fn default() -> Self {
        let (changes, _) = tokio::sync::watch::channel(Vec::new());
        Self {
            route_table: Arc::new(Mutex::new(SubnetRouteTables::default())),
            changes,
        }
    }
}
impl SubnetExternalRoute {
    pub fn new(route_table: Vec<NetInput>) -> Self {
        let route = Self::default();
        route.set_route_table(route_table);
        route
    }
    pub fn set_route_table(&self, route_table: Vec<NetInput>) {
        let routes = {
            let mut tables = self.route_table.lock();
            tables.static_routes = route_table;
            rebuild_routes(&mut tables);
            tables.effective_routes.clone()
        };
        self.publish(routes);
    }
    pub fn set_automatic_routes(&self, route_table: Vec<NetInput>) {
        let routes = {
            let mut tables = self.route_table.lock();
            tables.automatic_routes = route_table;
            rebuild_routes(&mut tables);
            tables.effective_routes.clone()
        };
        self.publish(routes);
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        let route_table = self.route_table.lock();
        for net in &route_table.effective_routes {
            if net.net.contains(ip) {
                return Some(net.target_ip);
            }
        }
        None
    }
    pub fn all_route(&self) -> Vec<NetInput> {
        self.route_table.lock().effective_routes.clone()
    }
    pub fn static_routes(&self) -> Vec<NetInput> {
        self.route_table.lock().static_routes.clone()
    }
    pub fn automatic_routes(&self) -> Vec<NetInput> {
        self.route_table.lock().automatic_routes.clone()
    }
    pub fn reset_route(&self, route_table: Vec<NetInput>) {
        self.set_route_table(route_table);
    }
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Vec<NetInput>> {
        self.changes.subscribe()
    }

    fn publish(&self, routes: Vec<NetInput>) {
        self.changes.send_if_modified(|current| {
            if *current == routes {
                false
            } else {
                *current = routes;
                true
            }
        });
    }
}

fn rebuild_routes(tables: &mut SubnetRouteTables) {
    let mut routes = tables.static_routes.clone();
    routes.extend(tables.automatic_routes.clone());
    routes.sort_by_key(|route| std::cmp::Reverse(route.net.prefix_len()));
    tables.effective_routes = routes;
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

#[cfg(test)]
mod tests {
    use super::{NetInput, SubnetExternalRoute};

    #[test]
    fn static_and_automatic_routes_are_replaced_independently() {
        let static_route = "192.168.0.0/24,10.26.0.2".parse::<NetInput>().unwrap();
        let automatic_route = "172.16.0.0/16,10.26.0.3".parse::<NetInput>().unwrap();
        let routes = SubnetExternalRoute::new(vec![static_route.clone()]);
        routes.set_automatic_routes(vec![automatic_route.clone()]);
        assert_eq!(routes.static_routes(), vec![static_route.clone()]);
        assert_eq!(routes.automatic_routes(), vec![automatic_route.clone()]);
        assert!(routes.all_route().contains(&automatic_route));

        routes.set_automatic_routes(Vec::new());
        assert!(routes.automatic_routes().is_empty());
        assert_eq!(routes.all_route(), vec![static_route]);
    }

    #[test]
    fn overlapping_routes_use_longest_prefix() {
        let routes = SubnetExternalRoute::new(Vec::new());
        routes.set_automatic_routes(vec![
            "192.168.0.0/24,10.26.0.2".parse::<NetInput>().unwrap(),
            "192.168.0.0/25,10.26.0.4".parse::<NetInput>().unwrap(),
        ]);

        assert_eq!(
            routes.route(&"192.168.0.20".parse().unwrap()),
            Some("10.26.0.4".parse().unwrap())
        );
        assert_eq!(
            routes.route(&"192.168.0.200".parse().unwrap()),
            Some("10.26.0.2".parse().unwrap())
        );
    }
}
