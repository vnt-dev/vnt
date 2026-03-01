use crate::context::config::Config;
use crate::context::nat::{MyNatInfo, PunchBackoff};
use crate::nat::SubnetExternalRoute;
use crate::protocol::client_message::PunchInfo;
use crate::protocol::control_message::{ClientSimpleInfo, ClientSimpleInfoList};
use crate::tunnel_core::p2p::route_table::RouteTable;
use crate::tunnel_core::server::transport::config::ProtocolAddress;
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use rust_p2p_core::nat::NatInfo;
use rust_p2p_core::route::RouteKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
#[derive(Default)]
struct PingStats {
    sent: u64,
    received: u64,
}

#[derive(Default)]
struct TrafficCounter {
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Clone, Default)]
pub struct TrafficStats {
    inner: Arc<RwLock<HashMap<Ipv4Addr, Arc<Mutex<TrafficCounter>>>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficInfo {
    pub ip: Ipv4Addr,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

impl TrafficStats {
    fn get_or_create(&self, ip: Ipv4Addr) -> Arc<Mutex<TrafficCounter>> {
        {
            let read = self.inner.read();
            if let Some(counter) = read.get(&ip) {
                return counter.clone();
            }
        }
        let mut write = self.inner.write();
        write
            .entry(ip)
            .or_insert_with(|| Arc::new(Mutex::new(TrafficCounter::default())))
            .clone()
    }

    pub fn record_tx(&self, ip: Ipv4Addr, bytes: u64) {
        let counter = self.get_or_create(ip);
        counter.lock().tx_bytes += bytes;
    }

    pub fn record_rx(&self, ip: Ipv4Addr, bytes: u64) {
        let counter = self.get_or_create(ip);
        counter.lock().rx_bytes += bytes;
    }

    pub fn get_traffic_info(&self, ip: &Ipv4Addr) -> Option<TrafficInfo> {
        let read = self.inner.read();
        read.get(ip).map(|counter| {
            let guard = counter.lock();
            TrafficInfo {
                ip: *ip,
                tx_bytes: guard.tx_bytes,
                rx_bytes: guard.rx_bytes,
            }
        })
    }

    pub fn get_all_traffic_info(&self) -> Vec<TrafficInfo> {
        let read = self.inner.read();
        read.iter()
            .map(|(ip, counter)| {
                let guard = counter.lock();
                TrafficInfo {
                    ip: *ip,
                    tx_bytes: guard.tx_bytes,
                    rx_bytes: guard.rx_bytes,
                }
            })
            .collect()
    }

    pub fn reset(&self, ip: &Ipv4Addr) {
        let read = self.inner.read();
        if let Some(counter) = read.get(ip) {
            *counter.lock() = TrafficCounter::default();
        }
    }

    pub fn reset_all(&self) {
        let read = self.inner.read();
        for counter in read.values() {
            *counter.lock() = TrafficCounter::default();
        }
    }

    pub fn clear(&self) {
        self.inner.write().clear();
    }
}

#[derive(Clone, Default)]
pub struct PacketLossStats {
    inner: Arc<RwLock<HashMap<(Ipv4Addr, RouteKey), Arc<Mutex<PingStats>>>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketLossInfo {
    pub ip: Ipv4Addr,
    #[serde(skip)]
    pub route_key: Option<RouteKey>,
    pub sent: u64,
    pub received: u64,
    pub loss_rate: f64,
}

impl PacketLossStats {
    fn get_or_create(&self, ip: Ipv4Addr, route_key: RouteKey) -> Arc<Mutex<PingStats>> {
        {
            let read = self.inner.read();
            if let Some(stats) = read.get(&(ip, route_key)) {
                return stats.clone();
            }
        }
        let mut write = self.inner.write();
        write
            .entry((ip, route_key))
            .or_insert_with(|| Arc::new(Mutex::new(PingStats::default())))
            .clone()
    }

    pub fn record_sent(&self, ip: Ipv4Addr, route_key: RouteKey) {
        let stats = self.get_or_create(ip, route_key);
        stats.lock().sent += 1;
    }

    pub fn record_received(&self, ip: Ipv4Addr, route_key: RouteKey) -> f64 {
        let stats = self.get_or_create(ip, route_key);
        let mut guard = stats.lock();
        guard.received += 1;

        // 计算并返回丢包率
        if guard.sent > 0 {
            1.0 - (guard.received as f64 / guard.sent as f64)
        } else {
            0.0
        }
    }

    pub fn get_loss_info(&self, ip: &Ipv4Addr, route_key: &RouteKey) -> Option<PacketLossInfo> {
        let read = self.inner.read();
        read.get(&(*ip, *route_key)).map(|stats| {
            let guard = stats.lock();
            let loss_rate = if guard.sent > 0 {
                1.0 - (guard.received as f64 / guard.sent as f64)
            } else {
                0.0
            };
            PacketLossInfo {
                ip: *ip,
                route_key: Some(*route_key),
                sent: guard.sent,
                received: guard.received,
                loss_rate,
            }
        })
    }

    /// 获取指定 IP 的所有路由的丢包信息
    pub fn get_loss_info_by_ip(&self, ip: &Ipv4Addr) -> Vec<PacketLossInfo> {
        let read = self.inner.read();
        read.iter()
            .filter(|((addr, _), _)| addr == ip)
            .map(|((addr, route_key), stats)| {
                let guard = stats.lock();
                let loss_rate = if guard.sent > 0 {
                    1.0 - (guard.received as f64 / guard.sent as f64)
                } else {
                    0.0
                };
                PacketLossInfo {
                    ip: *addr,
                    route_key: Some(*route_key),
                    sent: guard.sent,
                    received: guard.received,
                    loss_rate,
                }
            })
            .collect()
    }

    /// 获取指定 IP 的聚合丢包信息（所有路由合并）
    pub fn get_aggregated_loss_info(&self, ip: &Ipv4Addr) -> Option<PacketLossInfo> {
        let read = self.inner.read();
        let mut total_sent = 0u64;
        let mut total_received = 0u64;
        let mut found = false;

        for ((addr, _), stats) in read.iter() {
            if addr == ip {
                found = true;
                let guard = stats.lock();
                total_sent += guard.sent;
                total_received += guard.received;
            }
        }

        if found {
            let loss_rate = if total_sent > 0 {
                1.0 - (total_received as f64 / total_sent as f64)
            } else {
                0.0
            };
            Some(PacketLossInfo {
                ip: *ip,
                route_key: None,
                sent: total_sent,
                received: total_received,
                loss_rate,
            })
        } else {
            None
        }
    }

    pub fn get_all_loss_info(&self) -> Vec<PacketLossInfo> {
        let read = self.inner.read();
        read.iter()
            .map(|((ip, route_key), stats)| {
                let guard = stats.lock();
                let loss_rate = if guard.sent > 0 {
                    1.0 - (guard.received as f64 / guard.sent as f64)
                } else {
                    0.0
                };
                PacketLossInfo {
                    ip: *ip,
                    route_key: Some(*route_key),
                    sent: guard.sent,
                    received: guard.received,
                    loss_rate,
                }
            })
            .collect()
    }

    pub fn reset(&self, ip: &Ipv4Addr, route_key: &RouteKey) {
        let read = self.inner.read();
        if let Some(stats) = read.get(&(*ip, *route_key)) {
            *stats.lock() = PingStats::default();
        }
    }

    pub fn remove(&self, ip: &Ipv4Addr, route_key: &RouteKey) {
        let mut write = self.inner.write();
        write.remove(&(*ip, *route_key));
    }

    pub fn remove_batch(&self, keys: &[(Ipv4Addr, RouteKey)]) {
        let mut write = self.inner.write();
        for key in keys {
            write.remove(key);
        }
    }

    pub fn reset_all(&self) {
        let read = self.inner.read();
        for stats in read.values() {
            *stats.lock() = PingStats::default();
        }
    }

    pub fn clear(&self) {
        self.inner.write().clear();
    }
}

pub mod config;
pub(crate) mod nat;

#[derive(Clone, Default)]
pub(crate) struct AppState {
    config: Arc<Mutex<Option<Box<Config>>>>,
    pub(crate) network: SharedNetworkAddr,
    pub(crate) server_info_collection: ServerInfoCollection,
    pub(crate) peer_map: PeerInfoMap,
    pub(crate) route_table: RouteTable,
    pub(crate) subnet_route: SubnetExternalRoute,
    pub(crate) nat_info: MyNatInfo,
    pub(crate) punch_backoff: PunchBackoff,
    pub(crate) packet_loss_stats: PacketLossStats,
    pub(crate) traffic_stats: TrafficStats,
}
#[derive(Clone, Default)]
pub(crate) struct SharedNetworkAddr {
    inner: Arc<Mutex<Option<NetworkAddr>>>,
}
impl SharedNetworkAddr {
    pub fn network(&self) -> Option<Ipv4Net> {
        self.inner.lock().as_ref().map(|v| v.network())
    }
    pub fn ip(&self) -> Option<Ipv4Addr> {
        self.inner.lock().map(|v| v.ip)
    }
    pub fn get(&self) -> Option<NetworkAddr> {
        *self.inner.lock()
    }
    pub fn set(&self, addr: NetworkAddr) {
        *self.inner.lock() = Some(addr);
    }
    pub fn clear(&self) {
        *self.inner.lock() = None;
    }
}

/// 网络路由封装，包含本地网络信息和子网路由
#[derive(Clone)]
pub(crate) struct NetworkRoute {
    pub network: SharedNetworkAddr,
    pub subnet_route: SubnetExternalRoute,
}

impl NetworkRoute {
    pub fn new(network: SharedNetworkAddr, subnet_route: SubnetExternalRoute) -> Self {
        Self {
            network,
            subnet_route,
        }
    }

    /// 检查 IP 是否在本地网络或子网路由中
    pub fn network_contains(&self, ip: &Ipv4Addr) -> bool {
        if let Some(network) = self.network.network()
            && network.contains(ip)
        {
            return true;
        }
        self.subnet_route.route(ip).is_some()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerClientInfo {
    pub nat_info: Option<NatInfo>,
}

#[derive(Clone, Default)]
pub(crate) struct PeerInfoMap {
    inner: Arc<Mutex<HashMap<Ipv4Addr, PeerClientInfo>>>,
}

impl PeerInfoMap {
    pub fn get(&self, ip: &Ipv4Addr) -> Option<PeerClientInfo> {
        self.inner.lock().get(ip).cloned()
    }

    pub fn update_nat_info(&self, ip: Ipv4Addr, nat_info: NatInfo) {
        let mut guard = self.inner.lock();
        if let Some(v) = guard.get_mut(&ip) {
            v.nat_info = Some(nat_info);
            return;
        }
        guard.insert(
            ip,
            PeerClientInfo {
                nat_info: Some(nat_info),
            },
        );
    }

    pub fn clear(&self) {
        self.inner.lock().clear();
    }
}

#[derive(Clone, Default)]
pub(crate) struct ServerInfoCollection {
    client_simple_list: Arc<RwLock<Vec<ClientSimpleInfo>>>,
    server_node_map: Arc<RwLock<HashMap<u32, ServerNodeInfo>>>,
}
#[derive(Clone, Default)]
pub struct ServerNodeInfo {
    pub server_id: u32,
    pub server_addr: ProtocolAddress,
    pub connected: bool,
    pub rtt: Option<u32>,
    pub data_version: u64,
    pub client_map: HashMap<Ipv4Addr, ClientSimpleInfo>,
    pub last_connected_time: Option<i64>,
    pub disconnected_time: Option<i64>,
    pub server_version: Option<String>,
}
impl ServerInfoCollection {
    pub fn server_client_ip_map(&self) -> HashMap<u32, (Vec<Ipv4Addr>, u32)> {
        self.server_node_map
            .read()
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    (
                        v.client_map
                            .iter()
                            .filter(|(_, v)| v.online)
                            .map(|(k, _)| *k)
                            .collect(),
                        v.rtt.unwrap_or(500),
                    ),
                )
            })
            .collect()
    }
    pub fn server_node_list(&self) -> Vec<ServerNodeInfo> {
        self.server_node_map.read().values().cloned().collect()
    }
    pub fn update_server(&self, addr: Vec<(u32, ProtocolAddress)>) {
        let mut server_node_map_guard = self.server_node_map.write();
        let mut client_simple_list_guard = self.client_simple_list.write();
        server_node_map_guard.clear();
        client_simple_list_guard.clear();
        for (server_id, server_addr) in addr {
            let server_node = ServerNodeInfo {
                server_id,
                server_addr,
                ..Default::default()
            };
            server_node_map_guard.insert(server_id, server_node);
        }
    }
    pub fn find_connected_server(&self, server_ids: &[u32]) -> Option<u32> {
        let map = self.server_node_map.read();

        server_ids
            .iter()
            .filter_map(|id| {
                let server = map.get(id)?;

                if !server.connected {
                    return None;
                }

                let rtt = server.rtt.unwrap_or(u32::MAX);

                Some((*id, rtt))
            })
            .min_by_key(|(_, rtt)| *rtt)
            .map(|(id, _)| id)
    }
    pub fn find_ip_to_server(&self, server_ids: &[u32], ip: &Ipv4Addr) -> Option<u32> {
        let map = self.server_node_map.read();

        server_ids
            .iter()
            .filter_map(|id| {
                let server = map.get(id)?;

                if !server.connected {
                    return None;
                }

                let client = server.client_map.get(ip)?;
                if !client.online {
                    return None;
                }

                let rtt = server.rtt.unwrap_or(u32::MAX);

                Some((*id, rtt))
            })
            .min_by_key(|(_, rtt)| *rtt)
            .map(|(id, _)| id)
    }
    pub fn client_online_ips(&self) -> Vec<Ipv4Addr> {
        self.client_simple_list
            .read()
            .iter()
            .filter(|v| v.online)
            .map(|c| c.ip)
            .collect()
    }
    pub fn client_ips(&self) -> Vec<ClientSimpleInfo> {
        self.client_simple_list.read().clone()
    }
    pub fn data_version(&self, server_id: u32) -> u64 {
        self.server_node_map
            .read()
            .get(&server_id)
            .map(|v| v.data_version)
            .unwrap_or(0)
    }
    pub fn update_client_simple_list(
        &self,
        server_id: u32,
        self_ip: Ipv4Addr,
        client_simple_list: ClientSimpleInfoList,
        now: i64,
    ) {
        let mut guard = self.server_node_map.write();
        let server_node = guard.entry(server_id).or_default();
        if now > client_simple_list.time {
            server_node.rtt = Some((now - client_simple_list.time) as u32);
        }
        server_node.data_version = client_simple_list.data_version;
        let map: HashMap<Ipv4Addr, ClientSimpleInfo> = client_simple_list
            .list
            .into_iter()
            .filter(|v| v.ip != self_ip)
            .map(|info| (info.ip, info))
            .collect();

        if client_simple_list.is_all {
            server_node.client_map = map;
        } else {
            server_node.client_map.extend(map);
        }
        let mut client_simple_map = HashMap::<Ipv4Addr, ClientSimpleInfo>::new();
        for (_, server_node) in guard.iter() {
            for (_, x) in server_node.client_map.iter() {
                if let Some(v) = client_simple_map.get_mut(&x.ip) {
                    if x.online {
                        v.online = true;
                    }
                } else {
                    client_simple_map.insert(x.ip, x.clone());
                }
            }
        }

        let mut guard = self.client_simple_list.write();
        *guard = client_simple_map.into_values().collect()
    }
    pub fn set_server_connected(&self, server_id: u32, val: bool) -> bool {
        let mut mutex_guard = self.server_node_map.write();
        let server_node = mutex_guard.entry(server_id).or_default();
        let old = server_node.connected;
        server_node.connected = val;
        old
    }
    pub fn is_any_server_connected(&self, server_ids: Option<&[u32]>) -> bool {
        let guard = self.server_node_map.read();
        if let Some(server_ids) = server_ids {
            for id in server_ids {
                if guard.get(id).map(|v| v.connected).unwrap_or(false) {
                    return true;
                }
            }
        } else {
            for (_, server_node) in guard.iter() {
                if server_node.connected {
                    return true;
                }
            }
        }

        false
    }
    pub fn is_server_connected(&self, server_id: u32) -> bool {
        self.server_node_map
            .read()
            .get(&server_id)
            .map(|v| v.connected)
            .unwrap_or(false)
    }
    pub fn set_last_connected_time(&self, server_id: u32, last_connected_time: Option<i64>) {
        self.server_node_map
            .write()
            .entry(server_id)
            .or_default()
            .last_connected_time = last_connected_time;
    }
    pub fn set_disconnected_time(&self, server_id: u32, last_connected_time: Option<i64>) {
        self.server_node_map
            .write()
            .entry(server_id)
            .or_default()
            .disconnected_time = last_connected_time;
    }
    pub fn set_server_rtt(&self, server_id: u32, rtt: u32) {
        if let Some(v) = self.server_node_map.write().get_mut(&server_id) {
            v.rtt = Some(rtt);
        }
    }
    pub fn set_server_version(&self, server_id: u32, version: String) {
        if let Some(v) = self.server_node_map.write().get_mut(&server_id) {
            v.server_version = Some(version);
        }
    }
    pub fn get_server_rtt(&self, ip: &Ipv4Addr) -> Option<u32> {
        let server_node_map_guard = self.server_node_map.read();
        for (_, server_node) in server_node_map_guard.iter() {
            if !server_node.connected {
                continue;
            }
            if let Some(v) = server_node.client_map.get(ip)
                && v.online
            {
                return server_node.rtt;
            }
        }
        None
    }
    pub fn exists_online_client_ip(&self, ip: &Ipv4Addr) -> bool {
        self.client_simple_list
            .read()
            .iter()
            .any(|v| v.ip == *ip && v.online)
    }
    pub fn clear(&self) {
        self.client_simple_list.write().clear();
        let mut guard = self.server_node_map.write();
        for server_node in guard.values_mut() {
            server_node.connected = false;
            server_node.rtt = None;
            server_node.data_version = 0;
            server_node.client_map.clear();
            server_node.last_connected_time = None;
            server_node.disconnected_time = None;
        }
    }
}
#[derive(Copy, Clone, Debug)]
pub struct NetworkAddr {
    pub gateway: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
}
impl NetworkAddr {
    pub fn network(&self) -> Ipv4Net {
        Ipv4Net::new_assert(self.ip, self.prefix_len)
    }
}

impl AppState {
    pub fn stop_network(&self) {
        self.network.clear();
        self.server_info_collection.clear();
        self.peer_map.clear();
        // route_table 来自外部 crate，会在任务停止后自动失效
        self.nat_info.clear();
        self.punch_backoff.clear();
        self.packet_loss_stats.clear();
        self.traffic_stats.clear();
    }

    fn network(&self) -> Option<Ipv4Net> {
        self.network.network()
    }
    pub fn get_network(&self) -> Option<NetworkAddr> {
        self.network.get()
    }
    fn network_contains(&self, ip: &Ipv4Addr) -> bool {
        let Some(network) = self.network() else {
            return false;
        };
        if network.contains(ip) {
            return true;
        }
        self.subnet_route.route(ip).is_some()
    }
    pub fn client_ips(&self) -> Vec<ClientSimpleInfo> {
        self.server_info_collection.client_ips()
    }
    pub fn get_peer_info(&self, ip: &Ipv4Addr) -> Option<PeerClientInfo> {
        self.peer_map.get(ip)
    }

    pub fn set_config(&self, config: Box<Config>) {
        *self.config.lock() = Some(config);
    }

    pub fn get_config(&self) -> Option<Box<Config>> {
        self.config.lock().clone()
    }
    pub(crate) fn udp_stun(&self) -> Vec<String> {
        self.config
            .lock()
            .as_ref()
            .map(|v| v.udp_stun.clone())
            .unwrap_or_default()
    }
    pub(crate) fn tcp_stun(&self) -> Vec<String> {
        self.config
            .lock()
            .as_ref()
            .map(|v| v.tcp_stun.clone())
            .unwrap_or_default()
    }
}
impl AppState {
    pub fn get_punch_info(&self) -> Option<PunchInfo> {
        self.nat_info.get().map(|info| PunchInfo {
            nat_info: self.filter_ip(info),
        })
    }
    pub fn get_nat_info(&self) -> Option<NatInfo> {
        self.nat_info.get().map(|info| self.filter_ip(info))
    }
    pub fn filter_ip(&self, mut info: NatInfo) -> NatInfo {
        if self.network_contains(&info.local_ipv4) {
            info.local_ipv4 = Ipv4Addr::UNSPECIFIED;
        }
        info.local_ipv4s.retain(|ip| !self.network_contains(ip));
        info
    }
}
