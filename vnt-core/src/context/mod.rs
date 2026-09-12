use crate::context::config::{Config, punch_model_for};
use crate::context::nat::{MyNatInfo, PunchBackoff};
use crate::nat::SubnetExternalRoute;
use crate::protocol::client_message::PunchInfo;
use crate::protocol::control_message::{
    ClientSimpleInfo, ClientSimpleInfoList, ClientType, SubnetSyncResponse,
};
use crate::tunnel_core::p2p::node_info::NodeInfoMap;
use crate::tunnel_core::p2p::route_table::RouteTable;
use crate::tunnel_core::server::transport::config::ProtocolAddress;
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use rustp2p_core::nat::NatInfo;
use rustp2p_core::route_table::RouteKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
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

type PingStatsMap = HashMap<(Ipv4Addr, RouteKey), Arc<Mutex<PingStats>>>;

#[derive(Clone, Default)]
pub struct PacketLossStats {
    inner: Arc<RwLock<PingStatsMap>>,
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
    pub(crate) node_info_map: NodeInfoMap,
    pub(crate) subnet_route: SubnetExternalRoute,
    pub(crate) nat_info: MyNatInfo,
    pub(crate) punch_backoff: PunchBackoff,
    pub(crate) packet_loss_stats: PacketLossStats,
    pub(crate) traffic_stats: TrafficStats,
    p2p_listen_addrs: Arc<Mutex<Vec<TunnelListenAddr>>>,
}

/// A local P2P transport listener that was successfully bound at startup.
#[derive(Clone, Debug)]
pub struct TunnelListenAddr {
    pub protocol: &'static str,
    pub addr: SocketAddr,
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

    /// Validate a server registration against the locally active network and
    /// adopt the first real server gateway. This is atomic so concurrently
    /// connecting servers cannot install different gateways.
    pub fn reconcile_server(&self, ip: Ipv4Addr, prefix_len: u8, gateway: Ipv4Addr) -> bool {
        let Ok(network) = Ipv4Net::new(ip, prefix_len) else {
            return false;
        };
        if !network.contains(&gateway)
            || gateway == ip
            || gateway == network.network()
            || gateway == network.broadcast()
        {
            return false;
        }
        let mut guard = self.inner.lock();
        let Some(current) = guard.as_mut() else {
            return false;
        };
        if current.ip != ip || current.prefix_len != prefix_len {
            return false;
        }
        match current.gateway {
            Some(existing) => existing == gateway,
            None => {
                current.gateway = Some(gateway);
                true
            }
        }
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

    /// 更新对端 NAT 信息；返回 true 表示发生了“身份级”变化
    /// （网络切换/NAT 重启等，对称 NAT 的端口抖动不算）。
    pub fn update_nat_info(&self, ip: Ipv4Addr, nat_info: NatInfo) -> bool {
        let mut guard = self.inner.lock();
        if let Some(v) = guard.get_mut(&ip) {
            let changed = v
                .nat_info
                .as_ref()
                .is_some_and(|old| nat::nat_identity_changed(old, &nat_info));
            v.nat_info = Some(nat_info);
            return changed;
        }
        guard.insert(
            ip,
            PeerClientInfo {
                nat_info: Some(nat_info),
            },
        );
        false
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
    pub subnet_sync_supported: bool,
    pub subnet_snapshot_hash: Vec<u8>,
    pub subnet_nodes: HashMap<Ipv4Addr, Vec<Ipv4Net>>,
}
impl ServerInfoCollection {
    pub fn server_client_ip_map(&self) -> HashMap<u32, (Vec<Ipv4Addr>, u32)> {
        self.server_node_map
            .read()
            .iter()
            .filter(|(_, server)| server.connected)
            .map(|(k, v)| {
                (
                    *k,
                    (
                        v.client_map
                            .iter()
                            .filter(|(_, v)| v.online && v.client_type == ClientType::Vnt)
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
            .filter(|v| v.online && v.client_type == ClientType::Vnt)
            .map(|c| c.ip)
            .collect()
    }
    pub fn client_ips(&self) -> Vec<ClientSimpleInfo> {
        self.client_simple_list.read().clone()
    }
    pub(crate) fn client_type(&self, ip: &Ipv4Addr) -> Option<ClientType> {
        self.client_simple_list
            .read()
            .iter()
            .find(|client| client.ip == *ip && client.online)
            .map(|client| client.client_type)
    }
    pub fn data_version(&self, server_id: u32) -> u64 {
        self.server_node_map
            .read()
            .get(&server_id)
            .map(|v| v.data_version)
            .unwrap_or(0)
    }
    pub fn subnet_sync_request_hash(&self, server_id: u32) -> Option<Vec<u8>> {
        self.server_node_map
            .read()
            .get(&server_id)
            .filter(|server| server.connected && server.subnet_sync_supported)
            .map(|server| server.subnet_snapshot_hash.clone())
    }
    pub fn set_subnet_sync_supported(&self, server_id: u32, supported: bool) {
        let mut guard = self.server_node_map.write();
        let server = guard.entry(server_id).or_default();
        server.subnet_sync_supported = supported;
        if !supported {
            server.subnet_snapshot_hash.clear();
            server.subnet_nodes.clear();
        }
    }
    pub fn update_subnet_snapshot(&self, server_id: u32, response: SubnetSyncResponse) {
        let mut guard = self.server_node_map.write();
        let server = guard.entry(server_id).or_default();
        server.subnet_snapshot_hash = response.snapshot_hash;
        server.subnet_nodes = response
            .nodes
            .into_iter()
            .map(|node| (node.ip, node.subnets))
            .collect();
    }
    pub fn automatic_subnet_routes(
        &self,
        self_ip: Ipv4Addr,
        static_routes: &[crate::nat::NetInput],
    ) -> Vec<crate::nat::NetInput> {
        let guard = self.server_node_map.read();
        let mut declarations = Vec::<(Ipv4Addr, Ipv4Net)>::new();
        for server in guard.values().filter(|server| server.connected) {
            for (ip, subnets) in &server.subnet_nodes {
                if *ip == self_ip {
                    continue;
                }
                for subnet in subnets {
                    if !declarations.contains(&(*ip, *subnet)) {
                        declarations.push((*ip, *subnet));
                    }
                }
            }
        }
        declarations
            .sort_by_key(|(ip, net)| (u32::from(*ip), u32::from(net.network()), net.prefix_len()));

        let mut claimed = std::collections::HashSet::<Ipv4Net>::new();
        declarations
            .into_iter()
            // Sorting by node IP above makes an identical CIDR prefer the
            // smallest node. Different overlapping CIDRs remain valid LPM entries.
            .filter(|(_, subnet)| {
                claimed.insert(*subnet)
                    && !static_routes
                        .iter()
                        .any(|route| ipv4_nets_overlap(route.net, *subnet))
            })
            .map(|(target_ip, net)| crate::nat::NetInput { net, target_ip })
            .collect()
    }
    pub fn update_client_simple_list(
        &self,
        server_id: u32,
        self_ip: Ipv4Addr,
        client_simple_list: ClientSimpleInfoList,
        now: i64,
    ) -> Vec<Ipv4Addr> {
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
        let client_simple_map = merged_client_simple_map(&guard);

        let mut guard = self.client_simple_list.write();
        let previous_online: HashMap<Ipv4Addr, bool> =
            guard.iter().map(|info| (info.ip, info.online)).collect();
        let mut changed = Vec::new();
        for (ip, info) in &client_simple_map {
            if previous_online.get(ip).copied().unwrap_or(false) != info.online {
                changed.push(*ip);
            }
        }
        for (ip, was_online) in previous_online {
            if was_online && !client_simple_map.contains_key(&ip) {
                changed.push(ip);
            }
        }
        *guard = client_simple_map.into_values().collect();
        changed
    }
    pub fn set_server_connected(&self, server_id: u32, val: bool) -> bool {
        let mut mutex_guard = self.server_node_map.write();
        let server_node = mutex_guard.entry(server_id).or_default();
        let old = server_node.connected;
        server_node.connected = val;
        if !val {
            // Keep historical entries for device lists, but never reactivate
            // them merely because the transport reconnects. Version zero asks
            // the server for a fresh snapshot after registration.
            server_node.data_version = 0;
            for client in server_node.client_map.values_mut() {
                client.online = false;
            }
            server_node.subnet_snapshot_hash.clear();
            server_node.subnet_nodes.clear();
        }
        let clients = merged_client_simple_map(&mutex_guard)
            .into_values()
            .collect();
        *self.client_simple_list.write() = clients;
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
            for server_node in guard.values() {
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
        for server_node in server_node_map_guard.values() {
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
    #[cfg(test)]
    fn exists_online_client_ip(&self, ip: &Ipv4Addr) -> bool {
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
            server_node.subnet_sync_supported = false;
            server_node.subnet_snapshot_hash.clear();
            server_node.subnet_nodes.clear();
        }
    }
}

/// Merge server snapshots without treating a disconnected server's cached
/// state as current reachability. The cached maps themselves are retained so
/// reconnecting servers can continue incremental synchronization.
fn merged_client_simple_map(
    servers: &HashMap<u32, ServerNodeInfo>,
) -> HashMap<Ipv4Addr, ClientSimpleInfo> {
    let mut clients = HashMap::<Ipv4Addr, ClientSimpleInfo>::new();
    // Connected snapshots are authoritative. Prefer an online snapshot's
    // metadata when connected servers temporarily disagree about one IP.
    for server in servers.values().filter(|server| server.connected) {
        for snapshot in server.client_map.values() {
            if let Some(client) = clients.get_mut(&snapshot.ip) {
                let was_online = client.online;
                let prefer_snapshot = (snapshot.online && !was_online)
                    || (snapshot.online == was_online
                        && snapshot.client_type as i32 > client.client_type as i32);
                if prefer_snapshot {
                    *client = snapshot.clone();
                }
                client.online = was_online || snapshot.online;
            } else {
                clients.insert(snapshot.ip, snapshot.clone());
            }
        }
    }
    // Retain disconnected snapshots only as offline history. They must never
    // overwrite metadata supplied by a currently connected server.
    for server in servers.values().filter(|server| !server.connected) {
        for snapshot in server.client_map.values() {
            clients.entry(snapshot.ip).or_insert_with(|| {
                let mut client = snapshot.clone();
                client.online = false;
                client
            });
        }
    }
    clients
}

fn ipv4_nets_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

#[cfg(test)]
mod subnet_sync_tests {
    use super::ServerInfoCollection;
    use crate::nat::NetInput;
    use crate::protocol::control_message::{NodeSubnetRoutes, SubnetSyncResponse};
    use crate::tunnel_core::server::transport::config::ProtocolAddress;

    #[test]
    fn overlaps_are_kept_and_exact_duplicates_prefer_smallest_node_ip() {
        let servers = ServerInfoCollection::default();
        servers.update_server(vec![
            (0, ProtocolAddress::default()),
            (1, ProtocolAddress::default()),
        ]);
        servers.set_server_connected(0, true);
        servers.set_server_connected(1, true);
        servers.update_subnet_snapshot(
            0,
            SubnetSyncResponse {
                snapshot_hash: vec![1],
                nodes: vec![NodeSubnetRoutes {
                    ip: "10.26.0.2".parse().unwrap(),
                    subnets: vec![
                        "192.168.0.0/24".parse().unwrap(),
                        "172.16.0.0/24".parse().unwrap(),
                    ],
                }],
            },
        );
        servers.update_subnet_snapshot(
            1,
            SubnetSyncResponse {
                snapshot_hash: vec![2],
                nodes: vec![NodeSubnetRoutes {
                    ip: "10.26.0.4".parse().unwrap(),
                    subnets: vec![
                        "192.168.0.0/25".parse().unwrap(),
                        "192.168.0.0/24".parse().unwrap(),
                    ],
                }],
            },
        );

        let routes = servers.automatic_subnet_routes("10.26.0.3".parse().unwrap(), &[]);
        assert_eq!(routes.len(), 3);
        let duplicate = routes
            .iter()
            .find(|route| route.net == "192.168.0.0/24".parse().unwrap())
            .unwrap();
        assert_eq!(
            duplicate.target_ip,
            "10.26.0.2".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert!(
            routes
                .iter()
                .any(|route| route.net == "192.168.0.0/25".parse().unwrap())
        );
    }

    #[test]
    fn static_routes_override_whole_overlapping_automatic_declarations() {
        let servers = ServerInfoCollection::default();
        servers.update_server(vec![(0, ProtocolAddress::default())]);
        servers.set_server_connected(0, true);
        servers.update_subnet_snapshot(
            0,
            SubnetSyncResponse {
                snapshot_hash: vec![1],
                nodes: vec![NodeSubnetRoutes {
                    ip: "10.26.0.2".parse().unwrap(),
                    subnets: vec!["192.168.0.0/24".parse().unwrap()],
                }],
            },
        );
        let static_routes = vec![NetInput {
            net: "192.168.0.128/25".parse().unwrap(),
            target_ip: "10.26.0.9".parse().unwrap(),
        }];
        assert!(
            servers
                .automatic_subnet_routes("10.26.0.3".parse().unwrap(), &static_routes)
                .is_empty()
        );
    }
}

#[cfg(test)]
mod client_status_tests {
    use super::ServerInfoCollection;
    use crate::protocol::control_message::{ClientSimpleInfo, ClientSimpleInfoList, ClientType};
    use crate::tunnel_core::server::transport::config::ProtocolAddress;
    use std::net::Ipv4Addr;

    fn update(servers: &ServerInfoCollection, peer: Ipv4Addr, online: bool) -> Vec<Ipv4Addr> {
        servers.update_client_simple_list(
            0,
            Ipv4Addr::new(10, 26, 0, 1),
            ClientSimpleInfoList {
                data_version: 1,
                list: vec![ClientSimpleInfo {
                    ip: peer,
                    online,
                    client_type: ClientType::Vnt,
                }],
                is_all: true,
                time: 0,
            },
            0,
        )
    }

    #[test]
    fn online_transitions_are_reported_once() {
        let servers = ServerInfoCollection::default();
        servers.update_server(vec![(0, ProtocolAddress::default())]);
        servers.set_server_connected(0, true);
        let peer = Ipv4Addr::new(10, 26, 0, 2);

        assert_eq!(update(&servers, peer, true), vec![peer]);
        assert!(update(&servers, peer, true).is_empty());
        assert_eq!(update(&servers, peer, false), vec![peer]);
        assert!(update(&servers, peer, false).is_empty());
        assert_eq!(update(&servers, peer, true), vec![peer]);
    }

    #[test]
    fn disappearing_from_full_snapshot_is_one_offline_transition() {
        let servers = ServerInfoCollection::default();
        servers.update_server(vec![(0, ProtocolAddress::default())]);
        servers.set_server_connected(0, true);
        let peer = Ipv4Addr::new(10, 26, 0, 2);
        assert_eq!(update(&servers, peer, true), vec![peer]);

        let empty_snapshot = || ClientSimpleInfoList {
            data_version: 2,
            list: Vec::new(),
            is_all: true,
            time: 0,
        };
        assert_eq!(
            servers.update_client_simple_list(0, Ipv4Addr::new(10, 26, 0, 1), empty_snapshot(), 0,),
            vec![peer]
        );
        assert!(
            servers
                .update_client_simple_list(0, Ipv4Addr::new(10, 26, 0, 1), empty_snapshot(), 0,)
                .is_empty()
        );
    }

    #[test]
    fn relay_clients_keep_their_type_and_are_excluded_from_p2p_targets() {
        let servers = ServerInfoCollection::default();
        servers.update_server(vec![
            (0, ProtocolAddress::default()),
            (1, ProtocolAddress::default()),
        ]);
        let self_ip = Ipv4Addr::new(10, 26, 0, 1);
        let ikev2 = Ipv4Addr::new(10, 26, 0, 2);
        let wireguard = Ipv4Addr::new(10, 26, 0, 3);
        servers.set_server_connected(0, true);
        servers.set_server_connected(1, true);
        for (server_id, ip, client_type) in [
            (0, ikev2, ClientType::Ikev2),
            (1, wireguard, ClientType::Wireguard),
        ] {
            servers.update_client_simple_list(
                server_id,
                self_ip,
                ClientSimpleInfoList {
                    data_version: 1,
                    list: vec![ClientSimpleInfo {
                        ip,
                        online: true,
                        client_type,
                    }],
                    is_all: true,
                    time: 0,
                },
                0,
            );
        }

        assert_eq!(servers.client_type(&ikev2), Some(ClientType::Ikev2));
        assert_eq!(servers.client_type(&wireguard), Some(ClientType::Wireguard));
        assert!(!servers.client_online_ips().contains(&ikev2));
        assert!(!servers.client_online_ips().contains(&wireguard));
    }

    #[test]
    fn disconnected_server_snapshot_is_retained_but_not_reachable() {
        let servers = ServerInfoCollection::default();
        servers.update_server(vec![(0, ProtocolAddress::default())]);
        let peer = Ipv4Addr::new(10, 26, 0, 2);

        servers.set_server_connected(0, true);
        assert_eq!(update(&servers, peer, true), vec![peer]);
        assert!(servers.exists_online_client_ip(&peer));
        assert!(servers.server_client_ip_map().contains_key(&0));

        servers.set_server_connected(0, false);
        assert!(!servers.exists_online_client_ip(&peer));
        assert!(servers.server_client_ip_map().is_empty());
        let cached = servers
            .client_ips()
            .into_iter()
            .find(|client| client.ip == peer)
            .expect("disconnected snapshots remain available as offline history");
        assert!(!cached.online);

        servers.set_server_connected(0, true);
        assert!(!servers.exists_online_client_ip(&peer));
        assert_eq!(update(&servers, peer, true), vec![peer]);
        assert!(servers.exists_online_client_ip(&peer));
    }

    #[test]
    fn disconnected_server_metadata_does_not_override_connected_snapshot() {
        let servers = ServerInfoCollection::default();
        servers.update_server(vec![
            (0, ProtocolAddress::default()),
            (1, ProtocolAddress::default()),
        ]);
        let peer = Ipv4Addr::new(10, 26, 0, 2);

        servers.set_server_connected(0, true);
        servers.set_server_connected(1, true);
        servers.update_client_simple_list(
            0,
            Ipv4Addr::new(10, 26, 0, 1),
            ClientSimpleInfoList {
                data_version: 1,
                list: vec![ClientSimpleInfo {
                    ip: peer,
                    client_type: ClientType::Vnt,
                    online: true,
                }],
                is_all: true,
                time: 0,
            },
            0,
        );
        servers.update_client_simple_list(
            1,
            Ipv4Addr::new(10, 26, 0, 1),
            ClientSimpleInfoList {
                data_version: 1,
                list: vec![ClientSimpleInfo {
                    ip: peer,
                    client_type: ClientType::Wireguard,
                    online: true,
                }],
                is_all: true,
                time: 0,
            },
            0,
        );

        servers.set_server_connected(1, false);

        let client = servers
            .client_ips()
            .into_iter()
            .find(|client| client.ip == peer)
            .unwrap();
        assert!(client.online);
        assert_eq!(client.client_type, ClientType::Vnt);
    }
}
#[derive(Copy, Clone, Debug)]
pub struct NetworkAddr {
    pub gateway: Option<Ipv4Addr>,
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
        self.route_table.clear();
        self.node_info_map.clear();
        self.nat_info.clear();
        self.punch_backoff.clear();
        self.packet_loss_stats.clear();
        self.traffic_stats.clear();
        self.p2p_listen_addrs.lock().clear();
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
    pub(crate) fn set_p2p_listen_addrs(&self, addrs: Vec<TunnelListenAddr>) {
        *self.p2p_listen_addrs.lock() = addrs;
    }
    pub fn p2p_listen_addrs(&self) -> Vec<TunnelListenAddr> {
        self.p2p_listen_addrs.lock().clone()
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

#[cfg(test)]
mod optional_gateway_tests {
    use super::{NetworkAddr, SharedNetworkAddr};
    use std::net::Ipv4Addr;

    #[test]
    fn first_matching_server_supplies_gateway_and_later_servers_must_match() {
        let shared = SharedNetworkAddr::default();
        shared.set(NetworkAddr {
            gateway: None,
            broadcast: "10.26.0.255".parse().unwrap(),
            ip: "10.26.0.2".parse().unwrap(),
            prefix_len: 24,
        });
        let gateway = Ipv4Addr::new(10, 26, 0, 1);
        assert!(shared.reconcile_server("10.26.0.2".parse().unwrap(), 24, gateway));
        assert_eq!(shared.get().unwrap().gateway, Some(gateway));
        assert!(!shared.reconcile_server(
            "10.26.0.2".parse().unwrap(),
            24,
            "10.26.0.254".parse().unwrap()
        ));
        assert!(!shared.reconcile_server("10.26.0.2".parse().unwrap(), 16, gateway));
    }
}
impl AppState {
    pub fn get_punch_info(&self, target: Ipv4Addr) -> Option<PunchInfo> {
        let punch_model = self
            .config
            .lock()
            .as_ref()
            .map(|config| punch_model_for(&config.punch_model, &target))
            .unwrap_or_else(rustp2p_core::punch::PunchPolicySet::all);
        self.nat_info.get().map(|info| PunchInfo {
            nat_info: self.filter_ip(info),
            punch_model,
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
