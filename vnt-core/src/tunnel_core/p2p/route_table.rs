use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use rustp2p_core::punch::{PunchPolicy, PunchPolicySet};
use rustp2p_core::route_table::{DEFAULT_RTT, Protocol, RouteKey};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeInfo {
    pub ip: Ipv4Addr,
    pub name: String,
    pub version: String,
    pub advertised_subnets: Vec<Ipv4Net>,
}

#[derive(Clone, Debug)]
pub struct DirectPeerInfo {
    pub node_ip: Ipv4Addr,
    pub identity: Option<NodeInfo>,
}

#[derive(Clone, Debug)]
pub struct RouteEntryInfo {
    pub node: NodeInfo,
    pub refreshed_at: Instant,
}

#[derive(Copy, Clone, Debug)]
pub struct Route {
    route_key: RouteKey,
    metric: u8,
    rtt: u32,
    /// 丢包率，万分率（0-10000，10000 表示 100% 丢包）
    loss_rate: u16,
    /// 路由评分
    score: u32,
}
impl Route {
    pub fn from(route_key: RouteKey, metric: u8, rtt: u32) -> Self {
        let is_relay = metric > 1;
        let score = get_channel_score(rtt, 0, is_relay, route_key.protocol().is_tcp())
            / u32::from(metric.max(1));
        Self {
            route_key,
            metric,
            rtt,
            loss_rate: 0,
            score,
        }
    }
    pub fn from_with_loss(route_key: RouteKey, metric: u8, rtt: u32, loss_rate: u16) -> Self {
        let is_relay = metric > 1;
        let score = get_channel_score(
            rtt,
            loss_rate as u32,
            is_relay,
            route_key.protocol().is_tcp(),
        ) / u32::from(metric.max(1));
        Self {
            route_key,
            metric,
            rtt,
            loss_rate,
            score,
        }
    }
    pub fn from_default_rt(route_key: RouteKey, metric: u8) -> Self {
        let is_relay = metric > 1;
        let score = get_channel_score(DEFAULT_RTT, 0, is_relay, route_key.protocol().is_tcp())
            / u32::from(metric.max(1));
        Self {
            route_key,
            metric,
            rtt: DEFAULT_RTT,
            loss_rate: 0,
            score,
        }
    }
    pub fn route_key(&self) -> RouteKey {
        self.route_key
    }

    pub fn is_direct(&self) -> bool {
        self.metric == 1
    }
    pub fn rtt(&self) -> u32 {
        self.rtt
    }
    pub fn metric(&self) -> u8 {
        self.metric
    }
    pub fn loss_rate(&self) -> u16 {
        self.loss_rate
    }
    pub fn score(&self) -> u32 {
        self.score
    }
}

/// 计算路由评分
///
/// # 参数
/// - `rtt`: 往返时延（毫秒）
/// - `loss_v`: 丢包率（万分率，0-10000）
/// - `is_relay`: 是否为中继路由
/// - `is_tcp`: 是否为 TCP 路由，TCP 权重略高，使同质量下 TCP 评分稍高
///
/// # 返回
/// 评分值，越高表示路由质量越好
pub fn get_channel_score(rtt: u32, loss_v: u32, is_relay: bool, is_tcp: bool) -> u32 {
    let rtt = rtt.max(1);
    let loss_v = loss_v.min(10000);

    // 权重配置
    let base_weight = if is_relay { 100 } else { 120 };
    // TCP 权重略高（+5），质量相当时优先选择 TCP 路由
    let weight = if is_tcp { base_weight + 5 } else { base_weight };
    let k_adj = 10; // 丢包惩罚系数

    // 用 u64 计算避免溢出：分母最大 rtt * 110000，rtt > 约39s 时 u32 溢出
    // 分子：代表"有效做功"的放大值
    let numerator = weight as u64 * (10000 - loss_v) as u64 * 100;

    // 分母：代表"链路阻力"
    let denominator = rtt as u64 * (10000 + loss_v * k_adj) as u64;

    (numerator / denominator).min(u32::MAX as u64) as u32
}

#[derive(Clone)]
pub struct RouteTable {
    inner: Arc<RouteTableInner>,
}

#[derive(Default)]
struct RouteTableInner {
    route_table: RwLock<HashMap<Ipv4Addr, Vec<Route>>>,
    route_key_time: Mutex<HashMap<(Ipv4Addr, RouteKey), Instant>>,
    route_key_owner: Mutex<HashMap<RouteKey, Ipv4Addr>>,
    direct_peer_info: Mutex<HashMap<RouteKey, DirectPeerInfo>>,
    route_info: Mutex<HashMap<(Ipv4Addr, RouteKey), RouteEntryInfo>>,
    first_direct_route_notify: Arc<tokio::sync::Notify>,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RouteTableInner::default()),
        }
    }

    pub fn first_direct_route_notify(&self) -> Arc<tokio::sync::Notify> {
        self.inner.first_direct_route_notify.clone()
    }

    /// 获取指定 ID 的最优路由
    pub fn get_route_by_id(&self, id: &Ipv4Addr) -> anyhow::Result<Route> {
        self.inner
            .get_by_id(id)
            .ok_or_else(|| anyhow::anyhow!("route not found for {}", id))
    }

    /// 获取指定节点评分最高的直连路由，不受中继路由评分排序影响。
    pub fn get_direct_route_by_id(&self, id: &Ipv4Addr) -> Option<Route> {
        let guard = self.inner.route_table.read();
        best_direct_route(guard.get(id)?)
    }

    /// 检查是否存在到指定 ID 的路由
    pub fn exists(&self, id: &Ipv4Addr) -> bool {
        self.inner.get_by_id(id).is_some()
    }

    /// 返回配置允许、但当前尚未建立直连路由的打洞类型。
    pub fn missing_punch_policies(
        &self,
        id: &Ipv4Addr,
        configured: &PunchPolicySet,
    ) -> PunchPolicySet {
        let guard = self.inner.route_table.read();
        let routes = guard.get(id).map(Vec::as_slice).unwrap_or_default();
        let mut missing = PunchPolicySet::empty();
        for policy in [
            PunchPolicy::IPv4Tcp,
            PunchPolicy::IPv4Udp,
            PunchPolicy::IPv6Tcp,
            PunchPolicy::IPv6Udp,
        ] {
            if configured.is_match(policy)
                && !routes
                    .iter()
                    .any(|route| direct_route_matches_policy(route, policy))
            {
                missing.or(policy);
            }
        }
        missing
    }

    /// 获取直连路由数量（用于判断是否直连）
    pub fn p2p_num(&self, id: &Ipv4Addr) -> usize {
        let guard = self.inner.route_table.read();
        let Some(list) = guard.get(id) else {
            return 0;
        };
        list.iter().filter(|r| r.is_direct()).count()
    }

    /// 检查指定传输协议和物理地址是否已有直连路由。
    pub fn has_direct_endpoint(&self, protocol: Protocol, address: SocketAddr) -> bool {
        let guard = self.inner.route_table.read();
        guard.values().any(|routes| {
            routes.iter().any(|route| {
                route.is_direct()
                    && route.route_key().protocol() == protocol
                    && route.route_key().peer_addr() == address
            })
        })
    }

    /// 添加 owner 路由（打洞请求响应时调用）
    pub fn add_owner_route(&self, id: Ipv4Addr, key: RouteKey) -> bool {
        // A concurrent periodic announcement may arrive ahead of PunchRes.
        // Keep identity already learned on this same physical route.
        let early_identity = self
            .inner
            .route_info
            .lock()
            .get(&(id, key))
            .map(|entry| entry.node.clone());
        self.inner
            .direct_peer_info
            .lock()
            .entry(key)
            .or_insert_with(|| DirectPeerInfo {
                node_ip: id,
                identity: early_identity,
            });
        let first_direct = self.inner.add_owner_route(id, key);
        if first_direct {
            self.inner.first_direct_route_notify.notify_one();
        }
        first_direct
    }

    /// Adds a direct peer together with identity learned from a direct
    /// handshake. A compact punch or legacy handshake may add the owner first
    /// and fill this identity later through NodeAnnouncement.
    pub fn add_identified_owner_route(&self, node: NodeInfo, key: RouteKey) -> bool {
        let newly_identified = self
            .inner
            .direct_peer_info
            .lock()
            .insert(
                key,
                DirectPeerInfo {
                    node_ip: node.ip,
                    identity: Some(node.clone()),
                },
            )
            .is_none_or(|previous| previous.identity.is_none());
        self.inner.route_info.lock().insert(
            (node.ip, key),
            RouteEntryInfo {
                node: node.clone(),
                refreshed_at: Instant::now(),
            },
        );
        let first_direct = self.inner.add_owner_route(node.ip, key);
        if first_direct || newly_identified {
            self.inner.first_direct_route_notify.notify_one();
        }
        first_direct
    }

    pub fn add_gossip_route(&self, node: NodeInfo, route: Route) {
        if route.metric() > 15 {
            return;
        }
        self.inner.route_info.lock().insert(
            (node.ip, route.route_key()),
            RouteEntryInfo {
                node: node.clone(),
                refreshed_at: Instant::now(),
            },
        );
        if route.is_direct() {
            let owner = self
                .inner
                .route_key_owner
                .lock()
                .get(&route.route_key())
                .copied();
            if owner == Some(node.ip)
                && let Some(peer) = self
                    .inner
                    .direct_peer_info
                    .lock()
                    .get_mut(&route.route_key())
            {
                peer.identity = Some(node.clone());
            }
        }
        self.inner.add_route(node.ip, route, true, false);
    }

    pub fn direct_routes(&self, exclude: Option<&RouteKey>) -> Vec<RouteKey> {
        let owners = self.inner.route_key_owner.lock().clone();
        let peers = self.inner.direct_peer_info.lock();
        let excluded_node = exclude.and_then(|key| owners.get(key).copied());
        peers
            .iter()
            .filter_map(|(key, peer)| {
                (owners.get(key).is_some_and(|owner| *owner == peer.node_ip)
                    && exclude != Some(key)
                    && excluded_node != Some(peer.node_ip))
                .then_some(*key)
            })
            .collect()
    }

    pub fn node_info(&self, id: &Ipv4Addr) -> Option<NodeInfo> {
        let route = self.get_route_by_id(id).ok()?;
        self.inner
            .route_info
            .lock()
            .get(&(*id, route.route_key()))
            .map(|entry| {
                let _refreshed_at = entry.refreshed_at;
                entry.node.clone()
            })
    }

    pub fn node_infos(&self) -> Vec<NodeInfo> {
        let ids: Vec<_> = self.inner.route_table.read().keys().copied().collect();
        ids.into_iter()
            .filter_map(|id| self.node_info(&id))
            .collect()
    }

    /// 添加路由（心跳时调用，用于更新路由时间和添加跨节点转发路由）
    pub fn add_route(&self, id: Ipv4Addr, route: Route, is_default: bool) {
        if let Some(info) = self
            .inner
            .route_info
            .lock()
            .get_mut(&(id, route.route_key()))
        {
            info.refreshed_at = Instant::now();
        }
        if self.inner.add_route(id, route, false, is_default) {
            self.inner.first_direct_route_notify.notify_one();
        }
    }

    /// 添加由 RelayProbe 验证得到的中继路由，允许为目标建立第一条路由。
    pub fn add_relay_route(&self, id: Ipv4Addr, route: Route) {
        if route.is_direct() {
            return;
        }
        self.inner.add_route(id, route, true, true);
    }

    /// 获取所有路由表
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        let guard = self.inner.route_table.read();
        guard.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// Removes every logical route carried by one physical tunnel.
    pub fn remove_route_key(&self, route_key: &RouteKey) -> Vec<(Ipv4Addr, RouteKey)> {
        let mut table = self.inner.route_table.write();
        let mut owner_map = self.inner.route_key_owner.lock();
        let mut time_map = self.inner.route_key_time.lock();
        let mut removed = Vec::new();

        table.retain(|id, routes| {
            let old_len = routes.len();
            routes.retain(|route| route.route_key() != *route_key);
            if routes.len() != old_len {
                removed.push((*id, *route_key));
            }
            !routes.is_empty()
        });
        owner_map.remove(route_key);
        time_map.retain(|(_, key), _| key != route_key);
        self.inner.direct_peer_info.lock().remove(route_key);
        self.inner
            .route_info
            .lock()
            .retain(|(_, key), _| key != route_key);
        removed
    }

    /// 移除过期的路由
    pub fn remove_oldest_route(&self, expired_time: Instant) -> Vec<(Ipv4Addr, RouteKey)> {
        self.inner.remove_oldest_route(expired_time)
    }

    pub fn clear(&self) {
        self.inner.route_table.write().clear();
        self.inner.route_key_time.lock().clear();
        self.inner.route_key_owner.lock().clear();
        self.inner.direct_peer_info.lock().clear();
        self.inner.route_info.lock().clear();
    }
}

impl RouteTableInner {
    fn get_by_id(&self, id: &Ipv4Addr) -> Option<Route> {
        let guard = self.route_table.read();
        let list = guard.get(id)?;
        list.first().cloned()
    }

    fn add_owner_route(&self, id: Ipv4Addr, key: RouteKey) -> bool {
        self.route_key_owner.lock().insert(key, id);
        self.add_route(id, Route::from_default_rt(key, 1), false, false)
    }

    fn add_route(
        &self,
        id: Ipv4Addr,
        route: Route,
        allow_relay_bootstrap: bool,
        is_default: bool,
    ) -> bool {
        let key = route.route_key();
        let mut guard = self.route_table.write();
        let had_direct = guard
            .get(&id)
            .is_some_and(|routes| routes.iter().any(Route::is_direct));

        // 检查是否是 owner 路由
        let mut route_key_owner = self.route_key_owner.lock();
        if route.is_direct() {
            route_key_owner.entry(key).or_insert(id);
        } else if !allow_relay_bootstrap && !guard.contains_key(&id) {
            return false;
        }

        // 更新时间
        self.route_key_time.lock().insert((id, key), Instant::now());

        let list = guard.entry(id).or_insert_with(|| Vec::with_capacity(6));

        // 如果路由已存在，更新并重新排序
        if let Some(idx) = list.iter().position(|v| v.route_key() == key) {
            if is_default {
                return false;
            }
            list[idx] = route;
            // 向前冒泡（如果评分更高）
            let mut i = idx;
            while i > 0 && list[i].score() > list[i - 1].score() {
                list.swap(i, i - 1);
                i -= 1;
            }
            // 向后冒泡（如果评分更低）
            while i + 1 < list.len() && list[i].score() < list[i + 1].score() {
                list.swap(i, i + 1);
                i += 1;
            }
            return route.is_direct() && !had_direct;
        }

        // 插入新路由，保持按评分降序排序（评分高的在前）
        let mut pos = list.len();
        for (i, r) in list.iter().enumerate() {
            if route.score() > r.score() {
                pos = i;
                break;
            }
        }
        list.insert(pos, route);
        route.is_direct() && !had_direct
    }

    fn remove_oldest_route(&self, expired_time: Instant) -> Vec<(Ipv4Addr, RouteKey)> {
        let mut expired_keys = Vec::new();
        {
            let mut time_map = self.route_key_time.lock();
            time_map.retain(|(id, route_key), t| {
                if *t <= expired_time {
                    expired_keys.push((*id, *route_key));
                    false
                } else {
                    true
                }
            });
        }

        if expired_keys.is_empty() {
            return expired_keys;
        }

        let mut table = self.route_table.write();
        let mut owner_map = self.route_key_owner.lock();
        let mut route_info = self.route_info.lock();

        for (id, route_key) in &expired_keys {
            if let Some(list) = table.get_mut(id) {
                list.retain(|r| r.route_key() != *route_key);
                if list.is_empty() {
                    table.remove(id);
                }
            }

            if let Some(owner_id) = owner_map.get(route_key)
                && *owner_id == *id
            {
                owner_map.remove(route_key);
            }
            route_info.remove(&(*id, *route_key));
        }

        let live_keys: std::collections::HashSet<_> = table
            .values()
            .flat_map(|routes| routes.iter().map(Route::route_key))
            .collect();
        self.direct_peer_info
            .lock()
            .retain(|key, _| live_keys.contains(key));

        expired_keys
    }
}

fn best_direct_route(routes: &[Route]) -> Option<Route> {
    routes
        .iter()
        .filter(|route| route.is_direct())
        .max_by_key(|route| route.score())
        .copied()
}

fn direct_route_matches_policy(route: &Route, policy: PunchPolicy) -> bool {
    if !route.is_direct() {
        return false;
    }
    matches!(
        (
            route.route_key().protocol(),
            route.route_key().peer_addr(),
            policy
        ),
        (Protocol::TCP, SocketAddr::V4(_), PunchPolicy::IPv4Tcp)
            | (Protocol::UDP, SocketAddr::V4(_), PunchPolicy::IPv4Udp)
            | (Protocol::TCP, SocketAddr::V6(_), PunchPolicy::IPv6Tcp)
            | (Protocol::UDP, SocketAddr::V6(_), PunchPolicy::IPv6Udp)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;

    /// rtt 极大（>39s）时分母不能 u32 溢出（debug 构建下溢出会 panic）
    #[test]
    fn test_get_channel_score_large_rtt_no_overflow() {
        let score = get_channel_score(u32::MAX, 0, false, false);
        assert_eq!(score, 0);
        let score = get_channel_score(u32::MAX, 10000, true, true);
        assert_eq!(score, 0);
        // 正常值结果与预期一致：低 rtt 零丢包得分高
        let good = get_channel_score(10, 0, false, false);
        let bad = get_channel_score(1000, 5000, true, false);
        assert!(good > bad);
    }

    /// tcp 路由在相同质量下评分略高于 udp
    #[test]
    fn tcp_scores_slightly_higher_than_udp() {
        let udp = get_channel_score(50, 0, false, false);
        let tcp = get_channel_score(50, 0, false, true);
        assert!(tcp > udp);
        // 中继路由同样生效
        let udp_relay = get_channel_score(50, 0, true, false);
        let tcp_relay = get_channel_score(50, 0, true, true);
        assert!(tcp_relay > udp_relay);
    }

    #[test]
    fn relay_probe_can_bootstrap_route_but_regular_updates_cannot() {
        let table = RouteTable::new();
        let target = Ipv4Addr::new(10, 0, 0, 8);
        let route = Route::from_default_rt(RouteKey::default(), 2);

        table.add_route(target, route, true);
        assert!(!table.exists(&target));

        table.add_relay_route(target, route);
        let inserted = table.get_route_by_id(&target).unwrap();
        assert_eq!(inserted.metric(), 2);
    }

    #[test]
    fn route_notification_only_fires_for_first_direct_route() {
        let table = RouteTable::new();
        let notify = table.first_direct_route_notify();
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        let key = RouteKey::default();

        table.add_relay_route(peer, Route::from_default_rt(key, 2));
        assert!(notify.notified().now_or_never().is_none());

        table.add_owner_route(peer, key);
        assert!(notify.notified().now_or_never().is_some());

        table.add_route(peer, Route::from(key, 1, 25), false);
        assert!(notify.notified().now_or_never().is_none());

        table.remove_route_key(&key);
        assert!(notify.notified().now_or_never().is_none());
    }

    #[test]
    fn remove_route_key_cleans_direct_relay_owner_and_timestamps() {
        let table = RouteTable::new();
        let owner = Ipv4Addr::new(10, 0, 0, 2);
        let relayed = Ipv4Addr::new(10, 0, 0, 3);
        let unrelated = Ipv4Addr::new(10, 0, 0, 4);
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2000".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        );
        let other_key = RouteKey::new(
            Protocol::TCP,
            "127.0.0.1:2001".parse().unwrap(),
            "127.0.0.1:3001".parse().unwrap(),
        );

        table.add_owner_route(owner, key);
        table.add_relay_route(relayed, Route::from_default_rt(key, 2));
        table.add_owner_route(unrelated, other_key);

        assert_eq!(table.inner.route_key_owner.lock().get(&key), Some(&owner));
        assert_eq!(
            table
                .inner
                .route_key_time
                .lock()
                .keys()
                .filter(|(_, route_key)| *route_key == key)
                .count(),
            2
        );

        let mut removed = table.remove_route_key(&key);
        removed.sort_unstable();
        assert_eq!(removed, vec![(owner, key), (relayed, key)]);
        assert!(!table.exists(&owner));
        assert!(!table.exists(&relayed));
        assert!(table.exists(&unrelated));
        assert!(!table.inner.route_key_owner.lock().contains_key(&key));
        assert!(
            table
                .inner
                .route_key_time
                .lock()
                .keys()
                .all(|(_, route_key)| *route_key != key)
        );
    }

    #[test]
    fn identified_peer_and_all_routes_on_tunnel_are_released_together() {
        let table = RouteTable::new();
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2100".parse().unwrap(),
            "127.0.0.1:3100".parse().unwrap(),
        );
        let direct = NodeInfo {
            ip: "10.26.0.2".parse().unwrap(),
            name: "direct".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        };
        let relayed = NodeInfo {
            ip: "10.26.0.3".parse().unwrap(),
            name: "relayed".to_string(),
            version: "2".to_string(),
            advertised_subnets: vec!["192.168.3.0/24".parse().unwrap()],
        };
        table.add_identified_owner_route(direct.clone(), key);
        table.add_gossip_route(relayed.clone(), Route::from_default_rt(key, 2));
        assert_eq!(table.node_info(&direct.ip), Some(direct));
        assert_eq!(table.node_info(&relayed.ip), Some(relayed));

        table.remove_route_key(&key);
        assert!(table.node_infos().is_empty());
        assert!(table.inner.route_info.lock().is_empty());
    }

    #[test]
    fn graph_flood_excludes_every_tunnel_owned_by_the_ingress_node() {
        let table = RouteTable::new();
        let keys = [
            RouteKey::new(
                Protocol::TCP,
                "127.0.0.1:2110".parse().unwrap(),
                "127.0.0.1:3110".parse().unwrap(),
            ),
            RouteKey::new(
                Protocol::UDP,
                "127.0.0.1:2111".parse().unwrap(),
                "127.0.0.1:3111".parse().unwrap(),
            ),
            RouteKey::new(
                Protocol::TCP,
                "127.0.0.1:2112".parse().unwrap(),
                "127.0.0.1:3112".parse().unwrap(),
            ),
        ];
        for (key, ip) in [
            (keys[0], "10.26.0.2"),
            (keys[1], "10.26.0.2"),
            (keys[2], "10.26.0.3"),
        ] {
            table.add_identified_owner_route(
                NodeInfo {
                    ip: ip.parse().unwrap(),
                    name: ip.to_string(),
                    version: "2".to_string(),
                    advertised_subnets: Vec::new(),
                },
                key,
            );
        }
        assert_eq!(table.direct_routes(Some(&keys[0])), vec![keys[2]]);
    }

    #[test]
    fn unidentified_legacy_route_is_a_graph_next_hop_and_identity_can_arrive_later() {
        let table = RouteTable::new();
        let peer = Ipv4Addr::new(10, 26, 0, 2);
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2190".parse().unwrap(),
            "127.0.0.1:3190".parse().unwrap(),
        );
        table.add_owner_route(peer, key);
        assert_eq!(table.direct_routes(None), vec![key]);
        assert_eq!(
            table
                .inner
                .direct_peer_info
                .lock()
                .get(&key)
                .unwrap()
                .identity,
            None
        );

        let node = NodeInfo {
            ip: peer,
            name: "legacy-peer".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        };
        table.add_gossip_route(node.clone(), Route::from_default_rt(key, 1));
        assert_eq!(table.node_info(&peer), Some(node.clone()));
        assert_eq!(
            table
                .inner
                .direct_peer_info
                .lock()
                .get(&key)
                .unwrap()
                .identity,
            Some(node)
        );
    }

    #[test]
    fn announcement_arriving_before_punch_response_keeps_identity() {
        let table = RouteTable::new();
        let peer = Ipv4Addr::new(10, 26, 0, 2);
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2191".parse().unwrap(),
            "127.0.0.1:3191".parse().unwrap(),
        );
        let node = NodeInfo {
            ip: peer,
            name: "early-announcement".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        };

        table.add_gossip_route(node.clone(), Route::from_default_rt(key, 1));
        table.add_owner_route(peer, key);

        assert_eq!(
            table
                .inner
                .direct_peer_info
                .lock()
                .get(&key)
                .unwrap()
                .identity,
            Some(node)
        );
        assert_eq!(table.direct_routes(None), vec![key]);
    }

    #[test]
    fn four_node_chain_converges_through_an_initially_unidentified_edge() {
        let table = RouteTable::new();
        let via_b = RouteKey::new(
            Protocol::TCP,
            "127.0.0.1:2200".parse().unwrap(),
            "127.0.0.1:3200".parse().unwrap(),
        );
        for (index, (ip, name)) in [("10.26.0.2", "B"), ("10.26.0.3", "C"), ("10.26.0.4", "D")]
            .into_iter()
            .enumerate()
        {
            let node = NodeInfo {
                ip: ip.parse().unwrap(),
                name: name.to_string(),
                version: "2".to_string(),
                advertised_subnets: Vec::new(),
            };
            if index == 0 {
                table.add_owner_route(node.ip, via_b);
                table.add_gossip_route(node, Route::from_default_rt(via_b, 1));
            } else {
                table.add_gossip_route(node, Route::from_default_rt(via_b, index as u8 + 1));
            }
        }
        assert_eq!(
            table
                .get_route_by_id(&"10.26.0.4".parse().unwrap())
                .unwrap()
                .metric(),
            3
        );
        assert_eq!(table.node_infos().len(), 3);

        table.remove_route_key(&via_b);
        assert!(table.route_table().is_empty());
        assert!(table.node_infos().is_empty());
    }

    #[test]
    fn hop_count_penalizes_otherwise_equal_routes() {
        let one = Route::from_default_rt(RouteKey::default(), 1);
        let three = Route::from_default_rt(RouteKey::default(), 3);
        assert!(one.score() > three.score());
    }

    #[test]
    fn direct_route_lookup_ignores_higher_scored_relay_route() {
        let relay = Route::from(RouteKey::default(), 2, 1);
        let direct = Route::from(RouteKey::default(), 1, 1000);
        assert!(relay.score() > direct.score());
        assert_eq!(best_direct_route(&[relay, direct]).unwrap().metric(), 1);
    }

    #[test]
    fn missing_punch_policies_only_returns_configured_routes_without_direct_match() {
        let table = RouteTable::new();
        let target = Ipv4Addr::new(10, 0, 0, 2);
        let ipv4_tcp = RouteKey::new(
            Protocol::TCP,
            "127.0.0.1:2000".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        );
        let ipv4_udp = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2001".parse().unwrap(),
            "127.0.0.1:3001".parse().unwrap(),
        );
        let mut configured = PunchPolicySet::empty();
        configured.or(PunchPolicy::IPv4Tcp);
        configured.or(PunchPolicy::IPv4Udp);

        table.add_owner_route(target, ipv4_tcp);
        table.add_relay_route(target, Route::from_default_rt(ipv4_udp, 2));

        let missing = table.missing_punch_policies(&target, &configured);
        assert!(!missing.is_match(PunchPolicy::IPv4Tcp));
        assert!(missing.is_match(PunchPolicy::IPv4Udp));
        assert!(!missing.is_match(PunchPolicy::IPv6Tcp));
        assert!(!missing.is_match(PunchPolicy::IPv6Udp));

        table.add_owner_route(target, ipv4_udp);
        let missing = table.missing_punch_policies(&target, &configured);
        assert!(!missing.is_match(PunchPolicy::IPv4Tcp));
        assert!(!missing.is_match(PunchPolicy::IPv4Udp));
    }

    #[test]
    fn missing_punch_policies_distinguishes_ip_family_and_protocol() {
        let table = RouteTable::new();
        let target = Ipv4Addr::new(10, 0, 0, 2);
        let ipv6_udp = RouteKey::new(
            Protocol::UDP,
            "[::1]:2000".parse().unwrap(),
            "[::1]:3000".parse().unwrap(),
        );
        table.add_owner_route(target, ipv6_udp);

        let missing = table.missing_punch_policies(&target, &PunchPolicySet::all());
        assert!(missing.is_match(PunchPolicy::IPv4Tcp));
        assert!(missing.is_match(PunchPolicy::IPv4Udp));
        assert!(missing.is_match(PunchPolicy::IPv6Tcp));
        assert!(!missing.is_match(PunchPolicy::IPv6Udp));
    }
}
