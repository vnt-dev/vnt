use parking_lot::{Mutex, RwLock};
use rustp2p_core::punch::{PunchPolicy, PunchPolicySet};
use rustp2p_core::route_table::{DEFAULT_RTT, Protocol, RouteKey};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

const MAX_ROUTES_PER_NODE: usize = 5;

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
    /// Confirmed physical tunnel owner. A RouteKey reused by relayed routes
    /// still belongs only to its directly connected peer.
    route_key_owner: Mutex<HashMap<RouteKey, Ipv4Addr>>,
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
        self.inner.add_owner_route(id, key)
    }

    /// Adds or refreshes one Gossip path. Returns false when the route is
    /// rejected by the hop limit.
    pub fn add_gossip_route(&self, id: Ipv4Addr, route: Route) -> bool {
        if route.metric() > 15 {
            return false;
        }
        // Gossip/discovery supplies an initial next hop and refreshes its
        // lifetime. Once Ping/Pong has measured this route, repeated
        // announcements must not replace its RTT/loss/score with defaults.
        self.inner.add_route(id, route, true, true);
        true
    }

    pub fn direct_routes(&self, exclude: Option<&RouteKey>) -> Vec<RouteKey> {
        let owners = self.inner.route_key_owner.lock();
        let excluded_node = exclude.and_then(|key| owners.get(key).copied());
        owners
            .iter()
            .filter_map(|(key, peer_ip)| {
                (exclude != Some(key) && excluded_node != Some(*peer_ip)).then_some(*key)
            })
            .collect()
    }

    /// Returns unique virtual IPs currently reachable over a direct tunnel.
    pub fn direct_peer_ips(&self) -> Vec<Ipv4Addr> {
        let mut ips = self
            .inner
            .route_key_owner
            .lock()
            .values()
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        ips.sort_unstable();
        ips
    }

    /// 添加路由（心跳时调用，用于更新路由时间和添加跨节点转发路由）
    pub fn add_route(&self, id: Ipv4Addr, route: Route, is_default: bool) {
        self.inner.add_route(id, route, false, is_default);
    }

    /// Adds a two-hop route advertised by a directly connected Gossip peer.
    /// The target identity is learned separately from its own announcement.
    pub fn add_gossip_relay_route(&self, id: Ipv4Addr, route: Route) {
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
        // The handshake supplies only an initial route. Repeated Punch or
        // DirectConnect packets must refresh its lifetime without replacing
        // RTT/loss measurements learned from Ping/Pong.
        self.add_route(id, Route::from_default_rt(key, 1), false, true)
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

        if !route.is_direct() && !allow_relay_bootstrap && !guard.contains_key(&id) {
            return false;
        }

        // 更新时间
        self.route_key_time.lock().insert((id, key), Instant::now());

        let list = guard.entry(id).or_insert_with(|| Vec::with_capacity(6));

        // 如果路由已存在，更新并重新排序
        if let Some(idx) = list.iter().position(|v| v.route_key() == key) {
            let route = if is_default {
                let current = list[idx];
                if current.metric() == route.metric() {
                    return false;
                }
                // Handshakes and Gossip know the current hop count but do not
                // carry quality measurements. Keep measured RTT/loss while
                // still allowing a relayed RouteKey to become direct (or a
                // changed Gossip path to update its metric).
                Route::from_with_loss(key, route.metric(), current.rtt(), current.loss_rate())
            } else {
                route
            };
            if list[idx].metric() == route.metric()
                && list[idx].rtt() == route.rtt()
                && list[idx].loss_rate() == route.loss_rate()
            {
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

        // Bound the number of learned alternatives so routes which are never
        // probed do not expire and get recreated by every announcement. Direct
        // tunnels are physical connectivity and are therefore never evicted by
        // this logical route cap.
        while list.len() > MAX_ROUTES_PER_NODE {
            let Some(index) = list.iter().rposition(|candidate| !candidate.is_direct()) else {
                break;
            };
            let removed = list.remove(index);
            self.route_key_time
                .lock()
                .remove(&(id, removed.route_key()));
        }
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
        }

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
    use crate::tunnel_core::p2p::node_info::{NodeInfo, NodeInfoMap};

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
    fn gossip_hint_can_bootstrap_route_but_regular_updates_cannot() {
        let table = RouteTable::new();
        let target = Ipv4Addr::new(10, 0, 0, 8);
        let route = Route::from_default_rt(RouteKey::default(), 2);

        table.add_route(target, route, true);
        assert!(!table.exists(&target));

        table.add_gossip_relay_route(target, route);
        let inserted = table.get_route_by_id(&target).unwrap();
        assert_eq!(inserted.metric(), 2);
    }

    #[test]
    fn repeated_owner_handshake_preserves_measured_route_quality() {
        let table = RouteTable::new();
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:1990".parse().unwrap(),
            "127.0.0.1:2990".parse().unwrap(),
        );

        assert!(table.add_owner_route(peer, key));
        table.add_route(peer, Route::from_with_loss(key, 1, 37, 125), false);
        assert!(!table.add_owner_route(peer, key));

        let route = table.get_route_by_id(&peer).unwrap();
        assert_eq!(route.rtt(), 37);
        assert_eq!(route.loss_rate(), 125);
    }

    #[test]
    fn owner_handshake_updates_metric_without_discarding_measured_quality() {
        let table = RouteTable::new();
        let peer = Ipv4Addr::new(10, 0, 0, 6);
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:1994".parse().unwrap(),
            "127.0.0.1:2994".parse().unwrap(),
        );

        table.add_gossip_relay_route(peer, Route::from_with_loss(key, 2, 51, 375));
        assert!(table.add_owner_route(peer, key));

        let route = table.get_route_by_id(&peer).unwrap();
        assert!(route.is_direct());
        assert_eq!(route.rtt(), 51);
        assert_eq!(route.loss_rate(), 375);
    }

    #[test]
    fn repeated_gossip_preserves_measured_route_quality_and_refreshes_identity() {
        let table = RouteTable::new();
        let nodes = NodeInfoMap::default();
        let peer = Ipv4Addr::new(10, 0, 0, 3);
        let key = RouteKey::new(
            Protocol::TCP,
            "127.0.0.1:1991".parse().unwrap(),
            "127.0.0.1:2991".parse().unwrap(),
        );
        let mut node = NodeInfo {
            ip: peer,
            name: "before".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        };

        assert!(table.add_gossip_route(peer, Route::from_default_rt(key, 2)));
        nodes.upsert(node.clone());
        table.add_route(peer, Route::from_with_loss(key, 2, 43, 250), false);
        node.name = "after".to_string();
        assert!(table.add_gossip_route(peer, Route::from_default_rt(key, 2)));
        nodes.upsert(node.clone());

        let route = table.get_route_by_id(&peer).unwrap();
        assert_eq!(route.rtt(), 43);
        assert_eq!(route.loss_rate(), 250);
        assert_eq!(nodes.get(&peer), Some(node));
    }

    #[test]
    fn node_identity_survives_a_switch_to_an_unidentified_best_route() {
        let table = RouteTable::new();
        let nodes = NodeInfoMap::default();
        let peer = Ipv4Addr::new(10, 0, 0, 4);
        let gossip_key = RouteKey::new(
            Protocol::TCP,
            "127.0.0.1:1992".parse().unwrap(),
            "127.0.0.1:2992".parse().unwrap(),
        );
        let direct_key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:1993".parse().unwrap(),
            "127.0.0.1:2993".parse().unwrap(),
        );
        let node = NodeInfo {
            ip: peer,
            name: "known-via-gossip".to_string(),
            version: "2".to_string(),
            advertised_subnets: vec!["192.168.4.0/24".parse().unwrap()],
        };

        table.add_gossip_route(peer, Route::from_default_rt(gossip_key, 2));
        nodes.upsert(node.clone());
        table.add_owner_route(peer, direct_key);

        assert_eq!(
            table.get_route_by_id(&peer).unwrap().route_key(),
            direct_key
        );
        assert_eq!(nodes.get(&peer), Some(node));
    }

    #[test]
    fn learned_route_count_is_bounded() {
        let table = RouteTable::new();
        let peer = Ipv4Addr::new(10, 0, 0, 5);
        for index in 0..=MAX_ROUTES_PER_NODE {
            let key = RouteKey::new(
                Protocol::UDP,
                format!("127.0.0.1:{}", 2100 + index).parse().unwrap(),
                format!("127.0.0.1:{}", 3100 + index).parse().unwrap(),
            );
            table.add_gossip_route(peer, Route::from_default_rt(key, 2));
        }

        assert_eq!(
            table
                .route_table()
                .into_iter()
                .find(|(ip, _)| *ip == peer)
                .unwrap()
                .1
                .len(),
            MAX_ROUTES_PER_NODE
        );
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
        table.add_gossip_relay_route(relayed, Route::from_default_rt(key, 2));
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
    fn all_routes_on_tunnel_are_released_together() {
        let table = RouteTable::new();
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2100".parse().unwrap(),
            "127.0.0.1:3100".parse().unwrap(),
        );
        let direct = Ipv4Addr::new(10, 26, 0, 2);
        let relayed = Ipv4Addr::new(10, 26, 0, 3);
        table.add_owner_route(direct, key);
        table.add_gossip_route(relayed, Route::from_default_rt(key, 2));

        table.remove_route_key(&key);
        assert!(table.route_table().is_empty());
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
            table.add_owner_route(ip.parse().unwrap(), key);
        }
        assert_eq!(table.direct_routes(Some(&keys[0])), vec![keys[2]]);
        assert_eq!(
            table.direct_peer_ips(),
            vec![Ipv4Addr::new(10, 26, 0, 2), Ipv4Addr::new(10, 26, 0, 3)]
        );
    }

    #[test]
    fn relayed_routes_reuse_the_direct_peer_key_without_changing_its_owner() {
        let table = RouteTable::new();
        let direct_peer = Ipv4Addr::new(10, 26, 0, 2);
        let relayed_peer = Ipv4Addr::new(10, 26, 0, 3);
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2113".parse().unwrap(),
            "127.0.0.1:3113".parse().unwrap(),
        );

        table.add_owner_route(direct_peer, key);
        table.add_gossip_relay_route(relayed_peer, Route::from_default_rt(key, 2));

        assert_eq!(
            table.inner.route_key_owner.lock().get(&key),
            Some(&direct_peer)
        );
        assert_eq!(table.direct_peer_ips(), vec![direct_peer]);
        assert!(table.exists(&relayed_peer));
    }

    #[test]
    fn metric_one_gossip_does_not_confirm_a_direct_tunnel_owner() {
        let table = RouteTable::new();
        let peer = Ipv4Addr::new(10, 26, 0, 2);
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2114".parse().unwrap(),
            "127.0.0.1:3114".parse().unwrap(),
        );

        assert!(table.add_gossip_route(peer, Route::from_default_rt(key, 1)));
        assert!(table.direct_routes(None).is_empty());
        assert!(!table.inner.route_key_owner.lock().contains_key(&key));

        table.add_owner_route(peer, key);
        assert_eq!(table.direct_routes(None), vec![key]);
    }

    #[test]
    fn route_quality_refresh_cannot_restore_an_old_node_identity() {
        let table = RouteTable::new();
        let nodes = NodeInfoMap::default();
        let peer = Ipv4Addr::new(10, 26, 0, 2);
        let old_key = RouteKey::new(
            Protocol::TCP,
            "127.0.0.1:2115".parse().unwrap(),
            "127.0.0.1:3115".parse().unwrap(),
        );
        let new_key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2116".parse().unwrap(),
            "127.0.0.1:3116".parse().unwrap(),
        );
        let mut identity = NodeInfo {
            ip: peer,
            name: "before".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        };

        table.add_gossip_route(peer, Route::from_default_rt(old_key, 2));
        nodes.upsert(identity.clone());
        table.add_gossip_route(peer, Route::from_default_rt(new_key, 2));
        identity.name = "after".to_string();
        nodes.upsert(identity.clone());

        table.add_route(peer, Route::from(old_key, 2, 12), false);
        assert_eq!(nodes.get(&peer), Some(identity));
    }

    #[test]
    fn gossip_hint_keeps_alternatives_from_distinct_direct_routes() {
        let table = RouteTable::new();
        let target = Ipv4Addr::new(10, 26, 0, 9);
        let keys = [
            RouteKey::new(
                Protocol::TCP,
                "127.0.0.1:2120".parse().unwrap(),
                "127.0.0.1:3120".parse().unwrap(),
            ),
            RouteKey::new(
                Protocol::UDP,
                "127.0.0.1:2121".parse().unwrap(),
                "127.0.0.1:3121".parse().unwrap(),
            ),
        ];

        for key in keys {
            table.add_gossip_relay_route(target, Route::from_default_rt(key, 2));
        }

        let routes = table
            .route_table()
            .into_iter()
            .find_map(|(ip, routes)| (ip == target).then_some(routes))
            .unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| route.metric() == 2));
    }

    #[test]
    fn unidentified_legacy_route_is_a_graph_next_hop_and_identity_can_arrive_later() {
        let table = RouteTable::new();
        let nodes = NodeInfoMap::default();
        let peer = Ipv4Addr::new(10, 26, 0, 2);
        let key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2190".parse().unwrap(),
            "127.0.0.1:3190".parse().unwrap(),
        );
        table.add_owner_route(peer, key);
        assert_eq!(table.direct_routes(None), vec![key]);
        assert!(nodes.get(&peer).is_none());

        let node = NodeInfo {
            ip: peer,
            name: "legacy-peer".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        };
        table.add_gossip_route(peer, Route::from_default_rt(key, 1));
        nodes.upsert(node.clone());
        assert_eq!(nodes.get(&peer), Some(node));
    }

    #[test]
    fn announcement_arriving_before_punch_response_keeps_identity() {
        let table = RouteTable::new();
        let nodes = NodeInfoMap::default();
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

        table.add_gossip_route(peer, Route::from_default_rt(key, 1));
        nodes.upsert(node.clone());
        table.add_owner_route(peer, key);

        assert_eq!(nodes.get(&peer), Some(node));
        assert_eq!(table.direct_routes(None), vec![key]);
    }

    #[test]
    fn four_node_chain_converges_through_an_initially_unidentified_edge() {
        let table = RouteTable::new();
        let nodes = NodeInfoMap::default();
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
                table.add_gossip_route(node.ip, Route::from_default_rt(via_b, 1));
            } else {
                table.add_gossip_route(node.ip, Route::from_default_rt(via_b, index as u8 + 1));
            }
            nodes.upsert(node);
        }
        assert_eq!(
            table
                .get_route_by_id(&"10.26.0.4".parse().unwrap())
                .unwrap()
                .metric(),
            3
        );
        assert_eq!(nodes.list().len(), 3);

        table.remove_route_key(&via_b);
        assert!(table.route_table().is_empty());
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
        table.add_gossip_relay_route(target, Route::from_default_rt(ipv4_udp, 2));

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
