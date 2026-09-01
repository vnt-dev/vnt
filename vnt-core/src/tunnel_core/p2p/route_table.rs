use parking_lot::{Mutex, RwLock};
use rustp2p_core::route_table::{DEFAULT_RTT, Protocol, RouteKey};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

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
        let score = get_channel_score(rtt, 0, is_relay, route_key.protocol().is_tcp());
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
        let score = get_channel_score(rtt, loss_rate as u32, is_relay, route_key.protocol().is_tcp());
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
        let score = get_channel_score(DEFAULT_RTT, 0, is_relay, route_key.protocol().is_tcp());
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

    /// 判断是否需要打洞（没有路由或只有中继路由）
    pub fn need_punch(&self, id: &Ipv4Addr) -> bool {
        let guard = self.inner.route_table.read();
        let Some(list) = guard.get(id) else {
            return true;
        };
        // 如果没有直连路由（metric=1），则需要打洞
        !list.iter().any(|r| r.is_direct())
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
    pub fn add_owner_route(&self, id: Ipv4Addr, key: RouteKey) {
        if self.inner.add_owner_route(id, key) {
            self.inner.first_direct_route_notify.notify_one();
        }
    }

    /// 添加路由（心跳时调用，用于更新路由时间和添加跨节点转发路由）
    pub fn add_route(&self, id: Ipv4Addr, route: Route, is_default: bool) {
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
        removed
    }

    /// 移除过期的路由
    pub fn remove_oldest_route(&self, expired_time: Instant) -> Vec<(Ipv4Addr, RouteKey)> {
        self.inner.remove_oldest_route(expired_time)
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
    fn direct_route_lookup_ignores_higher_scored_relay_route() {
        let relay = Route::from(RouteKey::default(), 2, 1);
        let direct = Route::from(RouteKey::default(), 1, 1000);
        assert!(relay.score() > direct.score());
        assert_eq!(best_direct_route(&[relay, direct]).unwrap().metric(), 1);
    }
}
