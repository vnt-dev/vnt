use parking_lot::{Mutex, RwLock};
use rust_p2p_core::route::{RouteKey, DEFAULT_RTT};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;


#[derive(Copy, Clone, Debug)]
pub struct Route {
    route_key: RouteKey,
    metric: u8,
    rtt: u32,
}
impl Route {
    pub fn from(route_key: RouteKey, metric: u8, rtt: u32) -> Self {
        Self {
            route_key,
            metric,
            rtt,
        }
    }
    pub fn from_default_rt(route_key: RouteKey, metric: u8) -> Self {
        Self {
            route_key,
            metric,
            rtt: DEFAULT_RTT,
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

    /// 添加 owner 路由（打洞请求响应时调用）
    pub fn add_owner_route(&self, id: Ipv4Addr, key: RouteKey) {
        self.inner.add_owner_route(id, key);
    }

    /// 添加路由（心跳时调用，用于更新路由时间和添加跨节点转发路由）
    pub fn add_route(&self, id: Ipv4Addr, route: Route) {
        self.inner.add_route(id, route);
    }

    /// 如果路由不存在则添加（用于 Ping 消息）
    pub fn add_route_if_absent(&self, id: Ipv4Addr, route: Route) {
        let guard = self.inner.route_table.read();
        if guard.contains_key(&id) {
            return;
        }
        drop(guard);
        self.inner.add_route(id, route);
    }

    /// 获取所有路由表
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        let guard = self.inner.route_table.read();
        guard.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// 根据 RouteKey 查找对应的 IP
    pub fn get_id_by_route_key(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        let owner_map = self.inner.route_key_owner.lock();
        owner_map.get(route_key).copied()
    }

    /// 移除指定 IP 和 RouteKey 的路由
    pub fn remove_route(&self, id: &Ipv4Addr, route_key: &RouteKey) {
        let mut table = self.inner.route_table.write();
        let mut owner_map = self.inner.route_key_owner.lock();
        let mut time_map = self.inner.route_key_time.lock();

        if let Some(list) = table.get_mut(id) {
            list.retain(|r| r.route_key() != *route_key);
            if list.is_empty() {
                table.remove(id);
            }
        }

        if let Some(owner_id) = owner_map.get(route_key) {
            if owner_id == id {
                owner_map.remove(route_key);
            }
        }

        time_map.remove(&(*id, *route_key));
    }

    /// 移除过期的路由
    pub fn remove_oldest_route(&self, expired_time: Instant) {
        self.inner.remove_oldest_route(expired_time);
    }
}

impl RouteTableInner {
    fn get_by_id(&self, id: &Ipv4Addr) -> Option<Route> {
        let guard = self.route_table.read();
        let list = guard.get(id)?;
        list.first().cloned()
    }

    fn add_owner_route(&self, id: Ipv4Addr, key: RouteKey) {
        let route = Route::from_default_rt(key, 1);
        let mut guard = self.route_table.write();

        self.route_key_owner.lock().insert(key, id);
        self.route_key_time.lock().insert((id, key), Instant::now());

        let list = guard.entry(id).or_insert_with(|| Vec::with_capacity(6));
        if list.iter().any(|v| v.route_key() == key) {
            return;
        }
        list.push(route);
    }

    fn add_route(&self, id: Ipv4Addr, route: Route) {
        let key = route.route_key();
        let mut guard = self.route_table.write();

        // 检查是否是 owner 路由
        let mut route_key_owner = self.route_key_owner.lock();
        if route.is_direct() {
            route_key_owner.entry(key).or_insert(id);
        } else {
            if !guard.contains_key(&id) {
                return;
            }
        }

        // 更新时间
        self.route_key_time.lock().insert((id, key), Instant::now());

        let list = guard.entry(id).or_insert_with(|| Vec::with_capacity(6));

        // 如果路由已存��，更新并重新排序
        if let Some(idx) = list.iter().position(|v| v.route_key() == key) {
            list[idx] = route;
            // 向前冒泡（如果 RTT 更小）
            let mut i = idx;
            while i > 0 && list[i].rtt() < list[i - 1].rtt() {
                list.swap(i, i - 1);
                i -= 1;
            }
            // 向后冒泡（如果 RTT 更大）
            while i + 1 < list.len() && list[i].rtt() > list[i + 1].rtt() {
                list.swap(i, i + 1);
                i += 1;
            }
            return;
        }

        // 插入新路由，保持按 RTT 排序
        let mut pos = list.len();
        for (i, r) in list.iter().enumerate() {
            if route.rtt() < r.rtt() {
                pos = i;
                break;
            }
        }
        list.insert(pos, route);
    }

    fn remove_oldest_route(&self, expired_time: Instant) {
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
            return;
        }

        let mut table = self.route_table.write();
        let mut owner_map = self.route_key_owner.lock();

        for (id, route_key) in expired_keys {
            if let Some(list) = table.get_mut(&id) {
                list.retain(|r| r.route_key() != route_key);
                if list.is_empty() {
                    table.remove(&id);
                }
            }

            if let Some(owner_id) = owner_map.get(&route_key) {
                if *owner_id == id {
                    owner_map.remove(&route_key);
                }
            }
        }
    }
}
