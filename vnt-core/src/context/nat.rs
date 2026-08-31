use parking_lot::{Mutex, RwLock};
use rustp2p_core::nat::{NatInfo, NatType};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

type NatChangeCallback = Arc<dyn Fn() + Send + Sync>;

/// 判断 NAT 信息是否发生了“身份级”变化（网络切换/NAT 重启等）。
/// 对称 NAT 的公网映射端口会随每次连接重新分配，
/// 因此仅端口类字段的变化不算 NAT 变化。
pub(crate) fn nat_identity_changed(a: &NatInfo, b: &NatInfo) -> bool {
    let identity_changed = a.nat_type != b.nat_type
        || a.public_ips != b.public_ips
        || a.local_ipv4 != b.local_ipv4
        || a.local_ipv4s != b.local_ipv4s
        || a.ipv6 != b.ipv6
        || a.local_udp_ports != b.local_udp_ports
        || a.local_tcp_port != b.local_tcp_port;
    let mapping_changed = a.public_udp_ports != b.public_udp_ports
        || a.public_tcp_port != b.public_tcp_port
        || a.mapping_tcp_addr != b.mapping_tcp_addr
        || a.mapping_udp_addr != b.mapping_udp_addr;
    // 映射端口在非对称 NAT 下应保持稳定，变化说明映射被重建；
    // 对称 NAT 下端口变化是常态，不视为变化
    identity_changed || (b.nat_type != NatType::Symmetric && mapping_changed)
}

#[derive(Clone, Default)]
pub struct MyNatInfo {
    nat_info: Arc<RwLock<Option<NatInfo>>>,
    /// 本机 NAT 信息实际变化时触发（用于压缩打洞退避）
    on_change: Arc<Mutex<Option<NatChangeCallback>>>,
}
impl MyNatInfo {
    pub fn get(&self) -> Option<NatInfo> {
        self.nat_info.read().clone()
    }
    /// 注册 NAT 信息变化回调（同一实例的 clone 共享）
    pub fn set_on_change(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.on_change.lock() = Some(Arc::new(f));
    }
    fn notify_change(&self) {
        let cb = self.on_change.lock().clone();
        if let Some(cb) = cb {
            cb();
        }
    }
    pub fn update_public_addr(&self, addr: SocketAddr) {
        let (ip, port) = if let Some(r) = mapping_addr(addr) {
            r
        } else {
            return;
        };
        log::debug!("public_addr:{ip},{port}");
        let changed = {
            let mut guard = self.nat_info.write();
            let Some(info) = guard.as_mut() else {
                return;
            };
            if !rustp2p_core::util::addr::is_ipv4_global(&ip) {
                log::debug!("not public addr: {addr:?}");
                return;
            }
            let old = info.clone();
            if !info.public_ips.contains(&ip) {
                info.public_ips.push(ip);
            }
            if let Some(public_port) = info.public_udp_ports.first_mut() {
                *public_port = port;
            } else {
                info.public_udp_ports.push(port);
            }
            nat_identity_changed(&old, info)
        }; // 写锁在此释放
        if changed {
            self.notify_change();
        }
    }
    pub fn update_tcp_public_addr(&self, addr: SocketAddr) {
        let SocketAddr::V4(addr) = addr else {
            return;
        };
        let ip = *addr.ip();
        let port = addr.port();
        log::info!("tcp_public_addr, {}:{}", ip, port);
        let changed = {
            let mut guard = self.nat_info.write();
            let Some(info) = guard.as_mut() else {
                return;
            };
            if ip.is_unspecified() && port == 0 {
                info.public_tcp_port = 0;
                return;
            }
            if !rustp2p_core::util::addr::is_ipv4_global(&ip) {
                log::debug!("not public addr: {addr:?}");
                return;
            }
            let old = info.clone();
            if !info.public_ips.contains(&ip) {
                info.public_ips.push(ip);
            }
            info.public_tcp_port = port;
            nat_identity_changed(&old, info)
        }; // 写锁在此释放
        if changed {
            self.notify_change();
        }
    }
    pub fn replace_nat_info(&self, nat_info: NatInfo) {
        let changed = {
            let mut w = self.nat_info.write();
            // 首次设置（此前无 NAT 信息）不算变化
            let changed = w
                .as_ref()
                .is_some_and(|old| nat_identity_changed(old, &nat_info));
            *w = Some(nat_info);
            changed
        };
        if changed {
            self.notify_change();
        }
    }
    pub fn clear(&self) {
        *self.nat_info.write() = None;
    }
}
fn mapping_addr(addr: SocketAddr) -> Option<(Ipv4Addr, u16)> {
    match addr {
        SocketAddr::V4(addr) => Some((*addr.ip(), addr.port())),
        SocketAddr::V6(addr) => addr.ip().to_ipv4_mapped().map(|ip| (ip, addr.port())),
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PunchState {
    /// 打洞交互累计次数，退避时长按「BASE × count」线性增长，封顶 MAX_BACKOFF。
    pub count: u32,
    /// 该目标下次允许打洞的时刻，到点之前不应再次打洞。
    /// 用单调时钟 Instant，不受系统时间调整影响。
    pub backoff_until: Instant,
}

#[derive(Clone, Default)]
pub struct PunchBackoff {
    inner: Arc<RwLock<HashMap<Ipv4Addr, PunchState>>>,
}

impl PunchBackoff {
    const MAX_BACKOFF: Duration = Duration::from_secs(3_600); // 常规退避上限 1h
    const NAT_CHANGE_CAP: Duration = Duration::from_secs(600); // NAT 变化后最多等待 10 分钟
    const BASE: Duration = Duration::from_secs(3);

    /// 记录一次打洞交互：退避时长 = BASE × 累计次数，封顶 MAX_BACKOFF。
    pub fn record(&self, ip: Ipv4Addr) {
        let now = Instant::now();
        let mut map = self.inner.write();
        let entry = map.entry(ip).or_insert(PunchState {
            count: 0,
            backoff_until: now,
        });
        entry.count += 1;
        entry.backoff_until = now + (Self::BASE * entry.count).min(Self::MAX_BACKOFF);
    }

    pub fn should_punch(&self, ip: Ipv4Addr) -> bool {
        let map = self.inner.read();
        map.get(&ip)
            .is_none_or(|state| Instant::now() >= state.backoff_until)
    }

    /// 对端 NAT 变化：不删除退避记录，把该目标的退避截止时刻压缩到
    /// 「当前 + NAT_CHANGE_CAP」以内，并归零增长指数，允许尽快重新尝试打洞。
    pub fn cap(&self, ip: Ipv4Addr) {
        self.cap_impl(Some(ip));
    }

    /// 本机 NAT 变化：把所有目标的退避截止时刻压缩到 10 分钟以内，并归零增长指数。
    pub fn cap_all(&self) {
        self.cap_impl(None);
    }

    fn cap_impl(&self, ip: Option<Ipv4Addr>) {
        let limit = Instant::now() + Self::NAT_CHANGE_CAP;
        let mut map = self.inner.write();
        match ip {
            Some(ip) => {
                if let Some(state) = map.get_mut(&ip) {
                    // 归零指数避免下一次 record 瞬间把退避涨回原高度
                    state.count = 0;
                    if state.backoff_until > limit {
                        state.backoff_until = limit;
                    }
                }
            }
            None => {
                for state in map.values_mut() {
                    state.count = 0;
                    if state.backoff_until > limit {
                        state.backoff_until = limit;
                    }
                }
            }
        }
    }

    /// 网络停止时清空全部退避状态
    pub fn clear(&self) {
        self.inner.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn nat_info(
        nat_type: NatType,
        public_ips: Vec<Ipv4Addr>,
        public_udp_ports: Vec<u16>,
        local_ipv4: Ipv4Addr,
    ) -> NatInfo {
        NatInfo {
            nat_type,
            public_ips,
            public_udp_ports,
            mapping_tcp_addr: vec![],
            mapping_udp_addr: vec![],
            public_port_range: 0,
            local_ipv4,
            local_ipv4s: vec![local_ipv4],
            ipv6: None,
            local_udp_ports: vec![],
            local_tcp_port: 0,
            public_tcp_port: 0,
            stun_mapped_ports: vec![],
        }
    }

    #[test]
    fn symmetric_port_jitter_is_not_identity_change() {
        let local = Ipv4Addr::new(192, 168, 1, 2);
        let a = nat_info(NatType::Symmetric, vec![], vec![1000], local);
        let b = nat_info(NatType::Symmetric, vec![], vec![2000], local);
        assert!(!nat_identity_changed(&a, &b), "对称NAT端口抖动不算变化");
    }

    #[test]
    fn cone_port_change_is_identity_change() {
        let local = Ipv4Addr::new(192, 168, 1, 2);
        let a = nat_info(NatType::Cone, vec![], vec![1000], local);
        let b = nat_info(NatType::Cone, vec![], vec![2000], local);
        assert!(nat_identity_changed(&a, &b), "非对称NAT映射重建算变化");
    }

    #[test]
    fn public_ip_change_always_counts() {
        let local = Ipv4Addr::new(192, 168, 1, 2);
        let a = nat_info(
            NatType::Symmetric,
            vec![Ipv4Addr::new(1, 1, 1, 1)],
            vec![1000],
            local,
        );
        let b = nat_info(
            NatType::Symmetric,
            vec![Ipv4Addr::new(2, 2, 2, 2)],
            vec![2000],
            local,
        );
        assert!(nat_identity_changed(&a, &b), "出口IP变化必算变化");
    }

    #[test]
    fn identical_info_is_not_change() {
        let local = Ipv4Addr::new(192, 168, 1, 2);
        let a = nat_info(NatType::Cone, vec![], vec![1000], local);
        assert!(!nat_identity_changed(&a, &a.clone()));
    }

    #[test]
    fn record_delays_until_deadline() {
        let backoff = PunchBackoff::default();
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        assert!(backoff.should_punch(ip));
        backoff.record(ip);
        assert!(!backoff.should_punch(ip), "record后退避期内不应打洞");
        // 把退避截止时刻拨到过去 → 应立即允许
        backoff.inner.write().get_mut(&ip).unwrap().backoff_until =
            Instant::now() - Duration::from_secs(1);
        assert!(backoff.should_punch(ip));
    }

    #[test]
    fn record_after_expiry_keeps_growth() {
        let backoff = PunchBackoff::default();
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        for _ in 0..1200 {
            backoff.record(ip);
        }
        // 模拟上一次退避已到期后才再次 record（两次交互间隔较长）：
        // 退避必须继续按累计次数增长，而不是被重置回 BASE。
        let now = Instant::now();
        {
            let mut map = backoff.inner.write();
            map.get_mut(&ip).unwrap().backoff_until = now - Duration::from_secs(1);
        }
        backoff.record(ip);
        let until = backoff.inner.read().get(&ip).unwrap().backoff_until;
        assert!(
            until - now >= Duration::from_secs(3_500),
            "退避到期后再 record 应继续增长, until-now={:?}",
            until - now
        );
    }

    #[test]
    fn cap_compresses_backoff_to_nat_change_window() {
        let backoff = PunchBackoff::default();
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        // 连续 record 多次把退避推高到接近 1h 上限
        for _ in 0..2000 {
            backoff.record(ip);
        }
        let now = Instant::now();
        {
            let state = backoff.inner.read();
            let until = state.get(&ip).unwrap().backoff_until;
            assert!(
                until - now >= Duration::from_secs(3_500),
                "退避应逼近1h上限, until-now={:?}",
                until - now
            );
        }
        backoff.cap(ip);
        backoff.cap_all();
        let now = Instant::now();
        {
            let state = backoff.inner.read();
            let state = state.get(&ip).unwrap();
            assert_eq!(state.count, 0, "NAT变化后增长指数应归零");
            let until = state.backoff_until;
            assert!(
                until >= now && until - now <= Duration::from_secs(600),
                "NAT变化后退避应压缩到10分钟内, until-now={:?}",
                until.saturating_duration_since(now)
            );
        }
    }

    #[test]
    fn record_after_cap_restarts_from_base() {
        let backoff = PunchBackoff::default();
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        for _ in 0..2000 {
            backoff.record(ip);
        }
        backoff.cap(ip);
        // cap 后再 record：退避应从 BASE 重新起步，而不是瞬间涨回原高度
        backoff.record(ip);
        let now = Instant::now();
        let until = backoff.inner.read().get(&ip).unwrap().backoff_until;
        assert!(
            until - now <= Duration::from_secs(600),
            "cap后再record不应瞬间涨回1h, until-now={:?}",
            until - now
        );
    }

    #[test]
    fn my_nat_info_notifies_only_on_identity_change() {
        let nat = MyNatInfo::default();
        let notified = Arc::new(AtomicUsize::new(0));
        let counter = notified.clone();
        nat.set_on_change(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let local = Ipv4Addr::new(192, 168, 1, 2);
        let cone = nat_info(NatType::Cone, vec![], vec![1000], local);
        // 首次设置不算变化
        nat.replace_nat_info(cone.clone());
        assert_eq!(notified.load(Ordering::SeqCst), 0);
        // 完全相同不触发
        nat.replace_nat_info(cone.clone());
        assert_eq!(notified.load(Ordering::SeqCst), 0);
        // Cone 端口变化 → 触发
        nat.replace_nat_info(nat_info(NatType::Cone, vec![], vec![2000], local));
        assert_eq!(notified.load(Ordering::SeqCst), 1);
        // NAT 类型变化 → 触发
        nat.replace_nat_info(nat_info(NatType::Symmetric, vec![], vec![3000], local));
        assert_eq!(notified.load(Ordering::SeqCst), 2);
        // 对称 NAT 端口抖动 → 不触发
        nat.replace_nat_info(nat_info(NatType::Symmetric, vec![], vec![3001], local));
        assert_eq!(notified.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn update_public_addr_notifies_per_rules() {
        let nat = MyNatInfo::default();
        let notified = Arc::new(AtomicUsize::new(0));
        let counter = notified.clone();
        nat.set_on_change(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let local = Ipv4Addr::new(192, 168, 1, 2);
        let exit_ip = Ipv4Addr::new(8, 8, 8, 8);
        nat.replace_nat_info(nat_info(
            NatType::Symmetric,
            vec![exit_ip],
            vec![1000],
            local,
        ));
        assert_eq!(notified.load(Ordering::SeqCst), 0);

        let addr: SocketAddr = "8.8.8.8:2222".parse().unwrap();
        // 对称 NAT：公网 IP 不变、仅同索引端口更新 → 不触发
        nat.update_public_addr(addr);
        assert_eq!(notified.load(Ordering::SeqCst), 0);

        // Cone：端口更新 → 触发
        nat.replace_nat_info(nat_info(NatType::Cone, vec![exit_ip], vec![1000], local));
        assert_eq!(notified.load(Ordering::SeqCst), 1);
        nat.update_public_addr(addr);
        assert_eq!(notified.load(Ordering::SeqCst), 2);
    }
}
