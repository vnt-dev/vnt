use parking_lot::RwLock;
use rust_p2p_core::nat::NatInfo;
use rust_p2p_core::route::Index;
use rust_p2p_core::tunnel::udp::UDPIndex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct MyNatInfo {
    nat_info: Arc<RwLock<Option<NatInfo>>>,
}
impl MyNatInfo {
    pub fn get(&self) -> Option<NatInfo> {
        self.nat_info.read().clone()
    }
    pub fn update_public_addr(&self, index: Index, addr: SocketAddr) {
        let (ip, port) = if let Some(r) = mapping_addr(addr) {
            r
        } else {
            return;
        };
        log::debug!("public_addr:{},{},index={index:?}", ip, port);
        let mut nat_info = self.nat_info.write();
        let Some(nat_info) = nat_info.as_mut() else {
            return;
        };
        if rust_p2p_core::extend::addr::is_ipv4_global(&ip) {
            if !nat_info.public_ips.contains(&ip) {
                nat_info.public_ips.push(ip);
            }
            match index {
                Index::Udp(index) => {
                    let index = match index {
                        UDPIndex::MainV4(index) => index,
                        UDPIndex::MainV6(index) => index,
                        UDPIndex::SubV4(_) => return,
                    };
                    if let Some(p) = nat_info.public_udp_ports.get_mut(index) {
                        *p = port;
                    }
                }
                Index::Tcp(_) => {
                    nat_info.public_tcp_port = port;
                }
                _ => {}
            }
        } else {
            log::debug!("not public addr: {addr:?}")
        }
    }
    pub fn update_tcp_public_addr(&self, addr: SocketAddr) {
        let SocketAddr::V4(addr) = addr else {
            return;
        };
        let ip = *addr.ip();
        let port = addr.port();
        log::info!("tcp_public_addr, {}:{}", ip, port);
        let mut nat_info = self.nat_info.write();
        let Some(nat_info) = nat_info.as_mut() else {
            return;
        };
        if ip.is_unspecified() && port == 0 {
            nat_info.public_tcp_port = 0;
            return;
        }
        if rust_p2p_core::extend::addr::is_ipv4_global(&ip) {
            if !nat_info.public_ips.contains(&ip) {
                nat_info.public_ips.push(ip);
            }
            nat_info.public_tcp_port = port;
        } else {
            log::debug!("not public addr: {addr:?}")
        }
    }
    pub fn replace_nat_info(&self, nat_info: NatInfo) {
        self.nat_info.write().replace(nat_info);
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
    pub count: i64,
    pub last_ts: i64,
}

#[derive(Clone, Default)]
pub struct PunchBackoff {
    inner: Arc<RwLock<HashMap<Ipv4Addr, PunchState>>>,
}

impl PunchBackoff {
    const MAX_BACKOFF_MS: i64 = 3_600_000; // 1h
    const BASE_MS: i64 = 3000;

    fn now() -> i64 {
        crate::utils::time::now_ts_ms()
    }

    pub fn record(&self, ip: Ipv4Addr) {
        let mut map = self.inner.write();
        let entry = map.entry(ip).or_insert(PunchState {
            count: 0,
            last_ts: 0,
        });
        entry.count += 1;
        entry.last_ts = Self::now();
    }
    #[allow(dead_code)]
    pub fn reset(&self, ip: Ipv4Addr) {
        self.inner.write().remove(&ip);
    }
    #[allow(dead_code)]
    pub fn get(&self, ip: &Ipv4Addr) -> Option<PunchState> {
        self.inner.read().get(ip).copied()
    }

    pub fn should_punch(&self, ip: Ipv4Addr) -> bool {
        let map = self.inner.read();
        let Some(state) = map.get(&ip) else {
            return true;
        };

        let now = Self::now();
        let elapsed = now - state.last_ts;

        let mut backoff = Self::BASE_MS * state.count;
        if backoff > Self::MAX_BACKOFF_MS {
            backoff = Self::MAX_BACKOFF_MS;
        }

        elapsed >= backoff
    }
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.inner.write().clear();
    }
}
