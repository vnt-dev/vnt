use std::net::SocketAddr;

pub mod channel;
pub mod punch;
pub mod idle;
pub mod sender;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Status {
    Cone,
    Symmetric,
    Close,
}

#[derive(Copy, Clone, Debug)]
pub struct Route {
    index: usize,
    pub addr: SocketAddr,
    pub metric: u8,
    pub rt: i64,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteSortKey {
    pub metric: u8,
    pub rt: i64,
}

impl Route {
    pub fn new(index: usize,
               addr: SocketAddr, metric: u8, rt: i64, ) -> Self {
        Self {
            index,
            addr,
            metric,
            rt,
        }
    }
    pub fn from(route_key: RouteKey, metric: u8, rt: i64) -> Self {
        Self {
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt,
        }
    }
    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            index: self.index,
            addr: self.addr,
        }
    }
    pub fn sort_key(&self) -> RouteSortKey {
        RouteSortKey {
            metric: self.metric,
            rt: self.rt,
        }
    }
    pub fn is_p2p(&self) -> bool {
        self.metric == 1
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteKey {
    index: usize,
    pub addr: SocketAddr,
}

impl RouteKey {
    pub(crate) fn new(index: usize,
                      addr: SocketAddr, ) -> Self {
        Self {
            index,
            addr,
        }
    }
}