use std::net::SocketAddr;

pub mod channel;
pub mod idle;
pub mod punch;
pub mod sender;

const TCP_ID: usize = 0;
const UDP_ID: usize = 1;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Status {
    Cone,
    Symmetric,
    Close,
}

#[derive(Copy, Clone, Debug)]
pub struct Route {
    pub is_tcp: bool,
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
    pub fn new(is_tcp: bool, index: usize, addr: SocketAddr, metric: u8, rt: i64) -> Self {
        Self {
            is_tcp,
            index,
            addr,
            metric,
            rt,
        }
    }
    pub fn from(route_key: RouteKey, metric: u8, rt: i64) -> Self {
        Self {
            is_tcp: route_key.is_tcp,
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt,
        }
    }
    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            is_tcp: self.is_tcp,
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
    is_tcp: bool,
    index: usize,
    pub addr: SocketAddr,
}

impl RouteKey {
    pub(crate) fn new(is_tcp: bool, index: usize, addr: SocketAddr) -> Self {
        Self {
            is_tcp,
            index,
            addr,
        }
    }
    pub fn is_tcp(&self) -> bool {
        self.index == TCP_ID
    }
}
