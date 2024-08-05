use crate::channel::socket::LocalInterface;
use crossbeam_utils::atomic::AtomicCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub mod callback;
mod extension;
pub mod handshaker;
pub mod maintain;
pub mod recv_data;
pub mod registrar;
#[cfg(feature = "integrated_tun")]
pub mod tun_tap;

const SELF_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 2);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 1);

pub fn now_time() -> u64 {
    let now = std::time::SystemTime::now();
    if let Ok(timestamp) = now.duration_since(std::time::UNIX_EPOCH) {
        timestamp.as_secs() * 1000 + u64::from(timestamp.subsec_millis())
    } else {
        0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDeviceInfo {
    pub virtual_ip: Ipv4Addr,
    pub name: String,
    pub status: PeerDeviceStatus,
    pub client_secret: bool,
    pub client_secret_hash: Vec<u8>,
    pub wireguard: bool,
}

impl PeerDeviceInfo {
    pub fn new(
        virtual_ip: Ipv4Addr,
        name: String,
        status: u8,
        client_secret: bool,
        client_secret_hash: Vec<u8>,
        wireguard: bool,
    ) -> Self {
        Self {
            virtual_ip,
            name,
            status: PeerDeviceStatus::from(status),
            client_secret,
            client_secret_hash,
            wireguard,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BaseConfigInfo {
    pub name: String,
    pub token: String,
    pub ip: Option<Ipv4Addr>,
    pub client_secret_hash: Option<[u8; 16]>,
    pub server_secret: bool,
    pub device_id: String,
    pub server_addr: String,
    pub name_servers: Vec<String>,
    pub mtu: u32,
    #[cfg(feature = "integrated_tun")]
    #[cfg(target_os = "windows")]
    pub tap: bool,
    #[cfg(feature = "integrated_tun")]
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub device_name: Option<String>,
    pub allow_wire_guard: bool,
    pub default_interface: LocalInterface,
}

impl BaseConfigInfo {
    pub fn new(
        name: String,
        token: String,
        ip: Option<Ipv4Addr>,
        client_secret_hash: Option<[u8; 16]>,
        server_secret: bool,
        device_id: String,
        server_addr: String,
        name_servers: Vec<String>,
        mtu: u32,
        #[cfg(feature = "integrated_tun")]
        #[cfg(target_os = "windows")]
        tap: bool,
        #[cfg(feature = "integrated_tun")]
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        device_name: Option<String>,
        allow_wire_guard: bool,
        default_interface: LocalInterface,
    ) -> Self {
        Self {
            name,
            token,
            ip,
            client_secret_hash,
            server_secret,
            device_id,
            server_addr,
            name_servers,
            mtu,
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            tap,
            #[cfg(feature = "integrated_tun")]
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            device_name,
            allow_wire_guard,
            default_interface,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PeerDeviceStatus {
    Online,
    Offline,
}

impl PeerDeviceStatus {
    pub fn is_online(&self) -> bool {
        self == &PeerDeviceStatus::Online
    }
    pub fn is_offline(&self) -> bool {
        self == &PeerDeviceStatus::Offline
    }
}

impl Into<u8> for PeerDeviceStatus {
    fn into(self) -> u8 {
        match self {
            PeerDeviceStatus::Online => 0,
            PeerDeviceStatus::Offline => 1,
        }
    }
}

impl From<u8> for PeerDeviceStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PeerDeviceStatus::Online,
            _ => PeerDeviceStatus::Offline,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConnectStatus {
    Connecting,
    Connected,
}

impl ConnectStatus {
    pub fn online(&self) -> bool {
        self == &ConnectStatus::Connected
    }
    pub fn offline(&self) -> bool {
        self == &ConnectStatus::Connecting
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CurrentDeviceInfo {
    //本机虚拟IP
    pub virtual_ip: Ipv4Addr,
    //子网掩码
    pub virtual_netmask: Ipv4Addr,
    //虚拟网关
    pub virtual_gateway: Ipv4Addr,
    //网络地址
    pub virtual_network: Ipv4Addr,
    //直接广播地址
    pub broadcast_ip: Ipv4Addr,
    //链接的服务器地址
    pub connect_server: SocketAddr,
    //连接状态
    pub status: ConnectStatus,
}

impl CurrentDeviceInfo {
    pub fn new(
        virtual_ip: Ipv4Addr,
        virtual_netmask: Ipv4Addr,
        virtual_gateway: Ipv4Addr,
        connect_server: SocketAddr,
    ) -> Self {
        let broadcast_ip = (!u32::from_be_bytes(virtual_netmask.octets()))
            | u32::from_be_bytes(virtual_gateway.octets());
        let broadcast_ip = Ipv4Addr::from(broadcast_ip);
        let virtual_network = u32::from_be_bytes(virtual_netmask.octets())
            & u32::from_be_bytes(virtual_gateway.octets());
        let virtual_network = Ipv4Addr::from(virtual_network);
        Self {
            virtual_ip,
            virtual_netmask,
            virtual_gateway,
            virtual_network,
            broadcast_ip,
            connect_server,
            status: ConnectStatus::Connecting,
        }
    }
    pub fn new0(connect_server: SocketAddr) -> Self {
        Self {
            virtual_ip: Ipv4Addr::UNSPECIFIED,
            virtual_gateway: Ipv4Addr::UNSPECIFIED,
            virtual_netmask: Ipv4Addr::UNSPECIFIED,
            virtual_network: Ipv4Addr::UNSPECIFIED,
            broadcast_ip: Ipv4Addr::UNSPECIFIED,
            connect_server,
            status: ConnectStatus::Connecting,
        }
    }
    pub fn update(
        &mut self,
        virtual_ip: Ipv4Addr,
        virtual_netmask: Ipv4Addr,
        virtual_gateway: Ipv4Addr,
    ) {
        let broadcast_ip = (!u32::from_be_bytes(virtual_netmask.octets()))
            | u32::from_be_bytes(virtual_ip.octets());
        let broadcast_ip = Ipv4Addr::from(broadcast_ip);
        let virtual_network =
            u32::from_be_bytes(virtual_netmask.octets()) & u32::from_be_bytes(virtual_ip.octets());
        let virtual_network = Ipv4Addr::from(virtual_network);
        self.virtual_ip = virtual_ip;
        self.virtual_netmask = virtual_netmask;
        self.virtual_gateway = virtual_gateway;
        self.broadcast_ip = broadcast_ip;
        self.virtual_network = virtual_network;
    }
    #[inline]
    pub fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }
    #[inline]
    pub fn virtual_gateway(&self) -> Ipv4Addr {
        self.virtual_gateway
    }
    #[inline]
    pub fn is_gateway(&self, ip: &Ipv4Addr) -> bool {
        &self.virtual_gateway == ip || ip == &GATEWAY_IP
    }
    #[inline]
    pub fn not_in_network(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & u32::from(self.virtual_netmask) != u32::from(self.virtual_network)
    }
    pub fn is_server_addr(&self, addr: SocketAddr) -> bool {
        if self.connect_server == addr {
            return true;
        }
        let f = |ip: IpAddr| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4(),
        };
        addr.port() == self.connect_server.port() && f(addr.ip()) == f(self.connect_server.ip())
    }
}
pub fn change_status(
    current_device: &AtomicCell<CurrentDeviceInfo>,
    connect_status: ConnectStatus,
) -> CurrentDeviceInfo {
    loop {
        let cur = current_device.load();
        let mut new_info = cur;
        new_info.status = connect_status;
        if current_device.compare_exchange(cur, new_info).is_ok() {
            return new_info;
        }
    }
}
