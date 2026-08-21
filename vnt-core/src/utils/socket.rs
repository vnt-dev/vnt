use anyhow::Context;
use rust_p2p_core::socket::LocalInterface;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub(crate) struct ResolvedInterface {
    pub(crate) name: String,
    pub(crate) socket_interface: LocalInterface,
}

/// 将配置中的网卡名称解析为底层 Socket 所需的接口标识。
/// Linux/Android 使用名称绑定，Windows/macOS 使用接口索引。
pub(crate) fn resolve_interface(name: Option<&str>) -> anyhow::Result<Option<ResolvedInterface>> {
    let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) else {
        return Ok(None);
    };

    let (canonical_name, index) = match getifaddrs::if_nametoindex(name) {
        Ok(index) => (
            getifaddrs::if_indextoname(index).unwrap_or_else(|_| name.to_owned()),
            index,
        ),
        Err(_) => {
            let interface = getifaddrs::getifaddrs()
                .context("读取本机网卡列表失败")?
                .find(|interface| {
                    if interface.name.eq_ignore_ascii_case(name) {
                        return true;
                    }
                    #[cfg(windows)]
                    {
                        interface.description.eq_ignore_ascii_case(name)
                    }
                    #[cfg(not(windows))]
                    {
                        false
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("找不到出口网卡 '{name}'"))?;
            let index = interface
                .index
                .ok_or_else(|| anyhow::anyhow!("出口网卡 '{}' 没有可用索引", interface.name))?;
            (interface.name, index)
        }
    };

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let interface = LocalInterface::new(canonical_name.clone());

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let interface = LocalInterface::new(index);

    // Linux/Android 只用名称，但仍执行 if_nametoindex 来提前校验配置。
    let _ = index;
    Ok(Some(ResolvedInterface {
        name: canonical_name,
        socket_interface: interface,
    }))
}

pub(crate) trait SocketTrait {
    fn set_ip_unicast_if(&self, _interface: &LocalInterface) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl SocketTrait for Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> io::Result<()> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            IP_UNICAST_IF, IPPROTO_IP, SOCKET_ERROR, htonl, setsockopt,
        };

        let raw_socket = self.as_raw_socket();
        let result = unsafe {
            let best_interface = htonl(interface.index);
            setsockopt(
                raw_socket as usize,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &best_interface as *const _ as *const u8,
                std::mem::size_of_val(&best_interface) as i32,
            )
        };
        if result == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SocketTrait for Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> io::Result<()> {
        self.bind_device(Some(interface.name.as_bytes()))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl SocketTrait for Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> io::Result<()> {
        self.bind_device_by_index_v4(std::num::NonZeroU32::new(interface.index))
    }
}

#[cfg(target_os = "freebsd")]
impl SocketTrait for Socket {}

pub(crate) fn bind_socket_to_interface(
    socket: &Socket,
    interface: Option<&LocalInterface>,
    is_ipv4: bool,
) -> io::Result<()> {
    if is_ipv4 && let Some(interface) = interface {
        socket.set_ip_unicast_if(interface)?;
    }
    Ok(())
}

pub(crate) fn bind_udp(
    addr: SocketAddr,
    interface: Option<&LocalInterface>,
) -> io::Result<tokio::net::UdpSocket> {
    let socket = rust_p2p_core::socket::bind_udp(addr, interface)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

pub(crate) async fn connect_tcp(
    addr: SocketAddr,
    interface: Option<&LocalInterface>,
) -> io::Result<tokio::net::TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    bind_socket_to_interface(
        &socket,
        interface,
        addr.is_ipv4() && !addr.ip().is_loopback(),
    )?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;

    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => {}
        #[cfg(unix)]
        Err(ref error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(error) => return Err(error),
    }

    let stream = tokio::net::TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}

pub(crate) async fn connect_tcp_resolved<A: tokio::net::ToSocketAddrs>(
    addr: A,
    interface: Option<&LocalInterface>,
) -> io::Result<tokio::net::TcpStream> {
    let addrs = tokio::net::lookup_host(addr).await?.collect::<Vec<_>>();
    let mut last_error = None;
    for addr in addrs {
        match connect_tcp(addr, interface).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("目标地址解析结果为空")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_interface_name_disables_binding() {
        assert!(resolve_interface(None).unwrap().is_none());
        assert!(resolve_interface(Some("   ")).unwrap().is_none());
    }

    #[test]
    fn invalid_interface_name_is_rejected() {
        let name = "vnt-interface-that-must-not-exist";
        assert!(resolve_interface(Some(name)).is_err());
    }

    #[test]
    fn existing_interface_name_resolves() {
        let interface = getifaddrs::getifaddrs()
            .unwrap()
            .find(|interface| interface.index.is_some())
            .expect("at least one indexed interface");
        let resolved = resolve_interface(Some(&interface.name)).unwrap().unwrap();
        assert_eq!(resolved.name, interface.name);

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        assert_eq!(resolved.socket_interface.index, interface.index.unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn windows_friendly_name_resolves() {
        let interface = getifaddrs::getifaddrs()
            .unwrap()
            .find(|interface| interface.index.is_some() && !interface.description.is_empty())
            .expect("at least one described interface");
        let resolved = resolve_interface(Some(&interface.description))
            .unwrap()
            .unwrap();
        assert_eq!(resolved.socket_interface.index, interface.index.unwrap());
    }
}
