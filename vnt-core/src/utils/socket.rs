use anyhow::Context;
use rustp2p_core::socket::LocalInterface;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// TCP 连接建立（connect + 可写确认）超时
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    fn set_ip_unicast_if(&self, _interface: &LocalInterface, _is_ipv6: bool) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl SocketTrait for Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface, is_ipv6: bool) -> io::Result<()> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, htonl,
            setsockopt,
        };

        let raw_socket = self.as_raw_socket();
        // Windows 的 IPv4 接口索引用网络字节序，IPV6_UNICAST_IF 用主机字节序
        let best_interface = if is_ipv6 {
            interface.index
        } else {
            unsafe { htonl(interface.index) }
        };
        let (level, option) = if is_ipv6 {
            (IPPROTO_IPV6, IPV6_UNICAST_IF)
        } else {
            (IPPROTO_IP, IP_UNICAST_IF)
        };
        let result = unsafe {
            setsockopt(
                raw_socket as usize,
                level,
                option,
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
    fn set_ip_unicast_if(&self, interface: &LocalInterface, _is_ipv6: bool) -> io::Result<()> {
        self.bind_device(Some(interface.name.as_bytes()))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl SocketTrait for Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface, is_ipv6: bool) -> io::Result<()> {
        let index = std::num::NonZeroU32::new(interface.index);
        if is_ipv6 {
            self.bind_device_by_index_v6(index)
        } else {
            self.bind_device_by_index_v4(index)
        }
    }
}

#[cfg(target_os = "freebsd")]
impl SocketTrait for Socket {}

pub(crate) fn bind_socket_to_interface(
    socket: &Socket,
    interface: Option<&LocalInterface>,
    is_ipv6: bool,
) -> io::Result<()> {
    if let Some(interface) = interface {
        socket.set_ip_unicast_if(interface, is_ipv6)?;
    }
    Ok(())
}

pub(crate) fn bind_udp(
    addr: SocketAddr,
    interface: Option<&LocalInterface>,
) -> io::Result<tokio::net::UdpSocket> {
    let socket = rustp2p_core::socket::bind_udp(addr, interface)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

pub(crate) async fn connect_tcp(
    addr: SocketAddr,
    interface: Option<&LocalInterface>,
) -> io::Result<tokio::net::TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if !addr.ip().is_loopback() {
        bind_socket_to_interface(&socket, interface, addr.is_ipv6())?;
    }
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
    // connect 后的可写确认必须在超时内完成，否则不可达地址会挂住任务直到
    // 操作系统超时（Windows 约 21s、Linux 约 127s）
    tokio::time::timeout(CONNECT_TIMEOUT, stream.writable())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect to {addr} timed out after {CONNECT_TIMEOUT:?}"),
            )
        })??;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}

/// Connects to `addr` while binding the outgoing socket to an existing local
/// TCP listener port. This is used by TCP STUN so the observed public mapping
/// belongs to the P2P listener rather than to an unrelated ephemeral port.
pub(crate) async fn connect_tcp_reuse_port(
    addr: SocketAddr,
    local_port: u16,
    local_ipv4: std::net::Ipv4Addr,
    interface: Option<&LocalInterface>,
) -> io::Result<tokio::net::TcpStream> {
    if !addr.is_ipv4() || local_ipv4.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP STUN port reuse requires a concrete local IPv4 address",
        ));
    }
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // 该路径仅用于 IPv4（上方已拦截），绑定传输族为 IPv4
    if !addr.ip().is_loopback() {
        bind_socket_to_interface(&socket, interface, false)?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    let local_addr = SocketAddr::from((local_ipv4, local_port));
    socket.bind(&local_addr.into())?;
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
    tokio::time::timeout(CONNECT_TIMEOUT, stream.writable())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect to {addr} timed out after {CONNECT_TIMEOUT:?}"),
            )
        })??;
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

    #[tokio::test]
    async fn tcp_stun_connection_reuses_the_p2p_listener_port() {
        let p2p_listener = rustp2p_core::endpoint::TunnelIncoming::bind(
            rustp2p_core::endpoint::Config::tcp(0).enable_ipv6(false),
        )
        .await
        .unwrap();
        let local_port = p2p_listener
            .local_tcp_addr()
            .map(|addr| addr.port())
            .unwrap_or_default();
        let stun_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_listener.local_addr().unwrap();

        let accept = tokio::spawn(async move { stun_listener.accept().await.unwrap() });
        let stream =
            connect_tcp_reuse_port(stun_addr, local_port, std::net::Ipv4Addr::LOCALHOST, None)
                .await
                .unwrap();
        let (_accepted, peer_addr) = accept.await.unwrap();

        assert_eq!(stream.local_addr().unwrap().port(), local_port);
        assert_eq!(peer_addr.port(), local_port);
    }

    #[tokio::test]
    async fn tcp_stun_connection_reports_connect_failure() {
        let p2p_listener = rustp2p_core::endpoint::TunnelIncoming::bind(
            rustp2p_core::endpoint::Config::tcp(0).enable_ipv6(false),
        )
        .await
        .unwrap();
        let local_port = p2p_listener
            .local_tcp_addr()
            .map(|addr| addr.port())
            .unwrap_or_default();
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let result =
            connect_tcp_reuse_port(closed_addr, local_port, std::net::Ipv4Addr::LOCALHOST, None)
                .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tcp_stun_connections_can_reuse_the_listener_port_concurrently() {
        let p2p_listener = rustp2p_core::endpoint::TunnelIncoming::bind(
            rustp2p_core::endpoint::Config::tcp(0).enable_ipv6(false),
        )
        .await
        .unwrap();
        let local_port = p2p_listener
            .local_tcp_addr()
            .map(|addr| addr.port())
            .unwrap_or_default();
        let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_listener.local_addr().unwrap();
        let second_addr = second_listener.local_addr().unwrap();

        let first_accept = tokio::spawn(async move { first_listener.accept().await.unwrap() });
        let second_accept = tokio::spawn(async move { second_listener.accept().await.unwrap() });

        let (first, second) = tokio::join!(
            connect_tcp_reuse_port(first_addr, local_port, std::net::Ipv4Addr::LOCALHOST, None,),
            connect_tcp_reuse_port(second_addr, local_port, std::net::Ipv4Addr::LOCALHOST, None,),
        );

        assert_eq!(first.unwrap().local_addr().unwrap().port(), local_port);
        assert_eq!(second.unwrap().local_addr().unwrap().port(), local_port);
        first_accept.await.unwrap();
        second_accept.await.unwrap();
    }

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
