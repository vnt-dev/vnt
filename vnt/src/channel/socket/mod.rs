use anyhow::{anyhow, Context};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use socket2::Protocol;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub trait VntSocketTrait {
    fn set_ip_unicast_if(&self, _interface: &LocalInterface) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct LocalInterface {
    index: u32,
    #[cfg(unix)]
    name: Option<String>,
}

pub async fn connect_tcp(
    addr: SocketAddr,
    bind_port: u16,
    default_interface: &LocalInterface,
) -> anyhow::Result<tokio::net::TcpStream> {
    let socket = create_tcp0(addr.is_ipv4(), bind_port, default_interface)?;
    Ok(socket.connect(addr).await?)
}
pub fn create_tcp(
    v4: bool,
    default_interface: &LocalInterface,
) -> anyhow::Result<tokio::net::TcpSocket> {
    create_tcp0(v4, 0, default_interface)
}
pub fn create_tcp0(
    v4: bool,
    bind_port: u16,
    default_interface: &LocalInterface,
) -> anyhow::Result<tokio::net::TcpSocket> {
    let socket = if v4 {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(Protocol::TCP),
        )?
    } else {
        socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(Protocol::TCP),
        )?
    };
    if v4 {
        if let Err(e) = socket.set_ip_unicast_if(default_interface) {
            log::warn!("set_ip_unicast_if {:?}", e)
        }
    }
    if bind_port != 0 {
        socket
            .set_reuse_address(true)
            .context("set_reuse_address")?;
        #[cfg(unix)]
        if let Err(e) = socket.set_reuse_port(true) {
            log::warn!("set_reuse_port {:?}", e)
        }
        if v4 {
            let addr: SocketAddr = format!("0.0.0.0:{}", bind_port).parse().unwrap();
            socket.bind(&addr.into())?;
        } else {
            socket.set_only_v6(true)?;
            let addr: SocketAddr = format!("[::]:{}", bind_port).parse().unwrap();
            socket.bind(&addr.into())?;
        }
    }
    socket.set_nonblocking(true)?;
    socket.set_nodelay(true)?;
    Ok(tokio::net::TcpSocket::from_std_stream(socket.into()))
}
pub fn bind_udp_ops(
    addr: SocketAddr,
    only_v6: bool,
    default_interface: &LocalInterface,
) -> anyhow::Result<socket2::Socket> {
    let socket = if addr.is_ipv4() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if let Err(e) = socket.set_ip_unicast_if(default_interface) {
            log::warn!("set_ip_unicast_if {:?}", e)
        }
        socket
    } else {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        socket
            .set_only_v6(only_v6)
            .with_context(|| format!("set_only_v6 failed: {}", &addr))?;
        socket
    };
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}
pub fn bind_udp(
    addr: SocketAddr,
    default_interface: &LocalInterface,
) -> anyhow::Result<socket2::Socket> {
    bind_udp_ops(addr, true, default_interface).with_context(|| format!("{}", addr))
}

pub fn get_interface(dest_name: String) -> anyhow::Result<(LocalInterface, Ipv4Addr)> {
    let network_interfaces = NetworkInterface::show()?;
    for iface in network_interfaces {
        if iface.name == dest_name {
            for addr in iface.addr {
                if let IpAddr::V4(ip) = addr.ip() {
                    return Ok((
                        LocalInterface {
                            index: iface.index,
                            #[cfg(unix)]
                            name: Some(iface.name),
                        },
                        ip,
                    ));
                }
            }
        }
    }
    Err(anyhow!("No network card with name {} found", dest_name))
}
