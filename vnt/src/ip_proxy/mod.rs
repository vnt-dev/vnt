use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;

use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::handle::CurrentDeviceInfo;
use crate::ip_proxy::icmp_proxy::IcmpProxy;
use crate::ip_proxy::tcp_proxy::TcpProxy;
use crate::ip_proxy::udp_proxy::UdpProxy;
use crate::util::StopManager;

pub mod icmp_proxy;
pub mod tcp_proxy;
pub mod udp_proxy;

pub trait ProxyHandler {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool>;
    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()>;
}

#[derive(Clone)]
pub struct IpProxyMap {
    icmp_proxy: IcmpProxy,
    tcp_proxy: TcpProxy,
    udp_proxy: UdpProxy,
}

pub fn init_proxy(
    context: ChannelContext,
    stop_manager: StopManager,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
) -> anyhow::Result<IpProxyMap> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ipProxy")
        .build()?;
    let proxy_map = runtime.block_on(init_proxy0(context, current_device, client_cipher))?;
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    let worker = stop_manager.add_listener("ipProxy".into(), move || {
        let _ = sender.send(());
    })?;
    thread::Builder::new()
        .name("ipProxy".into())
        .spawn(move || {
            runtime.block_on(async {
                let _ = receiver.await;
            });
            runtime.shutdown_background();
            drop(worker);
        })?;

    return Ok(proxy_map);
}

async fn init_proxy0(
    context: ChannelContext,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
) -> anyhow::Result<IpProxyMap> {
    let icmp_proxy = IcmpProxy::new(context, current_device, client_cipher).await?;
    let tcp_proxy = TcpProxy::new().await?;
    let udp_proxy = UdpProxy::new().await?;

    Ok(IpProxyMap {
        icmp_proxy,
        tcp_proxy,
        udp_proxy,
    })
}

impl ProxyHandler for IpProxyMap {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        match ipv4.protocol() {
            ipv4::protocol::Protocol::Tcp => self.tcp_proxy.recv_handle(ipv4, source, destination),
            ipv4::protocol::Protocol::Udp => self.udp_proxy.recv_handle(ipv4, source, destination),
            ipv4::protocol::Protocol::Icmp => {
                self.icmp_proxy.recv_handle(ipv4, source, destination)
            }
            _ => {
                log::warn!(
                    "不支持的ip代理ipv4协议{:?}:{}->{}->{}",
                    ipv4.protocol(),
                    source,
                    destination,
                    ipv4.destination_ip()
                );
                Ok(false)
            }
        }
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        match ipv4.protocol() {
            ipv4::protocol::Protocol::Tcp => self.tcp_proxy.send_handle(ipv4),
            ipv4::protocol::Protocol::Udp => self.udp_proxy.send_handle(ipv4),
            ipv4::protocol::Protocol::Icmp => self.icmp_proxy.send_handle(ipv4),
            _ => Ok(()),
        }
    }
}
