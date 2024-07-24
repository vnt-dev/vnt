use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch::{channel, Sender};

use lwip_rs::stack::{NetStack, NetStackWrite};
use lwip_rs::tcp_listener::TcpListener as LwIPTcpListener;
use lwip_rs::udp::{UdpSocket as LwIpUdpSocket, UdpSocketWrite};
use vnt::channel::BUFFER_SIZE;
use vnt::core::{Config, Vnt};
use vnt::packet::ip::ipv4::packet::IpV4Packet;
use vnt::protocol::HEAD_LEN;
use vnt::vnt_device::DeviceWrite;
use vnt::VntCallback;

use crate::config::{LinkItem, LinkProtocol, VnLinkConfig};
use crate::{in_mapping, out_mapping};

pub struct VnLink {
    vnt: Vnt,
    in_udp_map: Arc<
        Mutex<
            HashMap<
                (SocketAddr, SocketAddr),
                (Arc<UdpSocket>, Option<SocketAddr>, Arc<AtomicCell<Instant>>),
            >,
        >,
    >,
    lwip_udp_write: UdpSocketWrite,
    shutdown_tx: Sender<bool>,
}

impl VnLink {
    pub async fn new<Call: VntCallback>(
        vnt_config: Config,
        vn_link_config: VnLinkConfig,
        callback: Call,
    ) -> anyhow::Result<Self> {
        let stack = NetStack::new(HEAD_LEN, 1024, vnt_config.mtu.unwrap_or(1420) as u16).await;
        let udp = LwIpUdpSocket::new()?;
        let tcp_listener = LwIPTcpListener::new()?;
        let (shutdown_tx, shutdown_rx) = channel(false);
        let (net_stack_write, mut net_stack_read) = stack.into_split();
        let vnt = Vnt::new_device(vnt_config, callback, VntDevice { net_stack_write })?;
        let shutdown_tx_ = shutdown_tx.clone();
        let w = vnt.add_stop_listener("vnt-link".into(), move || {
            let _ = shutdown_tx_.send(true);
        })?;
        let ip_sender = vnt.ipv4_packet_sender().unwrap();
        let mut shutdown_rx_ = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut extend = [0; BUFFER_SIZE];
            loop {
                tokio::select! {
                    _ = shutdown_rx_.changed() => {
                        break;
                    }
                    rs = net_stack_read.recv_ip() => {
                         match rs{
                              Ok((mut buf, start_index, len)) => {
                                let ipv4_packet = if let Ok(packet) =
                                     IpV4Packet::new(&buf[start_index..len])
                                {
                                    packet
                                } else {
                                    continue;
                                };
                                let destination_ip = ipv4_packet.destination_ip();
                                let source_ip = ipv4_packet.source_ip();

                                if let Err(e) = ip_sender.send_ip(&mut buf, len, &mut extend, destination_ip) {
                                    log::warn!("{}->{},{}", source_ip, destination_ip, e);
                                }
                            },
                            Err(e) => {
                                log::error!("net_stack_read {:?}", e);
                                break;
                            }
                        };
                    }
                }
            }
            w.stop_all();
        });

        let (lwip_udp_write, lwip_udp_read) = udp.into_split();
        let in_udp_map: Arc<
            Mutex<
                HashMap<
                    (SocketAddr, SocketAddr),
                    (Arc<UdpSocket>, Option<SocketAddr>, Arc<AtomicCell<Instant>>),
                >,
            >,
        > = Arc::new(Mutex::new(HashMap::new()));

        let current_device_info = vnt.current_device_info();
        let in_udp_map_ = in_udp_map.clone();
        let lwip_udp_write_ = lwip_udp_write.clone();
        let vnt_ = vnt.clone();
        let mut shutdown_rx_ = shutdown_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown_rx_.changed() => {}
                _ = out_mapping::udp::udp_mapping_start(
                    lwip_udp_write_,
                    lwip_udp_read,
                    current_device_info,
                    in_udp_map_,
                ) => {}
            }

            vnt_.stop();
        });
        let current_device_info = vnt.current_device_info();
        let vnt_ = vnt.clone();
        let mut shutdown_rx_ = shutdown_rx.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown_rx_.changed() => {}
                _ = out_mapping::tcp::tcp_mapping_listen(tcp_listener, current_device_info) => {}
            }
            vnt_.stop();
        });
        let link = Self {
            vnt,
            in_udp_map,
            lwip_udp_write,
            shutdown_tx,
        };
        link.add_mapping(vn_link_config.mapping).await?;
        Ok(link)
    }
    pub async fn add_mapping(&self, mapping: Vec<LinkItem>) -> anyhow::Result<()> {
        for item in mapping {
            let current_device_info = self.vnt.current_device_info();
            if item.dest.ip().is_unspecified() {
                Err(anyhow::anyhow!("dest_address {:?} is_unspecified", item))?
            }
            let mut shutdown_rx_ = self.shutdown_tx.subscribe();
            if *shutdown_rx_.borrow() {
                Err(anyhow::anyhow!("mapping stop"))?
            }
            if item.protocol == LinkProtocol::Udp {
                let lwip_udp_write = self.lwip_udp_write.clone();
                let in_udp_map = self.in_udp_map.clone();
                //只能本机访问，不然不同IP的相同来源端口会有问题
                let udp = UdpSocket::bind(format!("127.0.0.1:{}", item.src_port))
                    .await
                    .with_context(|| format!("udp bind failed {}", item.src_port))?;
                tokio::spawn(async move {
                    tokio::select! {
                        _ = shutdown_rx_.changed() => {}
                        _ = in_mapping::udp::udp_mapping_start(
                                udp,
                                lwip_udp_write,
                                current_device_info,
                                &in_udp_map,
                                item.dest,
                        ) => {}
                    }
                });
            } else {
                let listener = TcpListener::bind(format!("127.0.0.1:{}", item.src_port))
                    .await
                    .with_context(|| format!("tcp bind failed {}", item.src_port))?;
                tokio::spawn(async move {
                    tokio::select! {
                        _ = shutdown_rx_.changed() => {}
                        _ = in_mapping::tcp::tcp_mapping_listen(
                            listener,
                            current_device_info,
                            item.dest,
                        ) => {}
                    }
                });
            }
        }
        Ok(())
    }
    pub fn stop(&self) {
        self.as_vnt().stop()
    }
    pub async fn wait(&self) {
        loop {
            let mut receiver = self.shutdown_tx.subscribe();
            if *receiver.borrow() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn as_vnt(&self) -> &Vnt {
        &self.vnt
    }
}

#[derive(Clone)]
pub struct VntDevice {
    net_stack_write: NetStackWrite,
}

impl DeviceWrite for VntDevice {
    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.net_stack_write.send_ip(buf)?;
        Ok(buf.len())
    }
}
