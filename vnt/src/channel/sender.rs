use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use tokio::sync::mpsc::Sender;

use crate::channel::context::ChannelContext;
use crate::channel::notify::AcceptNotify;
use crate::cipher::Cipher;
use crate::compression::Compressor;
use crate::external_route::ExternalRoute;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::protocol;
use crate::protocol::{ip_turn_packet, NetPacket};

#[derive(Clone)]
pub struct IpPacketSender {
    context: ChannelContext,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    compressor: Compressor,
    client_cipher: Cipher,
    server_cipher: Cipher,
    ip_route: ExternalRoute,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    allow_wire_guard: bool,
}

impl IpPacketSender {
    pub fn new(
        context: ChannelContext,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        compressor: Compressor,
        client_cipher: Cipher,
        server_cipher: Cipher,
        ip_route: ExternalRoute,
        device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
        allow_wire_guard: bool,
    ) -> Self {
        Self {
            context,
            current_device,
            compressor,
            client_cipher,
            server_cipher,
            ip_route,
            device_map,
            allow_wire_guard,
        }
    }
    pub fn self_virtual_ip(&self) -> Ipv4Addr {
        self.current_device.load().virtual_ip
    }
    pub fn send_ip(
        &self,
        buf: &mut [u8],
        data_len: usize,
        auxiliary_buf: &mut [u8],
        mut dest_ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
        let device_info = self.current_device.load();
        let src_ip = device_info.virtual_ip;
        if src_ip.is_unspecified() {
            return Ok(());
        }
        if let Some(v) = self.ip_route.route(&dest_ip) {
            dest_ip = v;
        }
        if dest_ip.is_multicast() {
            //广播
            dest_ip = Ipv4Addr::BROADCAST;
        }
        let mut net_packet = NetPacket::new0(data_len, buf)?;
        net_packet.set_default_version();
        net_packet.set_protocol(protocol::Protocol::IpTurn);
        net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
        net_packet.first_set_ttl(6);
        net_packet.set_source(src_ip);
        net_packet.set_destination(dest_ip);
        if self.allow_wire_guard {
            if dest_ip.is_broadcast() || dest_ip == device_info.broadcast_ip {
                let exists_wg = self
                    .device_map
                    .lock()
                    .1
                    .values()
                    .any(|v| v.status.is_online() && v.wireguard);
                if exists_wg {
                    send_to_wg_broadcast(
                        &self.context,
                        &net_packet,
                        &self.server_cipher,
                        &device_info,
                    )?;
                }
            } else {
                let guard = self.device_map.lock();
                if let Some(peer_info) = guard.1.get(&dest_ip) {
                    if peer_info.wireguard {
                        if peer_info.status.is_offline() {
                            return Ok(());
                        }
                        drop(guard);
                        send_to_wg(
                            &self.context,
                            &mut net_packet,
                            &self.server_cipher,
                            &device_info,
                        )?;
                        return Ok(());
                    }
                }
            }
        }

        let mut auxiliary = NetPacket::new(auxiliary_buf)?;

        let mut net_packet = if self.compressor.compress(&net_packet, &mut auxiliary)? {
            auxiliary.set_default_version();
            auxiliary.set_protocol(protocol::Protocol::IpTurn);
            auxiliary.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
            auxiliary.first_set_ttl(6);
            auxiliary.set_source(src_ip);
            auxiliary.set_destination(dest_ip);
            auxiliary
        } else {
            net_packet
        };
        self.client_cipher.encrypt_ipv4(&mut net_packet)?;
        if dest_ip.is_broadcast() || dest_ip == device_info.broadcast_ip {
            //走服务端广播
            self.context
                .send_default(&net_packet, device_info.connect_server)?;
            return Ok(());
        }

        if device_info.not_in_network(dest_ip) {
            //不是一个网段的直接忽略
            return Ok(());
        }
        self.context.send_ipv4_by_id(
            &net_packet,
            &dest_ip,
            device_info.connect_server,
            device_info.status.online(),
        )?;
        Ok(())
    }
}

pub fn send_to_wg_broadcast(
    sender: &ChannelContext,
    net_packet: &NetPacket<&mut [u8]>,
    server_cipher: &Cipher,
    current_device: &CurrentDeviceInfo,
) -> anyhow::Result<()> {
    let mut copy_packet = NetPacket::new0(net_packet.data_len(), [0; 65536])?;
    copy_packet.set_default_version();
    copy_packet.set_protocol(protocol::Protocol::IpTurn);
    copy_packet.set_transport_protocol(ip_turn_packet::Protocol::WGIpv4.into());
    copy_packet.first_set_ttl(6);
    copy_packet.set_source(net_packet.source());
    copy_packet.set_destination(net_packet.destination());
    copy_packet.set_gateway_flag(true);
    copy_packet.set_payload(net_packet.payload())?;
    server_cipher.encrypt_ipv4(&mut copy_packet)?;
    sender.send_default(&copy_packet, current_device.connect_server)?;

    Ok(())
}
pub fn send_to_wg(
    sender: &ChannelContext,
    net_packet: &mut NetPacket<&mut [u8]>,
    server_cipher: &Cipher,
    current_device: &CurrentDeviceInfo,
) -> anyhow::Result<()> {
    net_packet.set_transport_protocol(ip_turn_packet::Protocol::WGIpv4.into());
    net_packet.set_gateway_flag(true);
    server_cipher.encrypt_ipv4(net_packet)?;
    sender.send_default(&net_packet, current_device.connect_server)?;

    Ok(())
}

pub struct AcceptSocketSender<T> {
    sender: SyncSender<T>,
    notify: AcceptNotify,
}

impl<T> Clone for AcceptSocketSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<T> AcceptSocketSender<T> {
    pub fn new(notify: AcceptNotify, sender: SyncSender<T>) -> Self {
        Self { sender, notify }
    }
    pub fn try_add_socket(&self, t: T) -> io::Result<()> {
        match self.sender.try_send(t) {
            Ok(_) => self.notify.add_socket(),
            Err(e) => match e {
                TrySendError::Full(_) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                TrySendError::Disconnected(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
            },
        }
    }
}
#[derive(Clone)]
pub struct PacketSender {
    sender: Sender<Vec<u8>>,
}

impl PacketSender {
    pub fn new(sender: Sender<Vec<u8>>) -> Self {
        Self { sender }
    }
    pub fn try_send(&self, buf: &[u8]) -> io::Result<()> {
        match self.sender.try_send(buf.to_vec()) {
            Ok(_) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "通道已满，发生丢包",
            )),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "通道关闭，发生丢包",
            )),
        }
    }
}

#[derive(Clone)]
pub struct ConnectUtil {
    connect_tcp: Sender<(Vec<u8>, Option<u16>, SocketAddr)>,
    connect_ws: Sender<(Vec<u8>, String)>,
}

impl ConnectUtil {
    pub fn new(
        connect_tcp: Sender<(Vec<u8>, Option<u16>, SocketAddr)>,
        connect_ws: Sender<(Vec<u8>, String)>,
    ) -> Self {
        Self {
            connect_tcp,
            connect_ws,
        }
    }
    pub fn try_connect_tcp(&self, buf: Vec<u8>, addr: SocketAddr) {
        if self.connect_tcp.try_send((buf, None, addr)).is_err() {
            log::warn!("try_connect_tcp failed {}", addr);
        }
    }
    pub fn try_connect_tcp_punch(&self, buf: Vec<u8>, addr: SocketAddr) {
        // 打洞的连接可以绑定随机端口
        if self.connect_tcp.try_send((buf, Some(0), addr)).is_err() {
            log::warn!("try_connect_tcp failed {}", addr);
        }
    }
    pub fn try_connect_ws(&self, buf: Vec<u8>, addr: String) {
        if self.connect_ws.try_send((buf, addr)).is_err() {
            log::warn!("try_connect_ws failed");
        }
    }
}
