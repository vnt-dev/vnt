use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use tokio::sync::mpsc::Sender;

use crate::channel::context::ChannelContext;
use crate::channel::notify::AcceptNotify;
use crate::cipher::Cipher;
use crate::compression::Compressor;
use crate::external_route::ExternalRoute;
use crate::handle::CurrentDeviceInfo;
use crate::protocol;
use crate::protocol::{ip_turn_packet, NetPacket};

#[derive(Clone)]
pub struct IpPacketSender {
    context: ChannelContext,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    compressor: Compressor,
    client_cipher: Cipher,
    ip_route: ExternalRoute,
}

impl IpPacketSender {
    pub fn new(
        context: ChannelContext,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        compressor: Compressor,
        client_cipher: Cipher,
        ip_route: ExternalRoute,
    ) -> Self {
        Self {
            context,
            current_device,
            compressor,
            client_cipher,
            ip_route,
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
        if dest_ip.is_multicast() || dest_ip.is_broadcast() || dest_ip == device_info.broadcast_ip {
            //广播
            dest_ip = Ipv4Addr::BROADCAST;
        }

        let mut net_packet = NetPacket::new0(data_len, buf)?;
        let mut auxiliary = NetPacket::new(auxiliary_buf)?;
        net_packet.set_default_version();
        net_packet.set_protocol(protocol::Protocol::IpTurn);
        net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
        net_packet.first_set_ttl(6);
        net_packet.set_source(src_ip);
        net_packet.set_destination(dest_ip);

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
        if dest_ip.is_broadcast() {
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
    connect_tcp: Sender<(Vec<u8>, SocketAddr)>,
    connect_ws: Sender<(Vec<u8>, String)>,
}

impl ConnectUtil {
    pub fn new(
        connect_tcp: Sender<(Vec<u8>, SocketAddr)>,
        connect_ws: Sender<(Vec<u8>, String)>,
    ) -> Self {
        Self {
            connect_tcp,
            connect_ws,
        }
    }
    pub fn try_connect_tcp(&self, buf: Vec<u8>, addr: SocketAddr) {
        if self.connect_tcp.try_send((buf, addr)).is_err() {
            log::warn!("try_connect_tcp failed {}", addr);
        }
    }
    pub fn try_connect_ws(&self, buf: Vec<u8>, addr: String) {
        if self.connect_ws.try_send((buf, addr)).is_err() {
            log::warn!("try_connect_ws failed");
        }
    }
}
