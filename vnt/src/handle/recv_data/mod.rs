use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};

use crate::channel::context::ChannelContext;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::punch::NatInfo;
use crate::channel::RouteKey;
use crate::cipher::Cipher;
#[cfg(feature = "server_encrypt")]
use crate::cipher::RsaCipher;
use crate::external_route::{AllowExternalRoute, ExternalRoute};
use crate::handle::callback::VntCallback;
use crate::handle::handshaker::Handshake;
use crate::handle::maintain::PunchSender;
use crate::handle::recv_data::client::ClientPacketHandler;
use crate::handle::recv_data::server::ServerPacketHandler;
use crate::handle::recv_data::turn::TurnPacketHandler;
use crate::handle::{BaseConfigInfo, CurrentDeviceInfo, PeerDeviceInfo, SELF_IP};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::nat::NatTest;
use crate::protocol::{NetPacket, HEAD_LEN};
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::U64Adder;

mod client;
mod server;
mod turn;

#[derive(Clone)]
pub struct RecvDataHandler<Call, Device> {
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    turn: TurnPacketHandler,
    client: ClientPacketHandler<Device>,
    server: ServerPacketHandler<Call, Device>,
    counter: U64Adder,
    nat_test: NatTest,
}

impl<Call: VntCallback, Device: DeviceWrite> RecvChannelHandler for RecvDataHandler<Call, Device> {
    fn handle(
        &mut self,
        buf: &mut [u8],
        extend: &mut [u8],
        route_key: RouteKey,
        context: &ChannelContext,
    ) {
        if buf.len() < HEAD_LEN {
            return;
        }
        //判断stun响应包
        if !route_key.is_tcp() {
            if let Ok(rs) = self
                .nat_test
                .recv_data(route_key.index(), route_key.addr, buf)
            {
                if rs {
                    return;
                }
            }
        }
        if let Err(e) = self.handle0(buf, extend, route_key, context) {
            log::error!(
                "[{}]-{:?}-{:?}",
                thread::current().name().unwrap_or(""),
                route_key.addr,
                e
            );
        }
    }
}

impl<Call: VntCallback, Device: DeviceWrite> RecvDataHandler<Call, Device> {
    pub fn new(
        #[cfg(feature = "server_encrypt")] rsa_cipher: Arc<Mutex<Option<RsaCipher>>>,
        server_cipher: Cipher,
        client_cipher: Cipher,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        device: Device,
        device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
        config_info: BaseConfigInfo,
        nat_test: NatTest,
        callback: Call,
        punch_sender: PunchSender,
        peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
        external_route: ExternalRoute,
        route: AllowExternalRoute,
        #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
        counter: U64Adder,
        handshake: Handshake,
        #[cfg(feature = "inner_tun")]
        tun_device_helper: crate::tun_tap_device::tun_create_helper::TunDeviceHelper,
    ) -> Self {
        let server = ServerPacketHandler::new(
            #[cfg(feature = "server_encrypt")]
            rsa_cipher,
            server_cipher,
            current_device.clone(),
            device.clone(),
            device_list,
            config_info,
            nat_test.clone(),
            callback,
            external_route.clone(),
            handshake,
            #[cfg(feature = "inner_tun")]
            tun_device_helper,
        );
        let client = ClientPacketHandler::new(
            device.clone(),
            client_cipher,
            punch_sender,
            peer_nat_info_map,
            nat_test.clone(),
            route,
            #[cfg(feature = "ip_proxy")]
            ip_proxy_map,
        );
        let turn = TurnPacketHandler::new();
        Self {
            current_device,
            turn,
            client,
            server,
            counter,
            nat_test,
        }
    }
    fn handle0(
        &mut self,
        buf: &mut [u8],
        extend: &mut [u8],
        route_key: RouteKey,
        context: &ChannelContext,
    ) -> anyhow::Result<()> {
        // 统计流量
        self.counter.add(buf.len() as _);
        let net_packet = NetPacket::new(buf)?;
        let extend = NetPacket::unchecked(extend);
        if net_packet.ttl() == 0 || net_packet.source_ttl() < net_packet.ttl() {
            log::warn!("丢弃过时包:{:?} {}", net_packet.head(), route_key.addr);
            return Ok(());
        }
        let current_device = self.current_device.load();
        let dest = net_packet.destination();
        if dest == current_device.virtual_ip
            || dest.is_broadcast()
            || dest.is_multicast()
            || dest == SELF_IP
            || dest.is_unspecified()
            || dest == current_device.broadcast_ip
        {
            //发给自己的包
            if net_packet.is_gateway() {
                //服务端-客户端包
                self.server
                    .handle(net_packet, extend, route_key, context, &current_device)
            } else {
                //客户端-客户端包
                self.client
                    .handle(net_packet, extend, route_key, context, &current_device)
            }
        } else {
            //转发包
            self.turn
                .handle(net_packet, extend, route_key, context, &current_device)
        }
    }
}

pub trait PacketHandler {
    fn handle(
        &self,
        net_packet: NetPacket<&mut [u8]>,
        extend: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        context: &ChannelContext,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()>;
}
