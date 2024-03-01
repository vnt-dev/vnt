use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};

use tun::Device;

use crate::channel::context::Context;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::punch::NatInfo;
use crate::channel::{RouteKey, UseChannelType};
use crate::cipher::Cipher;
#[cfg(feature = "server_encrypt")]
use crate::cipher::RsaCipher;
use crate::external_route::{AllowExternalRoute, ExternalRoute};
use crate::handle::callback::VntCallback;
use crate::handle::recv_data::client::ClientPacketHandler;
use crate::handle::recv_data::server::ServerPacketHandler;
use crate::handle::recv_data::turn::TurnPacketHandler;
use crate::handle::{BaseConfigInfo, CurrentDeviceInfo, PeerDeviceInfo, SELF_IP};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::nat::NatTest;
use crate::protocol::NetPacket;
use crate::util::U64Adder;

mod client;
mod server;
mod turn;

#[derive(Clone)]
pub struct RecvDataHandler<Call> {
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    turn: TurnPacketHandler,
    client: ClientPacketHandler,
    server: ServerPacketHandler<Call>,
    counter: U64Adder,
}

impl<Call: VntCallback> RecvChannelHandler for RecvDataHandler<Call> {
    fn handle(&mut self, buf: &mut [u8], route_key: RouteKey, context: &Context) {
        if let Err(e) = self.handle0(buf, route_key, context) {
            log::error!("[{}]-{:?}", thread::current().name().unwrap_or(""), e);
        }
    }
}

impl<Call: VntCallback> RecvDataHandler<Call> {
    pub fn new(
        #[cfg(feature = "server_encrypt")] rsa_cipher: Arc<Mutex<Option<RsaCipher>>>,
        server_cipher: Cipher,
        client_cipher: Cipher,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        device: Arc<Device>,
        device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
        config_info: BaseConfigInfo,
        nat_test: NatTest,
        callback: Call,
        use_channel_type: UseChannelType,
        punch_sender: SyncSender<(Ipv4Addr, NatInfo)>,
        peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
        external_route: ExternalRoute,
        route: AllowExternalRoute,
        #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
        counter: U64Adder,
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
            external_route,
        );
        let client = ClientPacketHandler::new(
            device.clone(),
            client_cipher,
            use_channel_type,
            punch_sender,
            peer_nat_info_map,
            nat_test,
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
        }
    }
    fn handle0(
        &mut self,
        buf: &mut [u8],
        route_key: RouteKey,
        context: &Context,
    ) -> io::Result<()> {
        // 统计流量
        self.counter.add(buf.len() as _);
        let net_packet = NetPacket::new(buf)?;
        if net_packet.ttl() == 0 || net_packet.source_ttl() < net_packet.ttl() {
            return Ok(());
        }
        let current_device = self.current_device.load();
        let dest = net_packet.destination();
        let source = net_packet.source();
        context.route_table.update_read_time(&source, &route_key);
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
                    .handle(net_packet, route_key, context, &current_device)
            } else {
                //客户端-客户端包
                self.client
                    .handle(net_packet, route_key, context, &current_device)
            }
        } else {
            //转发包
            self.turn
                .handle(net_packet, route_key, context, &current_device)
        }
    }
}

pub trait PacketHandler {
    fn handle(
        &self,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        context: &Context,
        current_device: &CurrentDeviceInfo,
    ) -> io::Result<()>;
}
