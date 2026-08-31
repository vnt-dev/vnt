use crate::compression::PacketCompression;
use crate::context::config::{DeviceMode, TurnRule, allow_punch};
use crate::context::nat::{MyNatInfo, PunchBackoff};
use crate::context::{
    NetworkAddr, NetworkRoute, PeerInfoMap, ServerInfoCollection, SharedNetworkAddr,
};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::event_script::{EventScript, EventScriptType};
use crate::fec::FecDecoder;
use crate::protocol::client_message::PunchInfo;
use crate::protocol::control_message::{
    ClientSimpleInfoList, FastRegRequestMsg, RequestMessage, ResponseMessage,
};
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::rpc_message::RpcMessageResponse;
use crate::protocol::transmission::TransmissionBytes;
use crate::tun::DeviceIOManager;
use crate::tunnel_core::p2p::transport::punch::NatPuncher;
use crate::tunnel_core::server::outbound::ServerOutbound;
use crate::tunnel_core::server::rpc::RpcNotifier;
use crate::tunnel_core::server::transport::TransportClient;
use crate::tunnel_core::server::transport::config::SharedRegistrationIp;
#[cfg(target_os = "android")]
use anyhow::Context;
use anyhow::bail;
use bytes::Bytes;
use pnet_packet::Packet;
use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
use pnet_packet::ipv4::Ipv4Packet;
use prost::Message;
use rustp2p_core::nat::NatInfo;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "android")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidIpUpdateRequest {
    pub request_id: u64,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
}

#[cfg(target_os = "android")]
pub type AndroidIpUpdateCallback =
    Arc<dyn Fn(AndroidIpUpdateRequest) -> anyhow::Result<()> + Send + Sync + 'static>;

#[cfg(target_os = "android")]
#[derive(Default)]
struct AndroidIpUpdateState {
    next_request_id: u64,
    pending: Vec<AndroidIpUpdateRequest>,
    prepared: Option<AndroidIpUpdateRequest>,
    callback: Option<AndroidIpUpdateCallback>,
}

#[derive(Clone)]
pub(crate) struct IpUpdateContext {
    network: SharedNetworkAddr,
    registration_ip: SharedRegistrationIp,
    server_outbound: ServerOutbound,
    update_lock: Arc<tokio::sync::Mutex<()>>,
    device_io_manager: DeviceIOManager,
    device_mode: DeviceMode,
    event_script: EventScript,
    server_addrs: Vec<String>,
    #[cfg(target_os = "android")]
    android: Arc<parking_lot::Mutex<AndroidIpUpdateState>>,
}

impl IpUpdateContext {
    pub fn new(
        network: SharedNetworkAddr,
        registration_ip: SharedRegistrationIp,
        server_outbound: ServerOutbound,
        device_io_manager: DeviceIOManager,
        device_mode: DeviceMode,
        event_script: EventScript,
        server_addrs: Vec<String>,
    ) -> Self {
        Self {
            network,
            registration_ip,
            server_outbound,
            update_lock: Arc::new(tokio::sync::Mutex::new(())),
            device_io_manager,
            device_mode,
            event_script,
            server_addrs,
            #[cfg(target_os = "android")]
            android: Arc::new(parking_lot::Mutex::new(AndroidIpUpdateState::default())),
        }
    }

    fn validate_target(current: NetworkAddr, new_ip: Ipv4Addr) -> anyhow::Result<NetworkAddr> {
        let net = current.network();
        if !net.contains(&new_ip) {
            bail!("更新 IP {new_ip} 不属于当前网段 {net}");
        }
        if new_ip == current.gateway {
            bail!("更新 IP 不能使用网关地址 {new_ip}");
        }
        if new_ip == net.network() || new_ip == net.broadcast() {
            bail!("更新 IP 不能使用网络地址或广播地址 {new_ip}");
        }
        Ok(NetworkAddr {
            ip: new_ip,
            broadcast: net.broadcast(),
            prefix_len: current.prefix_len,
            gateway: current.gateway,
        })
    }

    fn parse_update_ip(payload: &[u8]) -> anyhow::Result<Ipv4Addr> {
        let octets: [u8; 4] = payload
            .try_into()
            .map_err(|_| anyhow::anyhow!("UpdateIp payload 必须为 4 字节"))?;
        Ok(Ipv4Addr::from(octets))
    }

    fn fast_reg_packet(ip: Ipv4Addr) -> anyhow::Result<Bytes> {
        let payload = RequestMessage::FastReg(FastRegRequestMsg { ip }).encode();
        let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + payload.len()))?;
        packet.set_msg_type(MsgType::FastReg);
        packet.set_ttl(1);
        packet.set_gateway_flag(true);
        packet.set_payload(&payload)?;
        Ok(packet.into_buffer().into_bytes().freeze())
    }

    async fn send_fast_reg(&self, ip: Ipv4Addr) {
        let result = match Self::fast_reg_packet(ip) {
            Ok(packet) => {
                self.server_outbound
                    .send_gateway_to_all(packet, Duration::from_secs(2))
                    .await
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(sent) => log::info!("快速注册已发送到 {sent} 台服务端，新 IP: {ip}"),
            Err(error) => log::warn!("发送快速注册失败，保留新 IP {ip}: {error:#}"),
        }
    }

    pub async fn apply_and_fast_register(&self, new_ip: Ipv4Addr) -> anyhow::Result<bool> {
        let _guard = self.update_lock.lock().await;
        let current = self
            .network
            .get()
            .ok_or_else(|| anyhow::anyhow!("客户端尚未完成网络注册"))?;
        let updated = Self::validate_target(current, new_ip)?;

        #[cfg(not(target_os = "android"))]
        {
            if self.device_mode.has_device() {
                self.device_io_manager
                    .set_network(new_ip, current.prefix_len)
                    .await?;
            }

            self.network.set(updated);
            self.registration_ip.set(new_ip);
            // IP 实际发生变化时触发事件脚本（多服务器重复下发同 IP 时不会重复触发）
            if updated.ip != current.ip {
                self.event_script
                    .notify(
                        EventScriptType::IpUpdated,
                        &[
                            ("old-ip", current.ip.to_string()),
                            ("new-ip", updated.ip.to_string()),
                            ("prefix-length", updated.prefix_len.to_string()),
                            ("gateway", updated.gateway.to_string()),
                            ("broadcast", updated.broadcast.to_string()),
                            ("server", self.server_addrs.join(",")),
                        ],
                    )
                    .await;
            }
            self.send_fast_reg(new_ip).await;
            Ok(true)
        }

        #[cfg(target_os = "android")]
        {
            let _ = updated;
            if current.ip == new_ip {
                self.send_fast_reg(new_ip).await;
                return Ok(true);
            }
            let (request, callback) = {
                let mut state = self.android.lock();
                let request = if let Some(existing) = state
                    .pending
                    .iter()
                    .find(|request| request.ip == new_ip)
                    .copied()
                {
                    existing
                } else {
                    state.next_request_id = state.next_request_id.wrapping_add(1).max(1);
                    let request = AndroidIpUpdateRequest {
                        request_id: state.next_request_id,
                        ip: new_ip,
                        prefix_len: current.prefix_len,
                    };
                    state.pending.push(request);
                    request
                };
                (request, state.callback.clone())
            };
            let callback = callback.context("Android IP 更新监听器尚未注册")?;
            callback(request)?;
            Ok(false)
        }
    }

    #[cfg(target_os = "android")]
    pub fn set_android_callback(&self, callback: AndroidIpUpdateCallback) {
        self.android.lock().callback = Some(callback);
    }

    #[cfg(target_os = "android")]
    pub async fn prepare_android_update(
        &self,
        request_id: u64,
        ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
        let _guard = self.update_lock.lock().await;
        let request = {
            let state = self.android.lock();
            if state.prepared.is_some() {
                bail!("另一个 IP 更新请求正在切换");
            }
            state
                .pending
                .iter()
                .find(|request| request.request_id == request_id && request.ip == ip)
                .copied()
                .context("IP 更新请求不存在或已经失效")?
        };
        Self::validate_target(
            self.network.get().context("客户端尚未完成网络注册")?,
            request.ip,
        )?;
        if self.device_mode.has_device() {
            self.device_io_manager.suspend_android().await?;
        }
        self.android.lock().prepared = Some(request);
        Ok(())
    }

    #[cfg(target_os = "android")]
    pub async fn complete_android_update(
        &self,
        request_id: u64,
        ip: Ipv4Addr,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> anyhow::Result<()> {
        let _guard = self.update_lock.lock().await;
        let request = self
            .android
            .lock()
            .prepared
            .filter(|request| request.request_id == request_id && request.ip == ip)
            .context("IP 更新请求尚未准备或已经失效")?;
        let updated = Self::validate_target(
            self.network.get().context("客户端尚未完成网络注册")?,
            request.ip,
        )?;
        if self.device_mode.has_device() {
            self.device_io_manager
                .resume_android(
                    tun_fd.context("缺少新的 Android VPN fd")?,
                    ip,
                    request.prefix_len,
                )
                .await?;
        } else if tun_fd.is_some() {
            bail!("无 TUN 模式不能传入 VPN fd");
        }
        self.network.set(updated);
        self.registration_ip.set(ip);
        {
            let mut state = self.android.lock();
            state
                .pending
                .retain(|pending| pending.request_id > request_id);
            state.prepared = None;
        }
        self.send_fast_reg(ip).await;
        Ok(())
    }
}

pub(crate) struct ServerTurnInboundHandler {
    server_id: u32,
    network_route: NetworkRoute,
    ip_update: IpUpdateContext,
    server_info: ServerInfoCollection,
    nat_info: MyNatInfo,
    peer_map: PeerInfoMap,
    punch_backoff: PunchBackoff,
    puncher: NatPuncher,
    packet_crypto: PacketCrypto,
    packet_compression: PacketCompression,
    enhanced_inbound: EnhancedInbound,
    fec_decoder: FecDecoder,
    turn: Arc<Vec<TurnRule>>,
}
impl ServerTurnInboundHandler {
    pub fn new(
        server_id: u32,
        config: Box<super::connection_manager::InboundHandlerConfig>,
    ) -> Self {
        let config = *config;
        Self {
            server_id,
            network_route: config.network_route,
            ip_update: config.ip_update,
            server_info: config.server_info,
            nat_info: config.nat_info,
            peer_map: config.peer_map,
            punch_backoff: config.punch_backoff,
            puncher: config.puncher,
            packet_crypto: config.packet_crypto,
            packet_compression: config.packet_compression,
            enhanced_inbound: config.enhanced_inbound,
            fec_decoder: config.fec_decoder,
            turn: config.turn,
        }
    }
    fn network_contains(&self, ip: &Ipv4Addr) -> bool {
        self.network_route.network_contains(ip)
    }
    fn filter_ip(&self, mut info: NatInfo) -> NatInfo {
        if self.network_contains(&info.local_ipv4) {
            info.local_ipv4 = Ipv4Addr::UNSPECIFIED;
        }
        info.local_ipv4s.retain(|ip| !self.network_contains(ip));
        info
    }
    fn get_punch_info(&self) -> Option<PunchInfo> {
        self.nat_info.get().map(|info| PunchInfo {
            nat_info: self.filter_ip(info),
        })
    }
    fn update_peer_nat_info(&self, ip: Ipv4Addr, nat_info: NatInfo) {
        if self.peer_map.update_nat_info(ip, nat_info) {
            // 对端 NAT 变化时，把该对端的退避截止时刻压缩到 10 分钟内
            self.punch_backoff.cap(ip);
        }
    }

    pub async fn handle_server_data(
        &self,
        transport_client: &mut TransportClient,
        network_addr: NetworkAddr,
        data: TransmissionBytes,
        rpc_notifier: &RpcNotifier,
        now: i64,
    ) -> anyhow::Result<()> {
        let net_packet = NetPacket::new(data)?;
        let src = net_packet.src_id().into();
        let msg_type = net_packet.msg_type()?;
        let mut net_packet = self.packet_compression.decompress(net_packet)?;

        match msg_type {
            MsgType::Turn => {
                // 只允许icmp EchoReply
                let Some(ipv4) = Ipv4Packet::new(net_packet.payload()) else {
                    return Ok(());
                };
                if ipv4.get_version() != 4 {
                    return Ok(());
                }
                if ipv4.get_next_level_protocol() != pnet_packet::ip::IpNextHeaderProtocols::Icmp {
                    return Ok(());
                }
                let Some(icmp) = IcmpPacket::new(ipv4.payload()) else {
                    return Ok(());
                };
                if icmp.get_icmp_type() != IcmpTypes::EchoReply {
                    return Ok(());
                }
                self.enhanced_inbound
                    .inbound(&network_addr, msg_type, src, net_packet)
                    .await?;
            }
            MsgType::Ping => {
                net_packet.set_ttl(2);
                net_packet.set_msg_type(MsgType::Pong);
                net_packet.set_src_id(network_addr.ip.into());
                net_packet.set_dest_id(src.into());
                transport_client.send_turn(net_packet).await?;
            }
            MsgType::PongTurn => {
                // 服务端ping 回复，记录延迟
                if net_packet.payload().len() == 8 + 8 {
                    let time = i64::from_be_bytes(net_packet.payload()[..8].try_into()?);
                    // let data_version = u64::from_be_bytes(net_packet.payload()[8..].try_into()?);
                    if now >= time {
                        self.server_info
                            .set_server_rtt(self.server_id, (now - time) as u32);
                    }
                }
            }
            MsgType::PushClientIps => {
                let list = ClientSimpleInfoList::from_slice(net_packet.payload())?;
                self.server_info.update_client_simple_list(
                    self.server_id,
                    network_addr.ip,
                    list,
                    now,
                );
            }
            MsgType::RpcRes => {
                // 设置rpc响应
                let response = RpcMessageResponse::decode(net_packet.payload())?;
                rpc_notifier.notify_response(response);
            }
            MsgType::UpdateIp => {
                self.ip_update
                    .apply_and_fast_register(IpUpdateContext::parse_update_ip(
                        net_packet.payload(),
                    )?)
                    .await?;
            }
            MsgType::FastReg => match ResponseMessage::from_slice(net_packet.payload())? {
                ResponseMessage::FastReg(response) if response.success => {
                    log::info!("服务端 {} 快速注册成功", self.server_id);
                }
                ResponseMessage::FastReg(_) => {
                    log::warn!("服务端 {} 快速注册返回失败", self.server_id);
                }
                ResponseMessage::Error(error) => {
                    log::warn!(
                        "服务端 {} 快速注册失败: {} ({})",
                        self.server_id,
                        error.message,
                        error.code
                    );
                }
                response => {
                    log::warn!(
                        "服务端 {} 返回了非预期的快速注册响应: {response:?}",
                        self.server_id
                    );
                }
            },
            _ => {}
        }
        Ok(())
    }
    pub async fn handle_client_data(
        &self,
        network_addr: NetworkAddr,
        transport_client: &mut TransportClient,
        data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        let net_packet = NetPacket::new(data)?;
        let _ = net_packet.msg_type()?;

        // FEC 外层只做认证，解码后再按每个内层包的类型决定是否 AEAD 解密。
        if net_packet.is_fec() {
            let packets = self.fec_decoder.receive(net_packet)?;
            if let Some(packets) = packets {
                for pkt in packets {
                    self.process_inner_packet(network_addr, transport_client, pkt)
                        .await?;
                }
            }
            return Ok(());
        }

        self.process_inner_packet(network_addr, transport_client, net_packet)
            .await
    }

    async fn process_inner_packet(
        &self,
        network_addr: NetworkAddr,
        transport_client: &mut TransportClient,
        mut net_packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let msg_type = net_packet.msg_type()?;
        if msg_type != MsgType::Quic
            && let Err(e) = self.packet_crypto.decrypt_in_place(&mut net_packet)
        {
            log::error!(
                "{},msg_type={msg_type:?},src={},dst={}",
                e,
                Ipv4Addr::from(net_packet.src_id()),
                Ipv4Addr::from(net_packet.dest_id())
            );
            return Ok(());
        }
        self.process_plain_packet(network_addr, transport_client, net_packet)
            .await
    }

    /// 处理已经完成普通包解密/FEC 解码的原始 NetPacket。
    async fn process_plain_packet(
        &self,
        network_addr: NetworkAddr,
        transport_client: &mut TransportClient,
        net_packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let msg_type = net_packet.msg_type()?;
        let src = Ipv4Addr::from(net_packet.src_id());
        let dest = Ipv4Addr::from(net_packet.dest_id());

        if msg_type == MsgType::Quic {
            return self
                .enhanced_inbound
                .inbound(&network_addr, msg_type, src, net_packet)
                .await;
        }

        let net_packet = self.packet_compression.decompress(net_packet)?;
        self.process_decompressed_packet(
            network_addr,
            transport_client,
            net_packet,
            msg_type,
            src,
            dest,
        )
        .await
    }

    async fn process_decompressed_packet(
        &self,
        network_addr: NetworkAddr,
        transport_client: &mut TransportClient,
        net_packet: NetPacket<TransmissionBytes>,
        msg_type: MsgType,
        src: Ipv4Addr,
        dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        match msg_type {
            MsgType::Turn | MsgType::Broadcast => {
                self.enhanced_inbound
                    .inbound(&network_addr, msg_type, src, net_packet)
                    .await?;
            }
            MsgType::PunchStart1 => {
                if !allow_punch(&self.turn, &src) {
                    log::debug!("ignore configured turn target PunchStart1 from {src}");
                    return Ok(());
                }
                // 对方发起打洞
                let peer_punch_info = PunchInfo::from_slice(net_packet.payload())?;
                let Some(self_punch_info) = self.get_punch_info() else {
                    return Ok(());
                };
                log::info!(
                    "对方主动发起打洞 对方nat信息={peer_punch_info:?}，自己nat信息={self_punch_info:?} {src}->{dest}"
                );
                self.update_peer_nat_info(src, peer_punch_info.nat_info.clone());
                let rs = self.puncher.punch(src, peer_punch_info)?;
                if rs {
                    let bytes_mut = self_punch_info.encode();
                    let mut net_packet = NetPacket::new(TransmissionBytes::zeroed_size(
                        HEAD_LENGTH + bytes_mut.len(),
                        self.packet_crypto.encrypt_reserve(),
                    ))?;
                    net_packet.set_msg_type(MsgType::PunchStart2);
                    net_packet.set_ttl(2);
                    net_packet.set_src_id(dest.into());
                    net_packet.set_dest_id(src.into());
                    net_packet.set_payload(&bytes_mut)?;
                    self.packet_crypto.encrypt_in_place(&mut net_packet)?;
                    transport_client.send_turn(net_packet).await?;
                } else {
                    log::info!("限制打洞频率")
                }
            }
            MsgType::PunchStart2 => {
                if !allow_punch(&self.turn, &src) {
                    log::debug!("ignore configured turn target PunchStart2 from {src}");
                    return Ok(());
                }
                self.punch_backoff.record(src);
                // 对方回复开始打洞
                let peer_punch_info = PunchInfo::from_slice(net_packet.payload())?;
                self.update_peer_nat_info(src, peer_punch_info.nat_info.clone());
                log::info!("对方回复开始打洞 {:?} {src}->{dest}", peer_punch_info);
                self.puncher.punch_uncheck(src, peer_punch_info)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn handle(
        &self,
        transport_client: &mut TransportClient,
        data: TransmissionBytes,
        rpc_notifier: &RpcNotifier,
        now: i64,
    ) -> anyhow::Result<()> {
        let net_packet = NetPacket::new(&data)?;
        let Some(network_addr) = self.network_route.network.get() else {
            bail!("未找到自身IP")
        };

        if net_packet.is_gateway() {
            // 服务端数据
            return self
                .handle_server_data(transport_client, network_addr, data, rpc_notifier, now)
                .await;
        }
        let dest = Ipv4Addr::from(net_packet.dest_id());
        if !dest.is_broadcast() && !dest.is_unspecified() && network_addr.ip != dest {
            return Ok(());
        }
        self.handle_client_data(network_addr, transport_client, data)
            .await
    }
    pub async fn handle_ping(
        &self,
        transport_client: &mut TransportClient,
        now: i64,
    ) -> anyhow::Result<()> {
        let mut ping_packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + 8 + 8))?;
        ping_packet.set_ttl(1);
        ping_packet.set_msg_type(MsgType::PingTurn);
        ping_packet.set_gateway_flag(true);
        ping_packet.set_payload(&now.to_be_bytes())?;
        ping_packet.payload_mut()[0..8].copy_from_slice(&now.to_be_bytes());
        ping_packet.payload_mut()[8..]
            .copy_from_slice(&self.server_info.data_version(self.server_id).to_be_bytes());
        transport_client
            .send(ping_packet.into_buffer().into_bytes().freeze())
            .await?;
        Ok(())
    }
    pub fn handle_connected(&self) {
        self.server_info.set_server_connected(self.server_id, true);
        self.server_info
            .set_last_connected_time(self.server_id, Some(crate::utils::time::now_ts_ms()));
        self.server_info.set_disconnected_time(self.server_id, None);
    }
    pub fn set_server_version(&self, version: String) {
        self.server_info.set_server_version(self.server_id, version);
    }
    pub fn network_addr(&self) -> Option<NetworkAddr> {
        self.network_route.network.get()
    }
    pub fn handle_disconnected(&self) {
        if self.server_info.set_server_connected(self.server_id, false) {
            self.server_info
                .set_disconnected_time(self.server_id, Some(crate::utils::time::now_ts_ms()));
        }
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use crate::context::ServerInfoCollection;
    use crate::crypto::PacketCrypto;
    use crate::tunnel_core::server::transport::config::ProtocolAddress;
    use crate::utils::task_control::TaskGroupManager;
    use std::collections::HashMap;
    use tokio::sync::mpsc::Receiver;

    struct TestUpdateContext {
        context: IpUpdateContext,
        network: SharedNetworkAddr,
        registration_ip: SharedRegistrationIp,
        receivers: Vec<Receiver<(Bytes, std::time::Instant)>>,
    }

    fn network(ip: Ipv4Addr) -> NetworkAddr {
        NetworkAddr {
            ip,
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 26, 0, 1),
            broadcast: Ipv4Addr::new(10, 26, 0, 255),
        }
    }

    fn update_context(
        device_mode: DeviceMode,
        connected: bool,
        server_count: usize,
    ) -> TestUpdateContext {
        let task_group_manager = TaskGroupManager::new();
        let (task_group, _guard) = task_group_manager.create_task().unwrap();
        let device_io_manager = DeviceIOManager::new(task_group);
        let shared_network = SharedNetworkAddr::default();
        let initial_ip = Ipv4Addr::new(10, 26, 0, 2);
        shared_network.set(network(initial_ip));
        let registration_ip = SharedRegistrationIp::new(Some(initial_ip));

        let server_info = ServerInfoCollection::default();
        server_info.update_server(
            (0..server_count)
                .map(|id| (id as u32, ProtocolAddress::default()))
                .collect(),
        );
        let mut senders = HashMap::new();
        let mut receivers = Vec::new();
        for id in 0..server_count {
            let (sender, receiver) = tokio::sync::mpsc::channel(4);
            senders.insert(id as u32, sender);
            receivers.push(receiver);
            if connected {
                server_info.set_server_connected(id as u32, true);
            }
        }
        let outbound = ServerOutbound::new(
            Arc::new(senders),
            server_info,
            PacketCrypto::new_from_str(None).unwrap(),
        );
        let context = IpUpdateContext::new(
            shared_network.clone(),
            registration_ip.clone(),
            outbound,
            device_io_manager,
            device_mode,
            EventScript::new(None),
            Vec::new(),
        );
        TestUpdateContext {
            context,
            network: shared_network,
            registration_ip,
            receivers,
        }
    }

    #[test]
    fn update_ip_validation_preserves_network_shape() {
        let current = network(Ipv4Addr::new(10, 26, 0, 2));
        let updated =
            IpUpdateContext::validate_target(current, Ipv4Addr::new(10, 26, 0, 9)).unwrap();
        assert_eq!(updated.ip, Ipv4Addr::new(10, 26, 0, 9));
        assert_eq!(updated.gateway, current.gateway);
        assert_eq!(updated.prefix_len, current.prefix_len);
        assert_eq!(updated.broadcast, current.broadcast);

        for invalid in [
            Ipv4Addr::new(10, 26, 0, 0),
            Ipv4Addr::new(10, 26, 0, 1),
            Ipv4Addr::new(10, 26, 0, 255),
            Ipv4Addr::new(10, 27, 0, 9),
        ] {
            assert!(IpUpdateContext::validate_target(current, invalid).is_err());
        }

        assert_eq!(
            IpUpdateContext::parse_update_ip(&[10, 26, 0, 9]).unwrap(),
            Ipv4Addr::new(10, 26, 0, 9)
        );
        assert!(IpUpdateContext::parse_update_ip(&[10, 26, 0]).is_err());
        assert!(IpUpdateContext::parse_update_ip(&[10, 26, 0, 9, 1]).is_err());
    }

    #[test]
    fn fast_registration_uses_gateway_packet_type_22_and_ttl_one() {
        let ip = Ipv4Addr::new(10, 26, 0, 9);
        let bytes = IpUpdateContext::fast_reg_packet(ip).unwrap();
        let packet = NetPacket::new(bytes).unwrap();
        assert_eq!(packet.msg_type().unwrap(), MsgType::FastReg);
        assert!(packet.is_gateway());
        assert_eq!(packet.ttl(), 1);
        assert_eq!(
            packet.payload(),
            RequestMessage::FastReg(FastRegRequestMsg { ip })
                .encode()
                .as_ref()
        );
    }

    #[tokio::test]
    async fn no_device_update_changes_shared_state_and_broadcasts_every_time() {
        let TestUpdateContext {
            context,
            network: shared_network,
            registration_ip,
            mut receivers,
        } = update_context(DeviceMode::No, true, 2);
        let new_ip = Ipv4Addr::new(10, 26, 0, 9);

        assert!(context.apply_and_fast_register(new_ip).await.unwrap());
        assert_eq!(shared_network.ip(), Some(new_ip));
        assert_eq!(registration_ip.get(), Some(new_ip));
        for receiver in &mut receivers {
            let (bytes, _) = receiver.recv().await.unwrap();
            assert_eq!(
                NetPacket::new(bytes).unwrap().msg_type().unwrap(),
                MsgType::FastReg
            );
        }

        assert!(context.apply_and_fast_register(new_ip).await.unwrap());
        for receiver in &mut receivers {
            assert!(receiver.recv().await.is_some());
        }
    }

    #[tokio::test]
    async fn missing_tun_device_does_not_change_client_state() {
        let TestUpdateContext {
            context,
            network: shared_network,
            registration_ip,
            ..
        } = update_context(DeviceMode::Tun, true, 1);
        let old_ip = shared_network.ip().unwrap();
        assert!(
            context
                .apply_and_fast_register(Ipv4Addr::new(10, 26, 0, 9))
                .await
                .is_err()
        );
        assert_eq!(shared_network.ip(), Some(old_ip));
        assert_eq!(registration_ip.get(), Some(old_ip));
    }

    #[tokio::test]
    async fn send_failure_keeps_already_applied_ip() {
        let TestUpdateContext {
            context,
            network: shared_network,
            registration_ip,
            ..
        } = update_context(DeviceMode::No, false, 1);
        let new_ip = Ipv4Addr::new(10, 26, 0, 9);
        assert!(context.apply_and_fast_register(new_ip).await.unwrap());
        assert_eq!(shared_network.ip(), Some(new_ip));
        assert_eq!(registration_ip.get(), Some(new_ip));
    }
}
