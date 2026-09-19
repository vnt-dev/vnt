use crate::context::config::{DeviceMode, VirtualIp, allow_punch, punch_model_for};
use crate::context::nat::{MyNatInfo, PunchBackoff};
use crate::context::{
    NetworkAddr, NetworkRoute, PeerInfoMap, ServerInfoCollection, SharedNetworkAddr,
};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::event_script::EventScript;
#[cfg(not(target_os = "android"))]
use crate::event_script::EventScriptType;
use crate::fec::FecDecoder;
use crate::nat::{AllowSubnetExternalRoute, NetInput};
use crate::protocol::client_message::PunchInfo;
use crate::protocol::control_message::{
    ClientSimpleInfoList, FastRegRequestMsg, RequestMessage, ResponseMessage, SubnetSyncResponse,
    SubscriptionConfigEnvelope, encode_subnet_sync_request,
};
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::rpc_message::RpcMessageResponse;
use crate::protocol::transmission::TransmissionBytes;
use crate::runtime_config::RuntimePolicyStore;
use crate::tun::DeviceIOManager;
#[cfg(not(target_os = "android"))]
use crate::tun::{DeviceConfig, DeviceReconfigureAction};
use crate::tunnel_core::p2p::transport::punch::NatPuncher;
use crate::tunnel_core::server::outbound::ServerOutbound;
use crate::tunnel_core::server::rpc::RpcNotifier;
use crate::tunnel_core::server::transport::TransportClient;
use crate::tunnel_core::server::transport::config::SharedRegistrationIp;
#[cfg(any(target_os = "android", test))]
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
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunRebuildRequest {
    pub request_id: u64,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    /// Android cannot rename the kernel TUN interface. This is the VPN
    /// session label consumed by Java's VpnService.Builder.
    pub session_name: Option<String>,
    pub routes: Vec<NetInput>,
}

#[cfg(any(target_os = "android", test))]
impl serde::Serialize for TunRebuildRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("TunRebuildRequest", 6)?;
        state.serialize_field("request_id", &self.request_id)?;
        state.serialize_field("ip", &self.ip)?;
        state.serialize_field("prefix_len", &self.prefix_len)?;
        state.serialize_field("mtu", &self.mtu)?;
        state.serialize_field("session_name", &self.session_name)?;
        // Keep the JNI payload compact and independent from the internal
        // route representation. Java receives the stable `cidr,target` form.
        let routes = self
            .routes
            .iter()
            .map(|route| format!("{},{}", route.net, route.target_ip))
            .collect::<Vec<_>>();
        state.serialize_field("routes", &routes)?;
        state.end()
    }
}

#[cfg(any(target_os = "android", test))]
#[derive(Debug)]
pub(crate) struct AndroidTunRebuildError {
    pub restart_required: bool,
    message: String,
}

#[cfg(any(target_os = "android", test))]
impl AndroidTunRebuildError {
    fn keep_current(message: impl Into<String>) -> Self {
        Self {
            restart_required: false,
            message: message.into(),
        }
    }
}

#[cfg(any(target_os = "android", test))]
impl std::fmt::Display for AndroidTunRebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(any(target_os = "android", test))]
impl std::error::Error for AndroidTunRebuildError {}

#[cfg(any(target_os = "android", test))]
struct PendingTunRebuild {
    request: TunRebuildRequest,
    delivered: bool,
    replacing: bool,
    completion: tokio::sync::oneshot::Sender<Result<(), String>>,
}

#[cfg(any(target_os = "android", test))]
#[derive(Default)]
struct TunRebuildState {
    next_request_id: u64,
    pending: Option<PendingTunRebuild>,
    closed: bool,
}

/// Pull-only bridge for Android TUN replacement. It deliberately has no Java
/// references: Java waits for requests through JNI and later submits an fd.
#[cfg(any(target_os = "android", test))]
#[derive(Clone, Default)]
pub struct TunRebuildCoordinator {
    state: Arc<parking_lot::Mutex<TunRebuildState>>,
    changed: Arc<tokio::sync::Notify>,
}

#[cfg(any(target_os = "android", test))]
impl TunRebuildCoordinator {
    pub async fn request(
        &self,
        ip: Ipv4Addr,
        prefix_len: u8,
        mtu: u16,
        routes: Vec<NetInput>,
        session_name: Option<String>,
    ) -> anyhow::Result<()> {
        let (request_id, completion) = {
            let mut state = self.state.lock();
            if state.closed {
                anyhow::bail!("TUN 重建协调器已经停止");
            }
            if state.pending.is_some() {
                anyhow::bail!("已有 TUN 重建请求正在处理");
            }
            state.next_request_id = state.next_request_id.wrapping_add(1).max(1);
            let request_id = state.next_request_id;
            let (sender, receiver) = tokio::sync::oneshot::channel();
            state.pending = Some(PendingTunRebuild {
                request: TunRebuildRequest {
                    request_id,
                    ip,
                    prefix_len,
                    mtu,
                    session_name,
                    routes,
                },
                delivered: false,
                replacing: false,
                completion: sender,
            });
            (request_id, receiver)
        };
        self.changed.notify_waiters();
        match tokio::time::timeout(Duration::from_secs(30), completion).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(AndroidTunRebuildError::keep_current(error).into()),
            Ok(Err(_)) => {
                Err(AndroidTunRebuildError::keep_current("TUN 重建完成通道已关闭").into())
            }
            Err(_) => {
                self.finish(request_id, Err("等待 Android TUN 重建超时".to_string()))
                    .await;
                Err(AndroidTunRebuildError::keep_current("等待 Android TUN 重建超时").into())
            }
        }
    }

    pub async fn wait_next(&self) -> anyhow::Result<TunRebuildRequest> {
        loop {
            let notified = self.changed.notified();
            {
                let mut state = self.state.lock();
                if state.closed {
                    anyhow::bail!("TUN 重建协调器已经停止");
                }
                if let Some(pending) = state.pending.as_mut()
                    && !pending.delivered
                {
                    pending.delivered = true;
                    return Ok(pending.request.clone());
                }
            }
            notified.await;
        }
    }

    async fn claim(&self, request_id: u64) -> anyhow::Result<TunRebuildRequest> {
        let mut state = self.state.lock();
        let pending = state
            .pending
            .as_mut()
            .filter(|pending| pending.request.request_id == request_id && !pending.replacing)
            .context("TUN 重建请求不存在、已过期或正在替换")?;
        pending.replacing = true;
        Ok(pending.request.clone())
    }

    pub async fn finish(&self, request_id: u64, result: Result<(), String>) {
        let completion = {
            let mut state = self.state.lock();
            if state
                .pending
                .as_ref()
                .is_some_and(|pending| pending.request.request_id == request_id)
            {
                state.pending.take().map(|pending| pending.completion)
            } else {
                None
            }
        };
        if let Some(completion) = completion {
            let _ = completion.send(result);
        }
        self.changed.notify_waiters();
    }

    pub async fn reject(&self, request_id: u64, reason: String) -> anyhow::Result<()> {
        self.claim(request_id).await?;
        self.finish(request_id, Err(reason)).await;
        Ok(())
    }

    pub fn close(&self) {
        let completion = {
            let mut state = self.state.lock();
            state.closed = true;
            state.pending.take().map(|pending| pending.completion)
        };
        if let Some(completion) = completion {
            let _ = completion.send(Err("网络实例已经停止".to_string()));
        }
        self.changed.notify_waiters();
    }
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
    #[cfg(test)]
    fixed_ip: bool,
    #[cfg(target_os = "android")]
    tun_rebuild: TunRebuildCoordinator,
    #[cfg(target_os = "android")]
    tun_rebuild_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedNetworkApply {
    Live,
    ComponentReload,
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
        #[cfg(test)]
        let fixed_ip = registration_ip.get().is_some();
        Self {
            network,
            registration_ip,
            server_outbound,
            update_lock: Arc::new(tokio::sync::Mutex::new(())),
            device_io_manager,
            device_mode,
            event_script,
            server_addrs,
            #[cfg(test)]
            fixed_ip,
            #[cfg(target_os = "android")]
            tun_rebuild: TunRebuildCoordinator::default(),
            #[cfg(target_os = "android")]
            tun_rebuild_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn validate_target(current: NetworkAddr, new_ip: Ipv4Addr) -> anyhow::Result<NetworkAddr> {
        let net = current.network();
        if !net.contains(&new_ip) {
            bail!("更新 IP {new_ip} 不属于当前网段 {net}");
        }
        if current.gateway == Some(new_ip) {
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

    pub(crate) fn set_registered_ip(&self, ip: Ipv4Addr) {
        self.registration_ip.set(ip);
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

    #[cfg(all(test, not(target_os = "android")))]
    pub async fn apply_and_fast_register(&self, new_ip: Ipv4Addr) -> anyhow::Result<bool> {
        self.apply_ip(new_ip, false).await
    }

    /// Applies the managed virtual address and the effective MTU as a single
    /// runtime transaction. This is intentionally separate from `UpdateIp`:
    /// a server-originated address update must not silently alter the local
    /// MTU, while a revisioned managed configuration may change both.
    pub(crate) async fn apply_managed_network(
        &self,
        target: VirtualIp,
        mtu: u16,
        routes: Vec<NetInput>,
        tun_name: Option<Option<String>>,
    ) -> anyhow::Result<ManagedNetworkApply> {
        #[cfg(not(target_os = "android"))]
        let _ = &routes;
        let current = self
            .network
            .get()
            .ok_or_else(|| anyhow::anyhow!("客户端尚未完成网络注册"))?;
        // Ipv4Net preserves the host address it was constructed with. Compare
        // canonical network addresses rather than the Ipv4Net values
        // themselves, otherwise 10.26.0.9/24 and 10.26.0.10/24 appear to be
        // different networks merely because their host bits differ.
        if target.prefix_len() != current.prefix_len
            || target.network().network() != current.network().network()
        {
            bail!("受管 IP 的前缀或虚拟网段变化需要重启实例");
        }
        #[cfg(not(target_os = "android"))]
        return self
            .apply_managed_network_desktop(target.ip(), mtu, tun_name)
            .await;

        #[cfg(target_os = "android")]
        return self
            .apply_managed_android_network(target.ip(), mtu, routes, tun_name)
            .await;
    }

    #[cfg(not(target_os = "android"))]
    async fn apply_managed_network_desktop(
        &self,
        new_ip: Ipv4Addr,
        mtu: u16,
        tun_name: Option<Option<String>>,
    ) -> anyhow::Result<ManagedNetworkApply> {
        let _guard = self.update_lock.lock().await;
        let current = self
            .network
            .get()
            .ok_or_else(|| anyhow::anyhow!("客户端尚未完成网络注册"))?;
        let updated = Self::validate_target(current, new_ip)?;
        let ip_changed = updated.ip != current.ip;
        let mut action = ManagedNetworkApply::Live;
        if self.device_mode.has_device() {
            if let Some(tun_name) = tun_name {
                let mut config = DeviceConfig::default()
                    .set_device_mode(self.device_mode)
                    .set_mtu(mtu);
                if let Some(tun_name) = tun_name {
                    config = config.set_tun_name(tun_name);
                }
                if self.device_mode == DeviceMode::Tap {
                    config = config.set_mac_addr(crate::ethernet::mac_from_ip(new_ip).octets());
                }
                action = match self
                    .device_io_manager
                    .reconfigure_managed(config, new_ip, current.prefix_len)
                    .await?
                {
                    DeviceReconfigureAction::Live => ManagedNetworkApply::Live,
                    DeviceReconfigureAction::Rebuilt => ManagedNetworkApply::ComponentReload,
                };
            } else {
                self.device_io_manager
                    .set_network_and_mtu(new_ip, current.prefix_len, mtu)
                    .await?;
            }
        }
        self.network.set(updated);
        self.registration_ip.set(new_ip);
        if ip_changed {
            self.event_script
                .notify(
                    EventScriptType::IpUpdated,
                    &[
                        ("old-ip", current.ip.to_string()),
                        ("new-ip", updated.ip.to_string()),
                        ("prefix-length", updated.prefix_len.to_string()),
                        (
                            "gateway",
                            updated
                                .gateway
                                .map(|gateway| gateway.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                        ),
                        ("broadcast", updated.broadcast.to_string()),
                        ("server", self.server_addrs.join(",")),
                    ],
                )
                .await;
            self.send_fast_reg(new_ip).await;
        }
        Ok(action)
    }

    #[cfg(target_os = "android")]
    async fn apply_managed_android_network(
        &self,
        new_ip: Ipv4Addr,
        mtu: u16,
        routes: Vec<NetInput>,
        tun_name: Option<Option<String>>,
    ) -> anyhow::Result<ManagedNetworkApply> {
        let current = self
            .network
            .get()
            .ok_or_else(|| anyhow::anyhow!("客户端尚未完成网络注册"))?;
        Self::validate_target(current, new_ip)?;
        if !self.device_mode.has_device() {
            let updated = Self::validate_target(current, new_ip)?;
            let changed = updated.ip != current.ip;
            self.network.set(updated);
            self.registration_ip.set(new_ip);
            if changed {
                self.send_fast_reg(new_ip).await;
            }
            return Ok(ManagedNetworkApply::Live);
        }

        // Java pulls this request through JNI. Do not hold update_lock while
        // waiting, because replace_tun_task acquires it to commit the fd.
        let _serial = self.tun_rebuild_lock.lock().await;
        self.tun_rebuild
            .request(new_ip, current.prefix_len, mtu, routes, tun_name.flatten())
            .await?;
        Ok(ManagedNetworkApply::ComponentReload)
    }

    #[cfg(target_os = "android")]
    pub fn tun_rebuild_coordinator(&self) -> TunRebuildCoordinator {
        self.tun_rebuild.clone()
    }

    #[cfg(target_os = "android")]
    pub async fn replace_android_tun_task(
        &self,
        request_id: u64,
        tun_fd: std::os::fd::OwnedFd,
    ) -> anyhow::Result<()> {
        let result = async {
            let _guard = self.update_lock.lock().await;
            // Claim only after acquiring the device transaction lock. A
            // 30-second request timeout can then cancel an fd that is still
            // waiting behind another device update, before it changes TUN.
            let request = self.tun_rebuild.claim(request_id).await?;
            let current = self.network.get().context("客户端尚未完成网络注册")?;
            let updated = Self::validate_target(current, request.ip)?;
            self.device_io_manager
                .replace_task_fd(tun_fd, request.ip, request.prefix_len, request.mtu)
                .await?;
            let ip_changed = updated.ip != current.ip;
            self.network.set(updated);
            self.registration_ip.set(request.ip);
            if ip_changed {
                self.send_fast_reg(request.ip).await;
            }
            Ok(())
        }
        .await;
        self.tun_rebuild
            .finish(
                request_id,
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|error| format!("{error:#}")),
            )
            .await;
        result
    }

    #[cfg(target_os = "android")]
    pub async fn reject_android_tun_rebuild(
        &self,
        request_id: u64,
        reason: String,
    ) -> anyhow::Result<()> {
        self.tun_rebuild.reject(request_id, reason).await
    }

    #[cfg(target_os = "android")]
    pub async fn request_android_route_rebuild(&self, routes: Vec<NetInput>) -> anyhow::Result<()> {
        let _serial = self.tun_rebuild_lock.lock().await;
        if !self.device_mode.has_device() {
            return Ok(());
        }
        let network = self.network.get().context("客户端尚未完成网络注册")?;
        let mtu = self.device_io_manager.current_mtu().await?;
        self.tun_rebuild
            .request(network.ip, network.prefix_len, mtu, routes, None)
            .await
    }

    #[cfg(target_os = "android")]
    pub fn close_android_tun_rebuild(&self) {
        self.tun_rebuild.close();
    }

    #[cfg(all(test, not(target_os = "android")))]
    async fn apply_ip(&self, new_ip: Ipv4Addr, managed: bool) -> anyhow::Result<bool> {
        let _guard = self.update_lock.lock().await;
        let current = self
            .network
            .get()
            .ok_or_else(|| anyhow::anyhow!("客户端尚未完成网络注册"))?;
        if !managed && self.fixed_ip && new_ip != current.ip {
            bail!("服务器不能修改客户端配置的固定虚拟 IP")
        }
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
                            (
                                "gateway",
                                updated
                                    .gateway
                                    .map(|gateway| gateway.to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                            ),
                            ("broadcast", updated.broadcast.to_string()),
                            ("server", self.server_addrs.join(",")),
                        ],
                    )
                    .await;
            }
            self.send_fast_reg(new_ip).await;
            Ok(true)
        }
    }
}

pub(crate) struct ServerTurnInboundHandler {
    server_id: u32,
    network_route: NetworkRoute,
    server_info: ServerInfoCollection,
    nat_info: MyNatInfo,
    peer_map: PeerInfoMap,
    punch_backoff: PunchBackoff,
    puncher: NatPuncher,
    packet_crypto: PacketCrypto,
    enhanced_inbound: EnhancedInbound,
    fec_decoder: FecDecoder,
    policy: RuntimePolicyStore,
    basic_outbound: crate::tunnel_core::outbound::BasicOutbound,
    app_state: crate::context::AppState,
    subscription_verified: Arc<AtomicBool>,
    subscription_identity: Option<(String, String)>,
    last_unverified_push_log: Arc<AtomicI64>,
}

fn valid_server_relay_ipv4(
    payload: &[u8],
    src: Ipv4Addr,
    dest_id: Ipv4Addr,
    local_ip: Ipv4Addr,
    network_route: &NetworkRoute,
    relay_subnets: &AllowSubnetExternalRoute,
) -> bool {
    let Some(ipv4) = Ipv4Packet::new(payload) else {
        return false;
    };
    let header_length = ipv4.get_header_length() as usize * 4;
    ipv4.get_version() == 4
        && header_length >= Ipv4Packet::minimum_packet_size()
        && header_length <= payload.len()
        && ipv4.get_total_length() as usize == payload.len()
        && (ipv4.get_source() == src
            || network_route.subnet_route.route(&ipv4.get_source()) == Some(src))
        && (ipv4.get_destination() == local_ip || relay_subnets.allow(&ipv4.get_destination()))
        && dest_id == local_ip
}

fn server_relay_allowed(msg_type: MsgType, allow_ikev2: bool, allow_wireguard: bool) -> bool {
    (msg_type == MsgType::Ikev2Relay && allow_ikev2)
        || (msg_type == MsgType::WireGuardRelay && allow_wireguard)
}

impl ServerTurnInboundHandler {
    pub fn reconcile_server_network(
        &self,
        ip: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    ) -> bool {
        self.network_route
            .network
            .reconcile_server(ip, prefix_len, gateway)
    }
    pub fn new(
        server_id: u32,
        config: Box<super::connection_manager::InboundHandlerConfig>,
        subscription_verified: Arc<AtomicBool>,
        subscription_identity: Option<(String, String)>,
    ) -> Self {
        let config = *config;
        Self {
            server_id,
            network_route: config.network_route,
            server_info: config.server_info,
            nat_info: config.nat_info,
            peer_map: config.peer_map,
            punch_backoff: config.punch_backoff,
            puncher: config.puncher,
            packet_crypto: config.packet_crypto,
            enhanced_inbound: config.enhanced_inbound,
            fec_decoder: config.fec_decoder,
            policy: config.policy,
            basic_outbound: config.basic_outbound,
            app_state: config.app_state,
            subscription_verified,
            subscription_identity,
            last_unverified_push_log: Arc::new(AtomicI64::new(0)),
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
    fn get_punch_info(&self, target: Ipv4Addr) -> Option<PunchInfo> {
        self.nat_info.get().map(|info| PunchInfo {
            nat_info: self.filter_ip(info),
            punch_model: punch_model_for(&self.policy.load().punch_model, &target),
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
        let policy = self.policy.load();
        let mut net_packet = policy.packet_compression.decompress(net_packet)?;

        match msg_type {
            MsgType::Ikev2Relay | MsgType::WireGuardRelay
                if server_relay_allowed(msg_type, policy.allow_ikev2, policy.allow_wireguard) =>
            {
                if !valid_server_relay_ipv4(
                    net_packet.payload(),
                    src,
                    Ipv4Addr::from(net_packet.dest_id()),
                    network_addr.ip,
                    &self.network_route,
                    &policy.relay_subnets,
                ) {
                    return Ok(());
                }
                self.enhanced_inbound
                    .inbound(&network_addr, MsgType::Turn, src, net_packet)
                    .await?;
            }
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
                let changed = self.server_info.update_client_simple_list(
                    self.server_id,
                    network_addr.ip,
                    list,
                    now,
                );
                for ip in changed {
                    self.punch_backoff.reset(ip);
                }
            }
            MsgType::RpcRes => {
                // 设置rpc响应
                let response = RpcMessageResponse::decode(net_packet.payload())?;
                rpc_notifier.notify_response(response);
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
            MsgType::SubnetSyncRes if policy.auto_sync_subnet => {
                let response = SubnetSyncResponse::from_slice(net_packet.payload())?;
                self.server_info
                    .update_subnet_snapshot(self.server_id, response);
                self.refresh_automatic_subnet_routes(network_addr.ip);
            }
            MsgType::SubscriptionConfigPush => {
                if !self.subscription_verified.load(Ordering::Acquire) {
                    let now = crate::utils::time::now_ts_ms();
                    let last = self.last_unverified_push_log.load(Ordering::Relaxed);
                    if now.saturating_sub(last) >= 10_000
                        && self
                            .last_unverified_push_log
                            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                            .is_ok()
                    {
                        log::warn!(
                            "服务器 {} 未通过订阅链接凭据校验，已忽略其下发的配置",
                            self.server_id
                        );
                    }
                    return Ok(());
                }
                let config = SubscriptionConfigEnvelope::from_slice(net_packet.payload())?;
                if self.subscription_identity.as_ref().is_none_or(|identity| {
                    identity.0 != config.network_code || identity.1 != config.device_id
                }) {
                    log::warn!(
                        "服务器 {} 下发了不匹配的订阅链接管理身份，已忽略",
                        self.server_id
                    );
                    return Ok(());
                }
                self.app_state.push_subscription_config(config);
            }
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
        let msg_type = net_packet.msg_type()?;
        let graph_raw = if msg_type == MsgType::NodeAnnouncement {
            let mut raw = NetPacket::new(net_packet.source_buf().clone())?;
            raw.decr_ttl();
            Some(raw.into_bytes())
        } else {
            None
        };

        // FEC 外层只做认证，解码后再按每个内层包的类型决定是否 AEAD 解密。
        if net_packet.is_fec() {
            let packets = self.fec_decoder.receive(net_packet)?;
            if let Some(packets) = packets {
                for pkt in packets {
                    self.process_inner_packet(network_addr, transport_client, pkt, None)
                        .await?;
                }
            }
            return Ok(());
        }

        self.process_inner_packet(network_addr, transport_client, net_packet, graph_raw)
            .await
    }

    async fn process_inner_packet(
        &self,
        network_addr: NetworkAddr,
        transport_client: &mut TransportClient,
        mut net_packet: NetPacket<TransmissionBytes>,
        graph_raw: Option<NetPacket<bytes::Bytes>>,
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
        if let Some(raw) = graph_raw {
            let source = Ipv4Addr::from(net_packet.src_id());
            if msg_type == MsgType::NodeAnnouncement {
                crate::protocol::client_message::NodeAnnouncement::from_slice(
                    net_packet.payload(),
                    source,
                )?;
                if !network_addr.network().contains(&source) {
                    return Ok(());
                }
            }
            if !self
                .basic_outbound
                .graph_first_seen(msg_type, source, net_packet.seq())
            {
                return Ok(());
            }
            if raw.ttl() >= 1 {
                self.basic_outbound.flood_direct_p2p(&raw, None);
            }
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

        let net_packet = self
            .policy
            .load()
            .packet_compression
            .decompress(net_packet)?;
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
            MsgType::Turn => {
                self.enhanced_inbound
                    .inbound(&network_addr, msg_type, src, net_packet)
                    .await?;
            }
            MsgType::Broadcast => {
                if network_addr.network().contains(&src)
                    && src != network_addr.ip
                    && src != network_addr.network().network()
                    && src != network_addr.broadcast
                    && !src.is_unspecified()
                    && !src.is_broadcast()
                    && !src.is_multicast()
                    && self
                        .basic_outbound
                        .broadcast_first_delivery(src, net_packet.seq())
                {
                    self.enhanced_inbound
                        .inbound(&network_addr, msg_type, src, net_packet)
                        .await?;
                }
            }
            MsgType::PunchStart1 => {
                if !allow_punch(&self.policy.load().turn, &src) {
                    log::debug!("ignore configured turn target PunchStart1 from {src}");
                    return Ok(());
                }
                // 对方发起打洞
                let peer_punch_info = PunchInfo::from_slice(net_packet.payload())?;
                let Some(mut self_punch_info) = self.get_punch_info(src) else {
                    return Ok(());
                };
                log::info!(
                    "对方主动发起打洞 对方nat信息={peer_punch_info:?}，自己nat信息={self_punch_info:?} {src}->{dest}"
                );
                self.update_peer_nat_info(src, peer_punch_info.nat_info.clone());
                let effective_policies = self.puncher.punch(src, peer_punch_info)?;
                if let Some(effective_policies) = effective_policies {
                    // 回传双方都支持的请求策略，确保发起端也只打当前缺失的路由类型。
                    self_punch_info.punch_model = effective_policies;
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
                if !allow_punch(&self.policy.load().turn, &src) {
                    log::debug!("ignore configured turn target PunchStart2 from {src}");
                    return Ok(());
                }
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
        let graph_message = net_packet.msg_type()? == MsgType::NodeAnnouncement;
        if !graph_message
            && !dest.is_broadcast()
            && !dest.is_unspecified()
            && network_addr.ip != dest
        {
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

    pub async fn handle_subnet_sync(
        &self,
        transport_client: &mut TransportClient,
    ) -> anyhow::Result<()> {
        if self.policy.load().auto_sync_subnet
            && let Some(known_hash) = self.server_info.subnet_sync_request_hash(self.server_id)
        {
            let payload = encode_subnet_sync_request(&known_hash);
            let mut packet =
                NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + payload.len()))?;
            packet.set_ttl(1);
            packet.set_msg_type(MsgType::SubnetSyncReq);
            packet.set_gateway_flag(true);
            packet.set_payload(&payload)?;
            transport_client
                .send(packet.into_buffer().into_bytes().freeze())
                .await?;
        }
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
    pub fn set_server_identity(&self, instance_id: Vec<u8>, supported: bool) {
        self.server_info
            .set_server_identity(self.server_id, instance_id, supported);
    }
    pub fn set_subnet_sync_supported(&self, supported: bool) {
        self.server_info
            .set_subnet_sync_supported(self.server_id, supported);
    }
    pub fn network_addr(&self) -> Option<NetworkAddr> {
        self.network_route.network.get()
    }
    pub fn handle_disconnected(&self) {
        if self.server_info.set_server_connected(self.server_id, false) {
            self.server_info
                .set_disconnected_time(self.server_id, Some(crate::utils::time::now_ts_ms()));
        }
        if let Some(network) = self.network_route.network.get() {
            self.refresh_automatic_subnet_routes(network.ip);
        }
    }

    fn refresh_automatic_subnet_routes(&self, self_ip: Ipv4Addr) {
        let static_routes = self.network_route.subnet_route.static_routes();
        let routes = self
            .server_info
            .automatic_subnet_routes(self_ip, &static_routes);
        self.network_route.subnet_route.set_automatic_routes(routes);
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use crate::context::ServerInfoCollection;
    use crate::crypto::PacketCrypto;
    use crate::tunnel_core::server::transport::config::ProtocolAddress;
    use crate::utils::task_control::TaskGroupManager;
    use pnet_packet::ipv4::MutableIpv4Packet;
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
            gateway: Some(Ipv4Addr::new(10, 26, 0, 1)),
            broadcast: Ipv4Addr::new(10, 26, 0, 255),
        }
    }

    fn relay_ipv4(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut bytes = vec![0; Ipv4Packet::minimum_packet_size()];
        let mut packet = MutableIpv4Packet::new(&mut bytes).unwrap();
        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_total_length(Ipv4Packet::minimum_packet_size() as u16);
        packet.set_source(source);
        packet.set_destination(destination);
        drop(packet);
        bytes
    }

    #[test]
    fn server_relay_ipv4_authorizes_virtual_and_declared_subnet_addresses() {
        let source = Ipv4Addr::new(10, 26, 0, 9);
        let local = Ipv4Addr::new(10, 26, 0, 8);
        let shared_network = SharedNetworkAddr::default();
        shared_network.set(network(local));
        let network_route = NetworkRoute::new(
            shared_network,
            crate::nat::SubnetExternalRoute::new(vec![
                "192.168.30.0/24,10.26.0.9".parse().unwrap(),
            ]),
        );
        let relay_subnets = AllowSubnetExternalRoute::new(vec!["172.16.0.0/16".parse().unwrap()]);
        let check = |payload: &[u8], src, dest_id| {
            valid_server_relay_ipv4(payload, src, dest_id, local, &network_route, &relay_subnets)
        };
        let valid = relay_ipv4(source, local);
        assert!(check(&valid, source, local));
        assert!(!check(&valid, Ipv4Addr::new(10, 26, 0, 7), local));
        assert!(!check(&valid, source, Ipv4Addr::new(10, 26, 0, 7)));

        let subnet = relay_ipv4(Ipv4Addr::new(192, 168, 30, 7), Ipv4Addr::new(172, 16, 2, 3));
        assert!(check(&subnet, source, local));
        assert!(!check(&subnet, Ipv4Addr::new(10, 26, 0, 7), local));

        let wrong_destination = relay_ipv4(source, Ipv4Addr::new(10, 26, 0, 7));
        assert!(!check(&wrong_destination, source, local));

        let mut wrong_length = valid;
        wrong_length.push(0);
        assert!(!check(&wrong_length, source, local));

        let mut oversized_header = relay_ipv4(source, local);
        MutableIpv4Packet::new(&mut oversized_header)
            .unwrap()
            .set_header_length(15);
        assert!(!check(&oversized_header, source, local));
    }

    #[test]
    fn server_relay_capabilities_are_independent() {
        assert!(server_relay_allowed(MsgType::Ikev2Relay, true, false));
        assert!(!server_relay_allowed(MsgType::WireGuardRelay, true, false));
        assert!(server_relay_allowed(MsgType::WireGuardRelay, false, true));
        assert!(!server_relay_allowed(MsgType::Ikev2Relay, false, true));
        assert!(!server_relay_allowed(MsgType::Turn, true, true));
    }

    #[test]
    fn wireguard_relay_accepts_declared_subnet_endpoints_when_enabled() {
        let source = Ipv4Addr::new(10, 26, 0, 9);
        let local = Ipv4Addr::new(10, 26, 0, 8);
        let shared_network = SharedNetworkAddr::default();
        shared_network.set(network(local));
        let network_route = NetworkRoute::new(
            shared_network,
            crate::nat::SubnetExternalRoute::new(vec![
                "192.168.60.0/24,10.26.0.9".parse().unwrap(),
            ]),
        );
        let relay_subnets = AllowSubnetExternalRoute::new(vec!["172.23.0.0/16".parse().unwrap()]);
        let packet = relay_ipv4(Ipv4Addr::new(192, 168, 60, 7), Ipv4Addr::new(172, 23, 1, 8));

        assert!(server_relay_allowed(MsgType::WireGuardRelay, false, true));
        assert!(valid_server_relay_ipv4(
            &packet,
            source,
            local,
            local,
            &network_route,
            &relay_subnets,
        ));
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
        let registration_ip = SharedRegistrationIp::new(None);

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
        registration_ip.set(initial_ip);
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
    }

    #[tokio::test]
    async fn managed_ip_change_inside_same_prefix_is_live() {
        let TestUpdateContext {
            context,
            network: shared_network,
            registration_ip,
            ..
        } = update_context(DeviceMode::No, true, 1);
        let target = VirtualIp::new(Ipv4Addr::new(10, 26, 0, 10), 24).unwrap();

        assert_eq!(
            context
                .apply_managed_network(target, crate::core::DEFAULT_MTU, Vec::new(), None)
                .await
                .unwrap(),
            ManagedNetworkApply::Live
        );
        assert_eq!(shared_network.ip(), Some(Ipv4Addr::new(10, 26, 0, 10)));
        assert_eq!(registration_ip.get(), Some(Ipv4Addr::new(10, 26, 0, 10)));
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
    async fn server_cannot_replace_a_configured_fixed_ip() {
        let TestUpdateContext {
            mut context,
            network: shared_network,
            registration_ip,
            ..
        } = update_context(DeviceMode::No, true, 1);
        context.fixed_ip = true;
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

    #[tokio::test]
    async fn tun_rebuild_request_is_delivered_once_and_completed_by_java_side() {
        let coordinator = TunRebuildCoordinator::default();
        let request_coordinator = coordinator.clone();
        let apply = tokio::spawn(async move {
            request_coordinator
                .request(
                    Ipv4Addr::new(10, 26, 0, 9),
                    24,
                    1380,
                    Vec::new(),
                    Some("Managed VPN".to_string()),
                )
                .await
        });

        let request = tokio::time::timeout(Duration::from_secs(1), coordinator.wait_next())
            .await
            .expect("request should wake a blocked Java waiter")
            .unwrap();
        assert_eq!(request.ip, Ipv4Addr::new(10, 26, 0, 9));
        assert_eq!(request.prefix_len, 24);
        assert_eq!(request.mtu, 1380);
        assert_eq!(request.session_name.as_deref(), Some("Managed VPN"));
        assert_eq!(
            coordinator.claim(request.request_id).await.unwrap(),
            request,
            "the Java-side fd handoff claims exactly the delivered request"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), coordinator.wait_next())
                .await
                .is_err()
        );

        coordinator.finish(request.request_id, Ok(())).await;
        assert!(apply.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn tun_rebuild_close_wakes_waiters_and_rejects_pending_request() {
        let coordinator = TunRebuildCoordinator::default();
        assert!(!AndroidTunRebuildError::keep_current("test").restart_required);

        let request_coordinator = coordinator.clone();
        let rejected = tokio::spawn(async move {
            request_coordinator
                .request(Ipv4Addr::new(10, 26, 0, 9), 24, 1380, Vec::new(), None)
                .await
        });
        let request = coordinator.wait_next().await.unwrap();
        coordinator
            .reject(request.request_id, "VPN builder failed".to_string())
            .await
            .unwrap();
        assert!(rejected.await.unwrap().is_err());

        let waiter_coordinator = coordinator.clone();
        let waiter = tokio::spawn(async move { waiter_coordinator.wait_next().await });
        tokio::task::yield_now().await;
        coordinator.close();
        assert!(waiter.await.unwrap().is_err());

        let request_coordinator = coordinator.clone();
        assert!(
            request_coordinator
                .request(Ipv4Addr::new(10, 26, 0, 9), 24, 1380, Vec::new(), None)
                .await
                .is_err()
        );
    }
}
