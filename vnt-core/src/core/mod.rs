use crate::api::VntApi;
use crate::compression::PacketCompression;
use crate::context::config::{Config, DeviceMode};
use crate::context::{AppState, NetworkAddr, NetworkRoute};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::enhanced_ipv4_tunnel;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::enhanced_tunnel::outbound::EnhancedOutbound;
use crate::event_script::EventScript;
#[cfg(not(target_os = "android"))]
use crate::event_script::EventScriptType;
use crate::fec::{FecDecoder, FecEncoder};
#[cfg(target_os = "android")]
use crate::nat::NetInput;
use crate::nat::internal_nat::{InternalNatInbound, PortMappingManager};
use crate::nat::subnet_packet::SubnetPacketMapper;
use crate::nat::{
    AllowSubnetExternalRoute, SubnetExternalRoute, SubnetMappingTable, advertised_subnets,
};
use crate::protocol::client_message::NodeIdentityTemplate;
use crate::protocol::control_message::ErrorResponseMsg;
use crate::tun::enhanced_tun::EnhancedTunInbound;
use crate::tun::{DeviceConfig, DeviceIOManager, TunDataInbound, TunReceiver, tun_channel};
use crate::tunnel_core::outbound::{BasicOutbound, HybridOutbound};
use crate::tunnel_core::p2p::inbound::{P2pInboundConfig, P2pInboundHandler};
use crate::tunnel_core::p2p::transport::punch::{NatPuncher, PunchTaskContext, gossip_punch_task};
use crate::tunnel_core::p2p::transport::task::{
    P2pInitConfig, init_tunnel, node_announcement_task,
};
use crate::tunnel_core::server::connection_manager::{
    InboundHandlerConfig, ServerTurnManager, create_server_tunnel, register_with_first_available,
};
use crate::tunnel_core::server::inbound::IpUpdateContext;
use crate::tunnel_core::server::rpc::ServerRPC;
use crate::utils::task_control::TaskGroup;
use anyhow::{Context, bail};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

pub const DEFAULT_MTU: u16 = 1380;

#[cfg(target_os = "android")]
pub type AndroidSubnetRouteCallback =
    std::sync::Arc<dyn Fn(Vec<NetInput>) -> anyhow::Result<()> + Send + Sync + 'static>;

/// Context for deferred registration
struct RegistrationContext {
    server_managers: Vec<ServerTurnManager>,
    ip_update: IpUpdateContext,
    subnet_external_route: SubnetExternalRoute,
    puncher: NatPuncher,
    packet_crypto: PacketCrypto,
    packet_compression: PacketCompression,
    enhanced_inbound: EnhancedInbound,
    fec_decoder: FecDecoder,
    turn: std::sync::Arc<Vec<crate::context::config::TurnRule>>,
    punch_model: std::sync::Arc<Vec<crate::context::config::PunchRule>>,
    auto_sync_subnet: bool,
    allow_ikev2: bool,
    allow_wireguard: bool,
    relay_subnets: AllowSubnetExternalRoute,
    basic_outbound: BasicOutbound,
    node_identity: NodeIdentityTemplate,
}

pub struct NetworkManager {
    config: Box<Config>,
    event_script: EventScript,
    app_state: AppState,
    task_group: TaskGroup,
    device_io_manager: DeviceIOManager,
    #[cfg(target_os = "android")]
    ip_update: IpUpdateContext,
    enhanced_outbound: Option<EnhancedOutbound>,
    server_rpc: ServerRPC,
    tun_receiver: Option<TunReceiver>,
    registration_context: Option<Box<RegistrationContext>>,
    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
    system_routes_started: std::sync::atomic::AtomicBool,
}
pub enum RegisterResponse {
    Success(NetworkAddr),
    Failed(ErrorResponseMsg),
}

impl NetworkManager {
    pub async fn create_network(
        mut config: Box<Config>,
        task_group: TaskGroup,
    ) -> anyhow::Result<NetworkManager> {
        let app_state = AppState::default();
        // 本机 NAT 身份变化（换网/NAT 重启等）时，把所有对端的
        // 打洞退避截止时刻压缩到 10 分钟内；对称 NAT 的端口抖动
        // 不算变化（见 nat_identity_changed）
        let backoff = app_state.punch_backoff.clone();
        app_state.nat_info.set_on_change(move || backoff.cap_all());
        config.normalize()?;
        config.check()?;
        let turn = std::sync::Arc::new(config.turn.clone());
        let punch_model = std::sync::Arc::new(config.punch_model.clone());
        let outbound_interface_name = config
            .outbound_interface
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        let resolved_interface =
            crate::utils::socket::resolve_interface(outbound_interface_name.as_deref())?;
        let default_interface = resolved_interface
            .as_ref()
            .map(|interface| interface.socket_interface.clone());
        let canonical_interface_name = resolved_interface
            .as_ref()
            .map(|interface| interface.name.clone());
        if let Some(name) = canonical_interface_name.as_deref() {
            log::info!("绑定出口网卡: {name}");
        }
        let mtu = config.mtu.unwrap_or(DEFAULT_MTU);
        let packet_crypto = PacketCrypto::new_from_str(config.password.as_deref())?;
        let packet_compression = PacketCompression::new(config.compress);
        let node_identity = NodeIdentityTemplate {
            name: config.device_name.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            network_code: config.network_code.clone(),
            advertised_subnets: advertised_subnets(&config.output, &config.subnet_mapping),
        };
        let (server_manager_list, tunnel_to_server, server_rpc, registration_ip) =
            create_server_tunnel(
                app_state.clone(),
                &config,
                packet_crypto.clone(),
                default_interface.clone(),
            );
        let device_io_manager = DeviceIOManager::new(task_group.clone());
        let ip_update = IpUpdateContext::new(
            app_state.network.clone(),
            registration_ip,
            tunnel_to_server.clone(),
            device_io_manager.clone(),
            config.device_mode,
            EventScript::new(config.event_script.clone()),
            config
                .server_addr
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
        );
        let allow_subnet = AllowSubnetExternalRoute::new(config.output.clone());
        let relay_subnets = AllowSubnetExternalRoute::new(advertised_subnets(
            &config.output,
            &config.subnet_mapping,
        ));

        let p2p_enabled =
            !config.no_punch || !config.peer_address.is_empty() || !config.turn.is_empty();
        let (puncher, p2p_socket, p2p_task) = if p2p_enabled {
            let (puncher, p2p_socket_manager, p2p_task) = init_tunnel(
                task_group.clone(),
                app_state.clone(),
                tunnel_to_server.clone(),
                packet_crypto.clone(),
                P2pInitConfig {
                    tunnel_addr: config.tunnel_addr.clone(),
                    tunnel_port: config.tunnel_port,
                    automatic_punch: !config.no_punch,
                    auto_sync_subnet: config.auto_sync_subnet,
                    peer_address: config.peer_address.clone(),
                    turn: turn.clone(),
                    default_interface: default_interface.clone(),
                    identity: node_identity.clone(),
                },
            )
            .await?;

            (
                (!config.no_punch).then_some(puncher),
                Some(p2p_socket_manager),
                Some(p2p_task),
            )
        } else {
            (None, None, None)
        };
        let puncher = NatPuncher::new(
            app_state.network.clone(),
            app_state.punch_backoff.clone(),
            puncher,
            packet_crypto.clone(),
            punch_model.clone(),
            node_identity.clone(),
        );
        let subnet_external_route = app_state.subnet_route.clone();
        subnet_external_route.set_route_table(config.input.clone());
        let subnet_mapping = SubnetMappingTable::new(config.subnet_mapping.clone());
        let subnet_packet_mapper = SubnetPacketMapper::default();

        let fec_decoder = FecDecoder::new(packet_crypto.clone());
        let basic_outbound = BasicOutbound::new(
            tunnel_to_server.clone(),
            p2p_socket.clone(),
            packet_crypto.clone(),
            turn.clone(),
            node_identity.clone(),
        );
        if p2p_socket.is_some() {
            task_group.spawn(node_announcement_task(
                app_state.network.clone(),
                basic_outbound.clone(),
                node_identity.clone(),
            ));
        }
        if !config.no_punch {
            let punch_state = app_state.clone();
            let punch_ctx = PunchTaskContext {
                network: app_state.network.clone(),
                server_info: app_state.server_info_collection.clone(),
                punch_backoff: app_state.punch_backoff.clone(),
                punch_info_getter: std::sync::Arc::new(move |target| {
                    punch_state.get_punch_info(target)
                }),
                turn: turn.clone(),
            };
            task_group.spawn(gossip_punch_task(
                basic_outbound.clone(),
                app_state.route_table.clone(),
                punch_ctx,
            ));
        }
        let fec_encoder = if config.fec {
            Some(FecEncoder::new(
                &task_group,
                basic_outbound.clone(),
                app_state.network.clone(),
            ))
        } else {
            None
        };

        let hybrid_outbound = HybridOutbound::new(
            app_state.network.clone(),
            app_state.server_info_collection.clone(),
            app_state.traffic_stats.clone(),
            basic_outbound.clone(),
            packet_compression.clone(),
            subnet_external_route.clone(),
            subnet_mapping.clone(),
            subnet_packet_mapper.clone(),
            relay_subnets.clone(),
            fec_encoder,
        )
        .with_no_broadcast(config.no_broadcast)
        .with_allow_ikev2(config.allow_ikev2)
        .with_allow_wireguard(config.allow_wireguard);
        let port_mapping_manager = PortMappingManager::new(
            config.device_mode == DeviceMode::No,
            config.allow_port_mapping,
            app_state.network.clone(),
            default_interface.clone(),
        );
        let internal_nat_inbound = if config.no_nat && config.device_mode != DeviceMode::No {
            None
        } else {
            let nat_inbound = InternalNatInbound::create(
                &task_group,
                mtu,
                hybrid_outbound.clone(),
                allow_subnet.clone(),
                app_state.network.clone(),
                config.device_mode == DeviceMode::No,
                default_interface.clone(),
            )
            .await?;
            Some(nat_inbound)
        };

        let (enhanced_tun_inbound, tun_receiver) = match config.device_mode {
            DeviceMode::No => (
                EnhancedTunInbound::Nat(
                    internal_nat_inbound
                        .clone()
                        .context("internal NAT is unavailable in no-device mode")?,
                ),
                None,
            ),
            mode @ (DeviceMode::Tun | DeviceMode::Tap) => {
                let (tun_inbound, tun_receiver) = tun_channel();
                let tun_data_sender = TunDataInbound::new(tun_inbound, allow_subnet.clone(), mode);
                let inbound = if mode == DeviceMode::Tap {
                    EnhancedTunInbound::Tap(tun_data_sender)
                } else {
                    EnhancedTunInbound::Tun(tun_data_sender)
                };
                (inbound, Some(tun_receiver))
            }
        };

        let (enhanced_inbound, enhanced_outbound) = enhanced_ipv4_tunnel(
            app_state.clone(),
            task_group.clone(),
            enhanced_tun_inbound,
            crate::enhanced_tunnel::TunnelConfig {
                mtu,
                password: config.password.clone(),
                open_quic_client: config.rtx,
                port_mapping: config.port_mapping.clone(),
                device_mode: config.device_mode,
            },
            crate::enhanced_tunnel::TunnelComponents {
                hybrid_outbound: hybrid_outbound.clone(),
                external_route: subnet_external_route.clone(),
                subnet_mapping,
                subnet_packet_mapper,
                internal_nat_inbound,
                port_mapping_manager,
            },
        )
        .await?;

        if let Some(p2p_task) = p2p_task {
            let handler = P2pInboundHandler::new(P2pInboundConfig {
                network_route: NetworkRoute::new(
                    app_state.network.clone(),
                    subnet_external_route.clone(),
                ),
                route_table: app_state.route_table.clone(),
                packet_loss_stats: app_state.packet_loss_stats.clone(),
                packet_crypto: packet_crypto.clone(),
                packet_compression: packet_compression.clone(),
                enhanced_inbound: enhanced_inbound.clone(),
                fec_decoder: fec_decoder.clone(),
                turn: turn.clone(),
                basic_outbound: basic_outbound.clone(),
                punch_backoff: app_state.punch_backoff.clone(),
                identity: node_identity.clone(),
                auto_sync_subnet: config.auto_sync_subnet,
                puncher: puncher.clone(),
                punch_info_getter: {
                    let state = app_state.clone();
                    std::sync::Arc::new(move |target| state.get_punch_info(target))
                },
                peer_map: app_state.peer_map.clone(),
            });
            p2p_task.start(handler);
        }

        let registration_context = Box::new(RegistrationContext {
            server_managers: server_manager_list,
            ip_update: ip_update.clone(),
            subnet_external_route,
            puncher,
            packet_crypto,
            packet_compression,
            enhanced_inbound,
            fec_decoder,
            turn,
            punch_model,
            auto_sync_subnet: config.auto_sync_subnet,
            allow_ikev2: config.allow_ikev2,
            allow_wireguard: config.allow_wireguard,
            relay_subnets,
            basic_outbound: basic_outbound.clone(),
            node_identity: node_identity.clone(),
        });

        app_state.set_config(config.clone());
        let event_script = EventScript::new(config.event_script.clone());
        Ok(Self {
            config,
            event_script,
            app_state,
            task_group,
            device_io_manager,
            #[cfg(target_os = "android")]
            ip_update,
            enhanced_outbound,
            server_rpc,
            tun_receiver,
            registration_context: Some(registration_context),
            #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
            system_routes_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Register with server(s) and start data handling tasks.
    /// Returns the registration response on success.
    /// On connection-level failure the internal state is kept, so the call can be retried.
    pub async fn register(&mut self) -> anyhow::Result<RegisterResponse> {
        let Some(mut ctx) = self.registration_context.take() else {
            bail!("register can only be called once");
        };
        match Self::register_impl(&self.app_state, &self.task_group, &mut ctx, self.config.ip).await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                // 注册失败时归还上下文，允许调用方重试
                self.registration_context = Some(ctx);
                Err(e)
            }
        }
    }

    async fn register_impl(
        app_state: &AppState,
        task_group: &TaskGroup,
        ctx: &mut RegistrationContext,
        fixed_ip: Option<crate::context::config::VirtualIp>,
    ) -> anyhow::Result<RegisterResponse> {
        let mut initially_connected_server = None;
        let network_addr = if let Some(fixed_ip) = fixed_ip {
            let network = fixed_ip.network();
            let addr = NetworkAddr {
                gateway: None,
                broadcast: network.broadcast(),
                ip: fixed_ip.ip(),
                prefix_len: fixed_ip.prefix_len(),
            };
            app_state.network.set(addr);
            log::info!("Local fixed network activated: {fixed_ip}");
            addr
        } else {
            let is_multi_server = ctx.server_managers.len() > 1;
            let (server_index, response) = if is_multi_server {
                // A fixed IP lets each server register independently. Start as soon
                // as one server is ready and reconnect the rest in the background.
                log::info!(
                    "Multi-server mode: registering concurrently with {} servers",
                    ctx.server_managers.len()
                );
                register_with_first_available(&mut ctx.server_managers).await?
            } else {
                log::info!("Single-server mode: performing normal registration");
                (
                    0,
                    ctx.server_managers[0]
                        .connect_and_reg(crate::protocol::control_message::RegistrationMode::Normal)
                        .await?,
                )
            };
            let reg_response = match response {
                crate::protocol::control_message::ResponseMessage::Reg(reg) => reg,
                crate::protocol::control_message::ResponseMessage::Error(e) => {
                    return Ok(RegisterResponse::Failed(e));
                }
                crate::protocol::control_message::ResponseMessage::ConfirmReg(_) => {
                    bail!("Unexpected ConfirmReg response");
                }
                crate::protocol::control_message::ResponseMessage::FastReg(_) => {
                    bail!("Unexpected FastReg response");
                }
            };
            let addr = NetworkAddr {
                gateway: Some(reg_response.gateway),
                broadcast: Ipv4Net::new(reg_response.ip, reg_response.prefix_len)?.broadcast(),
                ip: reg_response.ip,
                prefix_len: reg_response.prefix_len,
            };
            app_state.network.set(addr);
            initially_connected_server = Some(server_index);
            if !reg_response.server_version.is_empty() {
                app_state
                    .server_info_collection
                    .set_server_version(server_index as u32, reg_response.server_version);
            }
            addr
        };

        // Start data handling tasks for all servers
        for (index, turn_manager) in ctx.server_managers.drain(..).enumerate() {
            let handler_config = Box::new(InboundHandlerConfig {
                network_route: NetworkRoute::new(
                    app_state.network.clone(),
                    ctx.subnet_external_route.clone(),
                ),
                ip_update: ctx.ip_update.clone(),
                server_info: app_state.server_info_collection.clone(),
                nat_info: app_state.nat_info.clone(),
                peer_map: app_state.peer_map.clone(),
                punch_backoff: app_state.punch_backoff.clone(),
                puncher: ctx.puncher.clone(),
                punch_model: ctx.punch_model.clone(),
                packet_crypto: ctx.packet_crypto.clone(),
                packet_compression: ctx.packet_compression.clone(),
                enhanced_inbound: ctx.enhanced_inbound.clone(),
                fec_decoder: ctx.fec_decoder.clone(),
                turn: ctx.turn.clone(),
                auto_sync_subnet: ctx.auto_sync_subnet,
                allow_ikev2: ctx.allow_ikev2,
                allow_wireguard: ctx.allow_wireguard,
                relay_subnets: ctx.relay_subnets.clone(),
                basic_outbound: ctx.basic_outbound.clone(),
                node_identity: ctx.node_identity.clone(),
            });
            turn_manager.data_handle_task(
                task_group,
                handler_config,
                initially_connected_server == Some(index),
            );
        }

        Ok(RegisterResponse::Success(network_addr))
    }

    pub fn device_mode(&self) -> DeviceMode {
        self.config.device_mode
    }

    pub async fn start_device(&mut self) -> anyhow::Result<()> {
        if self.tun_receiver.is_none() || self.enhanced_outbound.is_none() {
            bail!("start_device requires tun/tap mode and can only be called once");
        }
        let mut config = DeviceConfig::default();
        config = config
            .set_device_mode(self.config.device_mode)
            .set_mtu(self.config.mtu.unwrap_or(DEFAULT_MTU));
        if self.config.device_mode == DeviceMode::Tap {
            let net = self
                .app_state
                .get_network()
                .context("network is not registered")?;
            config = config.set_mac_addr(crate::ethernet::mac_from_ip(net.ip).octets());
        }
        if let Some(tun_name) = self.config.tun_name.clone() {
            config = config.set_tun_name(tun_name);
        }
        // 失败时 tun_receiver/enhanced_outbound 不会被消耗，可以重试
        self.device_io_manager
            .start_task(config, &mut self.tun_receiver, &mut self.enhanced_outbound)
            .await
    }
    #[cfg(unix)]
    pub async fn start_device_fd(&mut self, tun_fd: Option<i32>) -> anyhow::Result<()> {
        if self.tun_receiver.is_none() || self.enhanced_outbound.is_none() {
            bail!("start_device_fd requires tun/tap mode and can only be called once");
        }
        let mut config = DeviceConfig::default()
            .set_device_mode(self.config.device_mode)
            .set_mtu(self.config.mtu.unwrap_or(DEFAULT_MTU));
        if self.config.device_mode == DeviceMode::Tap {
            let net = self
                .app_state
                .get_network()
                .context("network is not registered")?;
            config = config.set_mac_addr(crate::ethernet::mac_from_ip(net.ip).octets());
        }
        if let Some(tun_fd) = tun_fd {
            config = config.set_tun_fd(tun_fd);
        }
        if let Some(tun_name) = self.config.tun_name.clone() {
            config = config.set_tun_name(tun_name);
        }
        self.device_io_manager
            .start_task(config, &mut self.tun_receiver, &mut self.enhanced_outbound)
            .await
    }
    #[cfg(not(target_os = "android"))]
    pub async fn set_device_network_ip(&self, ip: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        // 服务端数据处理任务早于虚拟网卡初始化启动。若此间已经收到 UpdateIp，
        // 必须以共享状态中的最新地址为准，不能再用最初注册响应覆盖新地址。
        let (ip, prefix_len) = self
            .app_state
            .get_network()
            .map(|network| (network.ip, network.prefix_len))
            .unwrap_or((ip, prefix_len));
        self.device_io_manager.set_network(ip, prefix_len).await?;
        #[cfg(not(any(target_os = "ios", target_os = "tvos")))]
        if !self
            .system_routes_started
            .load(std::sync::atomic::Ordering::Acquire)
        {
            let if_index = self.device_if_index().await?;
            if self
                .system_routes_started
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
            {
                crate::system_subnet_routes::start(
                    &self.task_group,
                    self.app_state.subnet_route.subscribe(),
                    if_index,
                );
            }
        }
        // 网卡设置成功（应用 IP）后触发事件脚本
        if let Some(network) = self.app_state.get_network() {
            let server = self
                .config
                .server_addr
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
                .join(",");
            self.event_script
                .notify(
                    EventScriptType::NetCardCreated,
                    &[
                        ("ip", network.ip.to_string()),
                        ("prefix-length", network.prefix_len.to_string()),
                        (
                            "gateway",
                            network
                                .gateway
                                .map(|gateway| gateway.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                        ),
                        ("broadcast", network.broadcast.to_string()),
                        ("server", server),
                    ],
                )
                .await;
        }
        Ok(())
    }

    #[cfg(target_os = "android")]
    pub fn set_android_ip_update_callback(
        &self,
        callback: crate::tunnel_core::server::inbound::AndroidIpUpdateCallback,
    ) {
        self.ip_update.set_android_callback(callback);
    }

    #[cfg(target_os = "android")]
    pub fn set_android_subnet_route_callback(&self, callback: AndroidSubnetRouteCallback) {
        if !self.config.auto_sync_subnet {
            return;
        }
        let mut routes = self.app_state.subnet_route.subscribe();
        self.task_group.spawn(async move {
            loop {
                if routes.changed().await.is_err() {
                    break;
                }
                let snapshot = routes.borrow_and_update().clone();
                if let Err(error) = callback(snapshot) {
                    log::warn!("通知 Android 子网路由变化失败: {error:#}");
                }
            }
        });
    }

    #[cfg(target_os = "android")]
    pub async fn prepare_android_ip_update(
        &self,
        request_id: u64,
        ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
        self.ip_update.prepare_android_update(request_id, ip).await
    }

    #[cfg(target_os = "android")]
    pub async fn complete_android_ip_update(
        &self,
        request_id: u64,
        ip: Ipv4Addr,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> anyhow::Result<()> {
        self.ip_update
            .complete_android_update(request_id, ip, tun_fd)
            .await
    }

    #[cfg(target_os = "android")]
    pub async fn prepare_android_route_update(&self) -> anyhow::Result<()> {
        self.ip_update.prepare_android_route_update().await
    }

    #[cfg(target_os = "android")]
    pub async fn complete_android_route_update(
        &self,
        tun_fd: std::os::fd::OwnedFd,
    ) -> anyhow::Result<()> {
        self.ip_update.complete_android_route_update(tun_fd).await
    }

    fn stop_network(&mut self) {
        self.task_group.stop();
        self.app_state.stop_network();
    }
    #[cfg(not(target_os = "android"))]
    pub async fn device_if_index(&self) -> anyhow::Result<u32> {
        self.device_io_manager.device_if_index().await
    }
    pub async fn wait_all_stopped(&mut self) {
        self.task_group.wait_all_stopped().await;
    }
    pub fn vnt_api(&self) -> VntApi {
        VntApi::new(self.app_state.clone(), self.server_rpc.clone())
    }
}
impl Drop for NetworkManager {
    fn drop(&mut self) {
        self.stop_network();
    }
}

#[cfg(test)]
mod decentralized_loopback_tests {
    use super::{NetworkManager, RegisterResponse};
    use crate::context::config::{Config, DeviceMode};
    use crate::utils::task_control::{TaskGroupGuard, TaskGroupManager};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
    use std::time::Duration;

    fn reserve_loopback_ports(count: usize) -> Vec<u16> {
        let mut listeners = Vec::with_capacity(count);
        while listeners.len() < count {
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = udp.local_addr().unwrap().port();
            if let Ok(tcp) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
                listeners.push((tcp, udp));
            }
        }
        let ports = listeners
            .iter()
            .map(|(_, udp)| udp.local_addr().unwrap().port())
            .collect();
        drop(listeners);
        ports
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn four_serverless_nodes_form_a_multihop_loopback_graph() {
        let ports = reserve_loopback_ports(4);
        let peers = [ports[1], ports[2], ports[3], ports[2]];
        let mut managers = Vec::new();
        let mut guards: Vec<TaskGroupGuard> = Vec::new();

        for index in 0..4 {
            let manager = TaskGroupManager::new();
            let (task_group, guard) = manager.create_task().unwrap();
            let ip = Ipv4Addr::new(10, 26, 0, index as u8 + 2);
            let config = Config {
                network_code: "loopback-gossip-test".to_string(),
                device_id: format!("loopback-device-{index}"),
                device_name: format!("node-{}", (b'A' + index as u8) as char),
                ip: Some(format!("{ip}/24").parse().unwrap()),
                password: Some("loopback-gossip-password".to_string()),
                no_punch: true,
                device_mode: DeviceMode::No,
                tunnel_addr: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, ports[index]))],
                peer_address: vec![format!("tcp://127.0.0.1:{}", peers[index]).parse().unwrap()],
                ..Config::default()
            };
            let mut network = NetworkManager::create_network(Box::new(config), task_group)
                .await
                .unwrap();
            assert!(matches!(
                network.register().await.unwrap(),
                RegisterResponse::Success(_)
            ));
            managers.push(network);
            guards.push(guard);
        }

        // Passive graph discovery waits for the first 25-35 second periodic
        // announcement; route creation no longer triggers an immediate one.
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let a = managers[0].vnt_api();
                let d = managers[3].vnt_api();
                let a_to_d = a.find_route(&Ipv4Addr::new(10, 26, 0, 5));
                let d_to_a = d.find_route(&Ipv4Addr::new(10, 26, 0, 2));
                let a_knows_d = a
                    .gossip_node_list()
                    .iter()
                    .any(|node| node.ip == Ipv4Addr::new(10, 26, 0, 5) && node.name == "node-D");
                if a_to_d.is_some_and(|route| route.metric() == 3)
                    && d_to_a.is_some_and(|route| route.metric() == 3)
                    && a_knows_d
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "loopback graph did not converge: A={:?}, D={:?}",
                managers[0].vnt_api().route_table(),
                managers[3].vnt_api().route_table()
            )
        });

        drop(guards);
    }
}
