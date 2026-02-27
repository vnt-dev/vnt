use crate::api::VntApi;
use crate::compression::PacketCompression;
use crate::context::config::Config;
use crate::context::{AppState, NetworkAddr, NetworkRoute};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::enhanced_ipv4_tunnel;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::enhanced_tunnel::outbound::EnhancedOutbound;
use crate::fec::{FecDecoder, FecEncoder};
use crate::nat::internal_nat::{InternalNatInbound, PortMappingManager};
use crate::nat::{AllowSubnetExternalRoute, SubnetExternalRoute};
use crate::protocol::control_message::ErrorResponseMsg;
use crate::tun::enhanced_tun::EnhancedTunInbound;
use crate::tun::{DeviceConfig, DeviceIOManager, TunDataInbound, TunReceiver, tun_channel};
use crate::tunnel_core::outbound::{BasicOutbound, HybridOutbound};
use crate::tunnel_core::p2p::inbound::{P2pInboundConfig, P2pInboundHandler};
use crate::tunnel_core::p2p::transport::punch::NatPuncher;
use crate::tunnel_core::p2p::transport::task::init_tunnel;
use crate::tunnel_core::server::connection_manager::{
    InboundHandlerConfig, ServerTurnManager, coordinated_registration, create_server_tunnel,
};
use crate::tunnel_core::server::rpc::ServerRPC;
use crate::utils::task_control::TaskGroup;
use anyhow::bail;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

pub const DEFAULT_MTU: u16 = 1380;

/// Context for deferred registration
struct RegistrationContext {
    server_managers: Vec<ServerTurnManager>,
    subnet_external_route: SubnetExternalRoute,
    puncher: NatPuncher,
    packet_crypto: PacketCrypto,
    packet_compression: PacketCompression,
    enhanced_inbound: EnhancedInbound,
    fec_decoder: FecDecoder,
}

pub struct NetworkManager {
    config: Box<Config>,
    app_state: AppState,
    task_group: TaskGroup,
    device_io_manager: DeviceIOManager,
    enhanced_outbound: Option<EnhancedOutbound>,
    server_rpc: ServerRPC,
    tun_receiver: Option<TunReceiver>,
    registration_context: Option<Box<RegistrationContext>>,
}
pub enum RegisterResponse {
    Success(NetworkAddr),
    Failed(ErrorResponseMsg),
}

impl NetworkManager {
    pub async fn create_network(
        config: Box<Config>,
        task_group: TaskGroup,
    ) -> anyhow::Result<NetworkManager> {
        let app_state = AppState::default();
        config.check()?;
        let mtu = config.mtu.unwrap_or(DEFAULT_MTU);
        let packet_crypto = PacketCrypto::new_from_str(config.password.as_deref());
        let packet_compression = PacketCompression::new(config.compress);
        let (server_manager_list, tunnel_to_server, server_rpc) =
            create_server_tunnel(app_state.clone(), &config, packet_crypto.clone());
        let device_io_manager = DeviceIOManager::new(task_group.clone());
        let allow_subnet = AllowSubnetExternalRoute::new(config.output.clone());

        let (puncher, p2p_socket, p2p_task) = if !config.no_punch {
            let (puncher, p2p_socket_manager, p2p_task) = init_tunnel(
                task_group.clone(),
                app_state.clone(),
                tunnel_to_server.clone(),
                packet_crypto.clone(),
                config.tunnel_port,
            )
            .await?;

            (Some(puncher), Some(p2p_socket_manager), Some(p2p_task))
        } else {
            (None, None, None)
        };
        let puncher = NatPuncher::new(
            app_state.network.clone(),
            app_state.punch_backoff.clone(),
            puncher,
            packet_crypto.clone(),
        );
        let subnet_external_route = app_state.subnet_route.clone();
        subnet_external_route.set_route_table(config.input.clone());

        let fec_decoder = FecDecoder::new();
        let basic_outbound = BasicOutbound::new(
            tunnel_to_server.clone(),
            p2p_socket.clone(),
            packet_crypto.clone(),
        );
        let fec_encoder = if config.fec {
            Some(FecEncoder::new(&task_group, basic_outbound.clone()))
        } else {
            None
        };

        let hybrid_outbound = HybridOutbound::new(
            app_state.network.clone(),
            app_state.server_info_collection.clone(),
            app_state.traffic_stats.clone(),
            basic_outbound,
            packet_compression.clone(),
            subnet_external_route.clone(),
            fec_encoder,
        );
        let port_mapping_manager = PortMappingManager::new(
            config.no_tun,
            config.allow_port_mapping,
            app_state.network.clone(),
        );
        let internal_nat_inbound = if config.no_nat && !config.no_tun {
            None
        } else {
            let nat_inbound = InternalNatInbound::create(
                &task_group,
                mtu,
                hybrid_outbound.clone(),
                allow_subnet.clone(),
                app_state.network.clone(),
                config.no_tun,
            )
            .await?;
            Some(nat_inbound)
        };

        let (enhanced_tun_inbound, tun_receiver) = if config.no_tun {
            (
                EnhancedTunInbound::Nat(
                    internal_nat_inbound
                        .clone()
                        .expect("internal_nat_inbound must be Some when no_tun is true"),
                ),
                None,
            )
        } else {
            let (tun_inbound, tun_receiver) = tun_channel();
            let tun_data_sender = TunDataInbound::new(tun_inbound, allow_subnet.clone());
            (EnhancedTunInbound::Tun(tun_data_sender), Some(tun_receiver))
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
            },
            crate::enhanced_tunnel::TunnelComponents {
                hybrid_outbound: hybrid_outbound.clone(),
                external_route: subnet_external_route.clone(),
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
            });
            p2p_task.start(handler);
        }

        let registration_context = Box::new(RegistrationContext {
            server_managers: server_manager_list,
            subnet_external_route,
            puncher,
            packet_crypto,
            packet_compression,
            enhanced_inbound,
            fec_decoder,
        });

        app_state.set_config(config.clone());
        Ok(Self {
            config,
            app_state,
            task_group,
            device_io_manager,
            enhanced_outbound,
            server_rpc,
            tun_receiver,
            registration_context: Some(registration_context),
        })
    }

    /// Register with server(s) and start data handling tasks.
    /// This method can only be called once.
    /// Returns the registration response on success.
    pub async fn register(&mut self) -> anyhow::Result<RegisterResponse> {
        let Some(mut ctx) = self.registration_context.take() else {
            bail!("register can only be called once");
        };

        let is_multi_server = ctx.server_managers.len() > 1;

        let response = if is_multi_server {
            // Multi-server: coordinated pre-registration
            log::info!(
                "Multi-server mode: performing coordinated registration for {} servers",
                ctx.server_managers.len()
            );
            coordinated_registration(&mut ctx.server_managers).await?
        } else {
            // Single-server: normal registration
            log::info!("Single-server mode: performing normal registration");
            ctx.server_managers[0]
                .connect_and_reg(crate::protocol::control_message::RegistrationMode::Normal)
                .await?
        };
        let reg_response = match response {
            crate::protocol::control_message::ResponseMessage::Reg(reg) => {
                log::info!(
                    "Registration completed, IP: {}, prefix_len: {}",
                    reg.ip,
                    reg.prefix_len
                );
                reg
            }
            crate::protocol::control_message::ResponseMessage::Error(e) => {
                return Ok(RegisterResponse::Failed(e));
            }
            crate::protocol::control_message::ResponseMessage::ConfirmReg(_) => {
                bail!("Unexpected ConfirmReg response");
            }
        };
        let network_addr = NetworkAddr {
            gateway: reg_response.gateway,
            broadcast: Ipv4Net::new(reg_response.ip, reg_response.prefix_len)?.broadcast(),
            ip: reg_response.ip,
            prefix_len: reg_response.prefix_len,
        };
        self.app_state.network.set(network_addr);

        // 保存服务器版本信息
        if !reg_response.server_version.is_empty() {
            for (index, _) in ctx.server_managers.iter().enumerate() {
                self.app_state
                    .server_info_collection
                    .set_server_version(index as u32, reg_response.server_version.clone());
            }
        }

        // Start data handling tasks for all servers
        for turn_manager in ctx.server_managers {
            let handler_config = Box::new(InboundHandlerConfig {
                network_route: NetworkRoute::new(
                    self.app_state.network.clone(),
                    ctx.subnet_external_route.clone(),
                ),
                server_info: self.app_state.server_info_collection.clone(),
                nat_info: self.app_state.nat_info.clone(),
                peer_map: self.app_state.peer_map.clone(),
                punch_backoff: self.app_state.punch_backoff.clone(),
                puncher: ctx.puncher.clone(),
                packet_crypto: ctx.packet_crypto.clone(),
                packet_compression: ctx.packet_compression.clone(),
                enhanced_inbound: ctx.enhanced_inbound.clone(),
                fec_decoder: ctx.fec_decoder.clone(),
            });
            turn_manager.data_handle_task_connected(&self.task_group, handler_config, network_addr);
        }

        Ok(RegisterResponse::Success(network_addr))
    }

    pub fn is_no_tun(&self) -> bool {
        self.config.no_tun
    }

    pub async fn start_tun(&mut self) -> anyhow::Result<()> {
        let Some(receiver) = self.tun_receiver.take() else {
            bail!("start_tun can only be called once");
        };
        let Some(enhanced_outbound) = self.enhanced_outbound.take() else {
            bail!("start_tun can only be called once");
        };
        let mut config = DeviceConfig::default();
        config = config.set_mtu(self.config.mtu.unwrap_or(DEFAULT_MTU));
        if let Some(tun_name) = self.config.tun_name.clone() {
            config = config.set_tun_name(tun_name);
        }
        self.device_io_manager
            .start_task(config, receiver, enhanced_outbound)
            .await
    }
    #[cfg(unix)]
    pub async fn start_tun_fd(&mut self, tun_fd: Option<i32>) -> anyhow::Result<()> {
        let Some(receiver) = self.tun_receiver.take() else {
            bail!("start_tun_fd can only be called once");
        };
        let Some(enhanced_outbound) = self.enhanced_outbound.take() else {
            bail!("start_tun_fd can only be called once");
        };
        let mut config = DeviceConfig::default();
        if let Some(tun_fd) = tun_fd {
            config = config.set_tun_fd(tun_fd);
        }
        if let Some(tun_name) = self.config.tun_name.clone() {
            config = config.set_tun_name(tun_name);
        }
        self.device_io_manager
            .start_task(config, receiver, enhanced_outbound)
            .await
    }
    #[cfg(not(target_os = "android"))]
    pub async fn set_tun_network_ip(&self, ip: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        self.device_io_manager.set_network(ip, prefix_len).await?;
        Ok(())
    }

    fn stop_network(&mut self) {
        self.task_group.stop();
        self.app_state.stop_network();
    }
    #[cfg(not(target_os = "android"))]
    pub async fn tun_if_index(&self) -> anyhow::Result<u32> {
        self.device_io_manager.tun_if_index().await
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
