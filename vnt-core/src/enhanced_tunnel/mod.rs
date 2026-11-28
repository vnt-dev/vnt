use crate::context::AppState;
use crate::context::config::DeviceMode;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::enhanced_tunnel::outbound::EnhancedOutbound;
use crate::ethernet::MacTable;
#[cfg(feature = "quic")]
use crate::nat::SubnetExternalRoute;
use crate::nat::SubnetMappingTable;
use crate::nat::internal_nat::InternalNatInbound;
#[cfg(feature = "quic")]
use crate::nat::internal_nat::PortMappingManager;
use crate::nat::subnet_packet::SubnetPacketMapper;
#[cfg(feature = "quic")]
use crate::port_mapping::PortMapping;
#[cfg(feature = "quic")]
use crate::runtime_config::RuntimePolicyStore;
use crate::tun::enhanced_tun::EnhancedTunInbound;
use crate::tunnel_core::outbound::HybridOutbound;
#[cfg(feature = "quic")]
use crate::utils::task_control::TaskGroup;

#[cfg(feature = "quic")]
pub(crate) mod quic_over;

pub(crate) mod inbound;
pub(crate) mod outbound;

#[derive(Clone)]
pub(crate) struct TunnelConfig {
    #[cfg(feature = "quic")]
    pub mtu: u16,
    #[cfg(feature = "quic")]
    pub password: Option<String>,
    #[cfg(feature = "quic")]
    pub port_mapping: Vec<PortMapping>,
    pub device_mode: DeviceMode,
}

#[derive(Clone)]
pub(crate) struct TunnelComponents {
    pub hybrid_outbound: HybridOutbound,
    #[cfg(feature = "quic")]
    pub external_route: SubnetExternalRoute,
    pub subnet_mapping: SubnetMappingTable,
    pub subnet_packet_mapper: SubnetPacketMapper,
    pub internal_nat_inbound: Option<InternalNatInbound>,
    #[cfg(feature = "quic")]
    pub port_mapping_manager: PortMappingManager,
    #[cfg(feature = "quic")]
    pub policy: RuntimePolicyStore,
}

pub(crate) async fn enhanced_ipv4_tunnel(
    app_state: AppState,
    #[cfg(feature = "quic")] task_group: TaskGroup,
    #[cfg(feature = "quic")] port_mapping_root: TaskGroup,
    tun_data_sender: EnhancedTunInbound,
    config: TunnelConfig,
    components: TunnelComponents,
) -> anyhow::Result<(EnhancedInbound, Option<EnhancedOutbound>)> {
    #[cfg(feature = "quic")]
    let tun = match &tun_data_sender {
        EnhancedTunInbound::Tun(tun) | EnhancedTunInbound::Tap(tun) => Some(tun.clone()),
        EnhancedTunInbound::Nat(_) => None,
    };
    #[cfg(feature = "quic")]
    let (quic_inbound, quic_outbound) = quic_over::boot::quic_tunnel_start(
        app_state.clone(),
        task_group,
        tun,
        quic_over::boot::QuicTunnelConfig {
            mtu: config.mtu,
            password: config.password.unwrap_or_else(|| "password".to_string()),
            port_mapping: config.port_mapping,
        },
        quic_over::boot::QuicTunnelComponents {
            hybrid_outbound: components.hybrid_outbound.clone(),
            external_route: components.external_route.clone(),
            subnet_mapping: components.subnet_mapping.clone(),
            internal_nat_manager: components.internal_nat_inbound.clone(),
            port_mapping_manager: components.port_mapping_manager,
            policy: components.policy.clone(),
        },
        port_mapping_root,
    )
    .await?;
    #[cfg(not(feature = "quic"))]
    let quic_outbound = config.device_mode.has_device().then_some(());
    let mac_table = MacTable::default();
    let enhanced_inbound = EnhancedInbound::new(
        tun_data_sender,
        #[cfg(feature = "quic")]
        quic_inbound,
        components.internal_nat_inbound,
        app_state.traffic_stats.clone(),
        config.device_mode,
        components.hybrid_outbound.clone(),
        components.subnet_mapping.clone(),
        components.subnet_packet_mapper.clone(),
        mac_table.clone(),
    );

    let enhanced_outbound = quic_outbound.map(|_outbound| {
        EnhancedOutbound::new(
            app_state.network.clone(),
            #[cfg(feature = "quic")]
            _outbound,
            components.hybrid_outbound,
            components.subnet_mapping,
            components.subnet_packet_mapper,
            mac_table,
        )
    });
    Ok((enhanced_inbound, enhanced_outbound))
}
