use crate::context::AppState;
use crate::context::config::DeviceMode;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::enhanced_tunnel::outbound::EnhancedOutbound;
use crate::ethernet::MacTable;
use crate::nat::internal_nat::{InternalNatInbound, PortMappingManager};
use crate::nat::subnet_packet::SubnetPacketMapper;
use crate::nat::{AllowSubnetExternalRoute, SubnetExternalRoute, SubnetMappingTable};
use crate::port_mapping::PortMapping;
use crate::runtime_config::{RuntimeConfigController, RuntimePolicyStore};
use crate::tun::enhanced_tun::EnhancedTunInbound;
use crate::tunnel_core::outbound::HybridOutbound;
use crate::utils::task_control::TaskGroup;
use rustp2p_core::socket::LocalInterface;

pub(crate) mod quic_over;

pub(crate) mod inbound;
pub(crate) mod outbound;

#[derive(Clone)]
pub(crate) struct TunnelConfig {
    pub mtu: u16,
    pub password: Option<String>,
    pub port_mapping: Vec<PortMapping>,
    pub device_mode: DeviceMode,
}

#[derive(Clone)]
pub(crate) struct TunnelComponents {
    pub hybrid_outbound: HybridOutbound,
    pub external_route: SubnetExternalRoute,
    pub subnet_mapping: SubnetMappingTable,
    pub subnet_packet_mapper: SubnetPacketMapper,
    pub internal_nat_inbound: Option<InternalNatInbound>,
    pub port_mapping_manager: PortMappingManager,
    pub policy: RuntimePolicyStore,
    pub runtime_config: RuntimeConfigController,
}

/// Inputs retained by the runtime controller to prepare an MTU-dependent
/// replacement without touching the stable network instance.
#[derive(Clone)]
pub(crate) struct MtuTunnelComponents {
    pub hybrid_outbound: HybridOutbound,
    pub external_route: SubnetExternalRoute,
    pub subnet_mapping: SubnetMappingTable,
    pub subnet_packet_mapper: SubnetPacketMapper,
    pub allow_subnet: AllowSubnetExternalRoute,
    pub network: crate::context::SharedNetworkAddr,
    pub no_tun: bool,
    pub default_interface: Option<LocalInterface>,
    pub port_mapping_manager: PortMappingManager,
    pub policy: RuntimePolicyStore,
    pub runtime_config: RuntimeConfigController,
}

pub(crate) struct PreparedMtuTunnel {
    pub inbound: EnhancedInbound,
    pub outbound: Option<EnhancedOutbound>,
    pub quic_client: quic_over::quic_client::QuicTunnelClient,
}

pub(crate) async fn enhanced_ipv4_tunnel(
    app_state: AppState,
    task_group: TaskGroup,
    port_mapping_root: TaskGroup,
    tun_data_sender: EnhancedTunInbound,
    config: TunnelConfig,
    components: TunnelComponents,
) -> anyhow::Result<(
    EnhancedInbound,
    Option<EnhancedOutbound>,
    quic_over::quic_client::QuicTunnelClient,
)> {
    build_enhanced_ipv4_tunnel(
        app_state,
        task_group.clone(),
        tun_data_sender,
        config,
        components,
        true,
        Some(port_mapping_root),
    )
    .await
}

async fn build_enhanced_ipv4_tunnel(
    app_state: AppState,
    task_group: TaskGroup,
    tun_data_sender: EnhancedTunInbound,
    config: TunnelConfig,
    components: TunnelComponents,
    initialize_port_mappings: bool,
    port_mapping_root: Option<TaskGroup>,
) -> anyhow::Result<(
    EnhancedInbound,
    Option<EnhancedOutbound>,
    quic_over::quic_client::QuicTunnelClient,
)> {
    let password = config.password.unwrap_or_else(|| "password".to_string());
    let tun = match &tun_data_sender {
        EnhancedTunInbound::Tun(tun) | EnhancedTunInbound::Tap(tun) => Some(tun.clone()),
        EnhancedTunInbound::Nat(_) => None,
    };
    let (inbound, outbound, quic_client) = quic_over::boot::quic_tunnel_start(
        app_state.clone(),
        task_group,
        tun,
        quic_over::boot::QuicTunnelConfig {
            mtu: config.mtu,
            password,
            port_mapping: config.port_mapping,
        },
        quic_over::boot::QuicTunnelComponents {
            hybrid_outbound: components.hybrid_outbound.clone(),
            external_route: components.external_route.clone(),
            subnet_mapping: components.subnet_mapping.clone(),
            internal_nat_manager: components.internal_nat_inbound.clone(),
            port_mapping_manager: components.port_mapping_manager,
            policy: components.policy.clone(),
            runtime_config: components.runtime_config,
        },
        initialize_port_mappings,
        port_mapping_root,
    )
    .await?;
    let mac_table = MacTable::default();
    let enhanced_inbound = EnhancedInbound::new(
        tun_data_sender,
        inbound,
        components.internal_nat_inbound,
        app_state.traffic_stats.clone(),
        config.device_mode,
        components.hybrid_outbound.clone(),
        components.subnet_mapping.clone(),
        components.subnet_packet_mapper.clone(),
        mac_table.clone(),
    );

    let enhanced_outbound = outbound.map(|outbound| {
        EnhancedOutbound::new(
            app_state.network.clone(),
            outbound,
            components.hybrid_outbound,
            components.subnet_mapping,
            components.subnet_packet_mapper,
            mac_table,
        )
    });
    Ok((enhanced_inbound, enhanced_outbound, quic_client))
}

pub(crate) async fn prepare_mtu_tunnel(
    app_state: AppState,
    task_group: TaskGroup,
    tun_data_sender: EnhancedTunInbound,
    config: TunnelConfig,
    components: MtuTunnelComponents,
) -> anyhow::Result<PreparedMtuTunnel> {
    let internal_nat_inbound = Some(
        InternalNatInbound::create(
            &task_group,
            config.mtu,
            components.hybrid_outbound.clone(),
            components.allow_subnet.clone(),
            components.network.clone(),
            components.no_tun,
            components.default_interface.clone(),
        )
        .await?,
    );
    // In no-device mode the enhanced TUN input is the internal NAT stack
    // itself, so it must follow the candidate MTU plane rather than retaining
    // the old stack through the stable dispatcher.
    let tun_data_sender = match tun_data_sender {
        EnhancedTunInbound::Nat(_) => EnhancedTunInbound::Nat(
            internal_nat_inbound
                .clone()
                .expect("internal NAT is constructed for every MTU plane"),
        ),
        other => other,
    };
    let (inbound, outbound, quic_client) = build_enhanced_ipv4_tunnel(
        app_state,
        task_group,
        tun_data_sender,
        config,
        TunnelComponents {
            hybrid_outbound: components.hybrid_outbound,
            external_route: components.external_route,
            subnet_mapping: components.subnet_mapping,
            subnet_packet_mapper: components.subnet_packet_mapper,
            internal_nat_inbound,
            port_mapping_manager: components.port_mapping_manager,
            policy: components.policy,
            runtime_config: components.runtime_config,
        },
        false,
        None,
    )
    .await?;
    Ok(PreparedMtuTunnel {
        inbound,
        outbound,
        quic_client,
    })
}
