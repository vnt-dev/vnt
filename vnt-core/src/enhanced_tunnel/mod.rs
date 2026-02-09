use crate::context::AppState;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::enhanced_tunnel::outbound::EnhancedOutbound;
use crate::nat::SubnetExternalRoute;
use crate::nat::internal_nat::{InternalNatInbound, PortMappingManager};
use crate::port_mapping::PortMapping;
use crate::tun::enhanced_tun::EnhancedTunInbound;
use crate::tunnel_core::outbound::HybridOutbound;
use crate::utils::task_control::TaskGroup;

pub(crate) mod quic_over;

pub(crate) mod inbound;
pub(crate) mod outbound;

pub(crate) struct TunnelConfig {
    pub mtu: u16,
    pub password: Option<String>,
    pub open_quic_client: bool,
    pub port_mapping: Vec<PortMapping>,
}

pub(crate) struct TunnelComponents {
    pub hybrid_outbound: HybridOutbound,
    pub external_route: SubnetExternalRoute,
    pub internal_nat_inbound: Option<InternalNatInbound>,
    pub port_mapping_manager: PortMappingManager,
}

pub(crate) async fn enhanced_ipv4_tunnel(
    app_state: AppState,
    task_group: TaskGroup,
    tun_data_sender: EnhancedTunInbound,
    config: TunnelConfig,
    components: TunnelComponents,
) -> anyhow::Result<(EnhancedInbound, Option<EnhancedOutbound>)> {
    let password = config.password.unwrap_or_else(|| "password".to_string());
    let tun = match &tun_data_sender {
        EnhancedTunInbound::Tun(tun) => Some(tun.clone()),
        EnhancedTunInbound::Nat(_) => None,
    };
    let (inbound, outbound) = quic_over::boot::quic_tunnel_start(
        app_state.clone(),
        task_group,
        tun,
        quic_over::boot::QuicTunnelConfig {
            mtu: config.mtu,
            password,
            open_quic_client: config.open_quic_client,
            port_mapping: config.port_mapping,
        },
        quic_over::boot::QuicTunnelComponents {
            hybrid_outbound: components.hybrid_outbound.clone(),
            external_route: components.external_route,
            internal_nat_manager: components.internal_nat_inbound.clone(),
            port_mapping_manager: components.port_mapping_manager,
        },
    )
    .await?;
    let enhanced_inbound = EnhancedInbound::new(
        tun_data_sender,
        inbound,
        components.internal_nat_inbound,
        app_state.traffic_stats.clone(),
    );

    let enhanced_outbound = outbound.map(|outbound| {
        EnhancedOutbound::new(
            app_state.network.clone(),
            outbound,
            components.hybrid_outbound,
        )
    });
    Ok((enhanced_inbound, enhanced_outbound))
}
