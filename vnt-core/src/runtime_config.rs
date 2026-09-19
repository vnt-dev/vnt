use crate::compression::PacketCompression;
use crate::context::config::{Config, PeerAddress, PunchRule, TurnRule};
use crate::context::{AppState, NetworkRoute, ServerInfoCollection};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::enhanced_tunnel::outbound::EnhancedOutbound;
use crate::enhanced_tunnel::quic_over::quic_client::QuicTunnelClient;
use crate::enhanced_tunnel::{
    MtuTunnelComponents, PreparedMtuTunnel, TunnelConfig, prepare_mtu_tunnel,
};
use crate::fec::FecDecoder;
use crate::fec::FecEncoder;
use crate::nat::{AllowSubnetExternalRoute, SubnetMappingTable, advertised_subnets};
use crate::port_mapping::{PortMapping, port_mapping_start};
use crate::protocol::client_message::SharedNodeIdentity;
use crate::protocol::control_message::{RegResponseMsg, ResponseMessage};
use crate::tunnel_core::outbound::BasicOutbound;
use crate::tunnel_core::p2p::transport::punch::NatPuncher;
use crate::tunnel_core::server::connection_manager::{
    InboundHandlerConfig, create_server_tunnel_with_registration_ip, register_with_first_available,
    server_addresses,
};
use crate::tunnel_core::server::outbound::ServerOutbound;
use crate::tunnel_core::server::rpc::ServerRPC;
use crate::tunnel_core::server::transport::config::SharedRegistrationIp;
use crate::utils::task_control::TaskGroup;
use arc_swap::ArcSwap;
use rustp2p_core::socket::LocalInterface;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

/// Immutable packet-processing policy. Each packet handler loads this once so
/// one packet cannot observe fields from two managed configuration revisions.
#[derive(Clone)]
pub(crate) struct RuntimePolicy {
    pub turn: Arc<Vec<TurnRule>>,
    pub punch_model: Arc<Vec<PunchRule>>,
    pub peer_address: Arc<Vec<PeerAddress>>,
    pub packet_compression: PacketCompression,
    pub subnet_mapping: SubnetMappingTable,
    pub relay_subnets: AllowSubnetExternalRoute,
    pub fec_encoder: Option<FecEncoder>,
    pub auto_sync_subnet: bool,
    pub no_broadcast: bool,
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub allow_mapping: bool,
    pub no_punch: bool,
    pub no_nat: bool,
    pub rtx: bool,
    pub udp_stun: Arc<Vec<String>>,
    pub tcp_stun: Arc<Vec<String>>,
}

impl RuntimePolicy {
    pub fn from_config_with_handles(
        config: &Config,
        fec_encoder: Option<FecEncoder>,
        subnet_mapping: SubnetMappingTable,
        _allow_subnet: AllowSubnetExternalRoute,
        relay_subnets: AllowSubnetExternalRoute,
    ) -> Self {
        Self {
            turn: Arc::new(config.turn.clone()),
            punch_model: Arc::new(config.punch_model.clone()),
            peer_address: Arc::new(config.peer_address.clone()),
            packet_compression: PacketCompression::new(config.compress),
            subnet_mapping,
            relay_subnets,
            fec_encoder,
            auto_sync_subnet: config.auto_sync_subnet,
            no_broadcast: config.no_broadcast,
            allow_ikev2: config.allow_ikev2,
            allow_wireguard: config.allow_wireguard,
            allow_mapping: config.allow_port_mapping,
            no_punch: config.no_punch,
            no_nat: config.no_nat,
            rtx: config.rtx,
            udp_stun: Arc::new(config.udp_stun.clone()),
            tcp_stun: Arc::new(config.tcp_stun.clone()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RuntimePolicyStore {
    policy: Arc<ArcSwap<RuntimePolicy>>,
    peer_revision: Arc<tokio::sync::watch::Sender<u64>>,
    stun_revision: Arc<tokio::sync::watch::Sender<u64>>,
    punch_revision: Arc<tokio::sync::watch::Sender<u64>>,
}

impl RuntimePolicyStore {
    pub fn new(policy: RuntimePolicy) -> Self {
        let (peer_revision, _) = tokio::sync::watch::channel(0);
        let (stun_revision, _) = tokio::sync::watch::channel(0);
        let (punch_revision, _) = tokio::sync::watch::channel(0);
        Self {
            policy: Arc::new(ArcSwap::from_pointee(policy)),
            peer_revision: Arc::new(peer_revision),
            stun_revision: Arc::new(stun_revision),
            punch_revision: Arc::new(punch_revision),
        }
    }

    #[inline]
    pub fn load(&self) -> arc_swap::Guard<Arc<RuntimePolicy>> {
        self.policy.load()
    }

    pub fn store(&self, policy: RuntimePolicy) {
        let current = self.policy.load();
        let peer_changed = current.peer_address != policy.peer_address;
        let stun_changed =
            current.udp_stun != policy.udp_stun || current.tcp_stun != policy.tcp_stun;
        let punch_changed = current.no_punch != policy.no_punch;
        drop(current);
        self.policy.store(Arc::new(policy));
        if peer_changed {
            self.peer_revision
                .send_modify(|revision| *revision = revision.wrapping_add(1));
        }
        if stun_changed {
            self.stun_revision
                .send_modify(|revision| *revision = revision.wrapping_add(1));
        }
        if punch_changed {
            self.punch_revision
                .send_modify(|revision| *revision = revision.wrapping_add(1));
        }
    }

    pub fn subscribe_peer(&self) -> tokio::sync::watch::Receiver<u64> {
        self.peer_revision.subscribe()
    }

    pub fn subscribe_stun(&self) -> tokio::sync::watch::Receiver<u64> {
        self.stun_revision.subscribe()
    }

    pub fn subscribe_punch(&self) -> tokio::sync::watch::Receiver<u64> {
        self.punch_revision.subscribe()
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeConfigController {
    policy: RuntimePolicyStore,
    fec_encoder: FecEncoder,
    subnet_mapping: SubnetMappingTable,
    allow_subnet: AllowSubnetExternalRoute,
    relay_subnets: AllowSubnetExternalRoute,
    apply_lock: Arc<tokio::sync::Mutex<()>>,
    server_components: Arc<OnceLock<ServerComponentController>>,
    port_mapping_components: Arc<OnceLock<PortMappingComponentController>>,
    mtu_components: Arc<OnceLock<MtuComponentController>>,
}

#[derive(Clone)]
pub(crate) struct ServerComponentController {
    pub app_state: AppState,
    pub root_task_group: TaskGroup,
    pub active_scope: Arc<tokio::sync::Mutex<TaskGroup>>,
    pub registration_ip: SharedRegistrationIp,
    pub default_interface: Option<LocalInterface>,
    pub identity: SharedNodeIdentity,
    pub packet_crypto: PacketCrypto,
    pub external_route: crate::nat::SubnetExternalRoute,
    pub client_instance_id: Arc<Vec<u8>>,
    pub puncher: NatPuncher,
    pub enhanced_inbound: EnhancedInbound,
    pub fec_decoder: FecDecoder,
    pub basic_outbound: BasicOutbound,
    pub server_outbound: ServerOutbound,
    pub server_rpc: ServerRPC,
}

#[derive(Clone)]
pub(crate) struct PortMappingComponentController {
    pub root_task_group: TaskGroup,
    pub active: Arc<tokio::sync::Mutex<Vec<(PortMapping, TaskGroup)>>>,
    pub quic_client: QuicTunnelClient,
}

#[derive(Clone)]
pub(crate) struct MtuComponentController {
    pub app_state: AppState,
    pub root_task_group: TaskGroup,
    pub active_scope: Arc<tokio::sync::Mutex<TaskGroup>>,
    pub tun_data_inbound: crate::tun::enhanced_tun::EnhancedTunInbound,
    pub components: MtuTunnelComponents,
    pub enhanced_inbound: EnhancedInbound,
    pub enhanced_outbound: Option<EnhancedOutbound>,
    pub quic_client: QuicTunnelClient,
}

pub(crate) struct PreparedMtuReload {
    scope: TaskGroup,
    plane: PreparedMtuTunnel,
}

pub(crate) enum PortMappingReload {
    Reloaded,
    RestartRequired,
}

/// Restore metadata obtained during the registration that proved a replacement
/// server set is usable. `update_server` intentionally replaces all entries,
/// so this must run after it for the already-connected manager, which does not
/// register again when its data task starts.
fn restore_initial_server_metadata(
    server_info: &ServerInfoCollection,
    server_index: usize,
    registration: &RegResponseMsg,
) {
    let server_id = server_index as u32;
    if !registration.server_version.is_empty() {
        server_info.set_server_version(server_id, registration.server_version.clone());
    }
    server_info.set_server_identity(
        server_id,
        registration.server_instance_id.clone(),
        registration.multi_link_supported,
    );
}

impl RuntimeConfigController {
    pub fn new(
        policy: RuntimePolicyStore,
        fec_encoder: FecEncoder,
        subnet_mapping: SubnetMappingTable,
        allow_subnet: AllowSubnetExternalRoute,
        relay_subnets: AllowSubnetExternalRoute,
    ) -> Self {
        Self {
            policy,
            fec_encoder,
            subnet_mapping,
            allow_subnet,
            relay_subnets,
            apply_lock: Arc::new(tokio::sync::Mutex::new(())),
            server_components: Arc::new(OnceLock::new()),
            port_mapping_components: Arc::new(OnceLock::new()),
            mtu_components: Arc::new(OnceLock::new()),
        }
    }

    pub fn attach_port_mapping_components(&self, components: PortMappingComponentController) {
        debug_assert!(self.port_mapping_components.set(components).is_ok());
    }

    pub fn attach_mtu_components(&self, components: MtuComponentController) {
        debug_assert!(self.mtu_components.set(components).is_ok());
    }

    /// Creates all MTU-fixed state in an isolated child scope. Nothing visible
    /// to packet handlers changes until `commit_mtu_reload` is called.
    pub async fn prepare_mtu_reload(&self, config: &Config) -> anyhow::Result<PreparedMtuReload> {
        let components = self
            .mtu_components
            .get()
            .ok_or_else(|| anyhow::anyhow!("MTU runtime is not ready"))?;
        let scope = components.root_task_group.child_scope();
        let result = prepare_mtu_tunnel(
            components.app_state.clone(),
            scope.clone(),
            components.tun_data_inbound.clone(),
            TunnelConfig {
                mtu: config.mtu.unwrap_or(crate::core::DEFAULT_MTU),
                password: config.password.clone(),
                port_mapping: config.port_mapping.clone(),
                device_mode: config.device_mode,
            },
            components.components.clone(),
        )
        .await;
        match result {
            Ok(plane) => Ok(PreparedMtuReload { scope, plane }),
            Err(error) => {
                scope.stop();
                scope.wait_all_stopped().await;
                Err(error)
            }
        }
    }

    pub async fn commit_mtu_reload(&self, prepared: PreparedMtuReload) -> anyhow::Result<()> {
        let components = self
            .mtu_components
            .get()
            .ok_or_else(|| anyhow::anyhow!("MTU runtime is not ready"))?;
        match (&components.enhanced_outbound, &prepared.plane.outbound) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => {
                prepared.scope.stop();
                prepared.scope.wait_all_stopped().await;
                anyhow::bail!("MTU replacement changed virtual-device mode");
            }
        }
        components
            .enhanced_inbound
            .replace_from(&prepared.plane.inbound);
        if let (Some(current), Some(candidate)) =
            (&components.enhanced_outbound, &prepared.plane.outbound)
        {
            current.replace_from(candidate);
        }
        components
            .quic_client
            .replace_from(&prepared.plane.quic_client);
        let old_scope = {
            let mut active = components.active_scope.lock().await;
            std::mem::replace(&mut *active, prepared.scope)
        };
        old_scope.stop();
        if tokio::time::timeout(Duration::from_secs(5), old_scope.wait_all_stopped())
            .await
            .is_err()
        {
            log::warn!("timed out draining previous MTU data plane after switch");
        }
        Ok(())
    }

    pub async fn abort_mtu_reload(&self, prepared: PreparedMtuReload) {
        prepared.scope.stop();
        prepared.scope.wait_all_stopped().await;
    }

    pub async fn reload_port_mappings(
        &self,
        rules: &[PortMapping],
    ) -> anyhow::Result<PortMappingReload> {
        let components = self
            .port_mapping_components
            .get()
            .ok_or_else(|| anyhow::anyhow!("port mapping runtime is not ready"))?;
        let mut active = components.active.lock().await;
        if active.iter().any(|(old, _)| {
            rules.iter().any(|new| {
                old.protocol == new.protocol && old.src_addr == new.src_addr && old != new
            })
        }) {
            return Ok(PortMappingReload::RestartRequired);
        }

        let mut prepared: Vec<(PortMapping, TaskGroup)> = Vec::new();
        for rule in rules {
            if active.iter().any(|(current, _)| current == rule) {
                continue;
            }
            let scope = components.root_task_group.child_scope();
            if let Err(error) =
                port_mapping_start(&scope, vec![rule.clone()], components.quic_client.clone()).await
            {
                scope.stop();
                scope.wait_all_stopped().await;
                for (_, prepared_scope) in prepared {
                    prepared_scope.stop();
                    prepared_scope.wait_all_stopped().await;
                }
                return Err(error);
            }
            prepared.push((rule.clone(), scope));
        }

        let mut removed = Vec::new();
        active.retain(|(current, scope)| {
            if rules.contains(current) {
                true
            } else {
                removed.push(scope.clone());
                false
            }
        });
        active.extend(prepared);
        drop(active);
        for scope in &removed {
            scope.stop();
        }
        if tokio::time::timeout(Duration::from_secs(5), async {
            for scope in removed {
                scope.wait_all_stopped().await;
            }
        })
        .await
        .is_err()
        {
            // The dispatcher has already stopped routing work to these scopes.
            // A slow task teardown must not turn a committed switch into a
            // KeepCurrent result at the API boundary.
            log::warn!("timed out draining previous port mappings after switch");
        }
        Ok(PortMappingReload::Reloaded)
    }

    pub fn attach_server_components(&self, components: ServerComponentController) {
        debug_assert!(self.server_components.set(components).is_ok());
    }

    /// Prepare a replacement server set, register it, then atomically switch
    /// the stable outbound/RPC dispatchers. The old scope is cancelled only
    /// after the replacement has proved that it can register.
    pub async fn reload_servers(&self, config: &Config) -> anyhow::Result<()> {
        let components = self
            .server_components
            .get()
            .ok_or_else(|| anyhow::anyhow!("server runtime is not ready"))?;
        let (mut managers, prepared_outbound, prepared_rpc, _) =
            create_server_tunnel_with_registration_ip(
                components.app_state.clone(),
                config,
                components.packet_crypto.clone(),
                components.default_interface.clone(),
                components.identity.clone(),
                components.client_instance_id.clone(),
                Some(components.registration_ip.clone()),
            );

        let (connected_index, response) = register_with_first_available(&mut managers).await?;
        let registration = match response {
            ResponseMessage::Reg(registration) => registration,
            ResponseMessage::Error(error) => {
                anyhow::bail!("server rejected registration: {error:?}")
            }
            _ => anyhow::bail!("unexpected server registration response"),
        };
        let current_network = components
            .app_state
            .get_network()
            .ok_or_else(|| anyhow::anyhow!("virtual network is not registered"))?;
        if registration.ip != current_network.ip
            || registration.prefix_len != current_network.prefix_len
        {
            anyhow::bail!(
                "replacement server returned another virtual network: {}/{}",
                registration.ip,
                registration.prefix_len
            );
        }

        let replacement_scope = components.root_task_group.child_scope();
        components.server_outbound.replace_from(&prepared_outbound);
        components.server_rpc.replace_from(&prepared_rpc);

        let old_scope = {
            let mut active = components.active_scope.lock().await;
            std::mem::replace(&mut *active, replacement_scope.clone())
        };
        old_scope.stop();
        if tokio::time::timeout(Duration::from_secs(5), old_scope.wait_all_stopped())
            .await
            .is_err()
        {
            // The stable dispatchers already point at the replacement. Treat
            // drain timeout as cleanup degradation, not failed reconfiguration.
            log::warn!("timed out draining previous server connections after switch");
        }

        components
            .app_state
            .server_info_collection
            .update_server(server_addresses(config));
        restore_initial_server_metadata(
            &components.app_state.server_info_collection,
            connected_index,
            &registration,
        );
        for (index, manager) in managers.drain(..).enumerate() {
            manager.data_handle_task(
                &replacement_scope,
                Box::new(InboundHandlerConfig {
                    network_route: NetworkRoute::new(
                        components.app_state.network.clone(),
                        components.external_route.clone(),
                    ),
                    server_info: components.app_state.server_info_collection.clone(),
                    nat_info: components.app_state.nat_info.clone(),
                    peer_map: components.app_state.peer_map.clone(),
                    punch_backoff: components.app_state.punch_backoff.clone(),
                    puncher: components.puncher.clone(),
                    packet_crypto: components.packet_crypto.clone(),
                    enhanced_inbound: components.enhanced_inbound.clone(),
                    fec_decoder: components.fec_decoder.clone(),
                    policy: self.policy.clone(),
                    basic_outbound: components.basic_outbound.clone(),
                    app_state: components.app_state.clone(),
                }),
                index == connected_index,
            );
        }
        Ok(())
    }

    pub fn policy_for(&self, config: &Config) -> RuntimePolicy {
        RuntimePolicy::from_config_with_handles(
            config,
            config.fec.then_some(self.fec_encoder.clone()),
            self.subnet_mapping.clone(),
            self.allow_subnet.clone(),
            self.relay_subnets.clone(),
        )
    }

    pub fn commit_policy(&self, config: &Config) {
        if !config.fec {
            self.fec_encoder.clear_pending();
        }
        self.subnet_mapping.replace(config.subnet_mapping.clone());
        self.allow_subnet.replace(config.output.clone());
        self.relay_subnets
            .replace(advertised_subnets(&config.output, &config.subnet_mapping));
        self.policy.store(self.policy_for(config));
    }

    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.apply_lock.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_core::server::transport::config::ProtocolAddress;

    #[test]
    fn reload_restores_identity_for_the_already_connected_server() {
        let server_info = ServerInfoCollection::default();
        server_info.update_server(vec![(0, ProtocolAddress::default())]);
        server_info.set_server_identity(0, vec![1; 32], true);

        // This mirrors reload_servers: rebuilding the server set deliberately
        // drops the metadata from the previous set before restoring the
        // response that made the replacement usable.
        server_info.update_server(vec![(0, ProtocolAddress::default())]);
        assert_eq!(server_info.server_instance_id(0), None);

        let registration = RegResponseMsg {
            ip: [10, 26, 0, 2].into(),
            prefix_len: 24,
            gateway: [10, 26, 0, 1].into(),
            server_version: "test".to_string(),
            subnet_sync_supported: false,
            subscription_config_supported: false,
            subscription: None,
            server_instance_id: vec![2; 32],
            multi_link_supported: true,
        };
        restore_initial_server_metadata(&server_info, 0, &registration);

        assert_eq!(server_info.server_instance_id(0), Some(vec![2; 32]));
        assert_eq!(
            server_info.server_node_list()[0].server_version.as_deref(),
            Some("test")
        );
    }
}
