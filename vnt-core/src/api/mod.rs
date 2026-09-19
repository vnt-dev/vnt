use crate::context::config::{Config, VirtualIp};
use crate::context::{
    AppState, NetworkAddr, PacketLossInfo, ServerNodeInfo, TrafficInfo, TunnelListenAddr,
};
use crate::core::DEFAULT_MTU;
use crate::nat::NetInput;
use crate::nat::advertised_subnets;
use crate::protocol::client_message::{NodeIdentityTemplate, SharedNodeIdentity};
use crate::protocol::control_message::{
    ClientSimpleInfo, SubscriptionConfigAck, SubscriptionConfigEnvelope,
};
use crate::runtime_config::{PortMappingReload, RuntimeConfigController};
#[cfg(not(target_os = "android"))]
use crate::tun::DeviceNetworkUpdateError;
use crate::tunnel_core::p2p::route_table::Route;
#[cfg(target_os = "android")]
use crate::tunnel_core::server::inbound::AndroidTunRebuildError;
use crate::tunnel_core::server::inbound::{IpUpdateContext, ManagedNetworkApply};
use crate::tunnel_core::server::rpc::ServerRPC;
use anyhow::Context;
use ipnet::Ipv4Net;
use rustp2p_core::nat::NatInfo;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct ApiNodeInfo {
    pub ip: Ipv4Addr,
    pub name: String,
    pub version: String,
    pub advertised_subnets: Vec<Ipv4Net>,
}

#[derive(Clone)]
pub struct VntApi {
    app_state: AppState,
    server_rpc: ServerRPC,
    ip_update: IpUpdateContext,
    node_identity: SharedNodeIdentity,
    runtime_config: RuntimeConfigController,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplyAction {
    NoChange,
    Live,
    ComponentReload,
    InstanceRestart,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ReconfigureReport {
    pub action: ApplyAction,
    pub changed_fields: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconfigureStage {
    Validate,
    Prepare,
    Commit,
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconfigureFallback {
    KeepCurrent,
    InstanceRestart,
}

#[derive(Debug, serde::Serialize)]
pub struct ReconfigureError {
    pub stage: ReconfigureStage,
    pub fallback: ReconfigureFallback,
    pub message: String,
}

impl std::fmt::Display for ReconfigureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for ReconfigureError {}

impl ReconfigureError {
    fn new(
        stage: ReconfigureStage,
        fallback: ReconfigureFallback,
        error: impl std::fmt::Display,
    ) -> Self {
        Self {
            stage,
            fallback,
            message: error.to_string(),
        }
    }
}

fn config_diff(current: &Config, candidate: &Config) -> Vec<String> {
    let mut fields = Vec::new();
    macro_rules! changed {
        ($field:ident, $name:expr) => {
            if current.$field != candidate.$field {
                fields.push($name.to_string());
            }
        };
        ($field:ident) => {
            changed!($field, stringify!($field));
        };
    }
    changed!(server_addr, "server");
    changed!(peer_address);
    changed!(turn);
    changed!(punch_model);
    changed!(cert_mode);
    changed!(device_name);
    changed!(tun_name);
    changed!(outbound_interface);
    changed!(ip);
    changed!(password);
    changed!(no_punch);
    changed!(no_broadcast);
    changed!(allow_ikev2);
    changed!(allow_wireguard);
    changed!(compress);
    changed!(rtx);
    changed!(fec);
    changed!(input);
    changed!(subnet_mapping);
    changed!(output);
    changed!(auto_sync_subnet);
    changed!(no_nat);
    changed!(device_mode);
    if current.mtu.unwrap_or(DEFAULT_MTU) != candidate.mtu.unwrap_or(DEFAULT_MTU) {
        fields.push("mtu".to_string());
    }
    changed!(port_mapping);
    changed!(allow_port_mapping, "allow_mapping");
    changed!(udp_stun);
    changed!(tcp_stun);
    changed!(tunnel_addr);
    changed!(tunnel_port);
    fields
}

fn port_mapping_update_requires_restart(
    port_mapping_changed: bool,
    ip_changed: bool,
    server_changed: bool,
    mtu_changed: bool,
    tun_name_changed: bool,
) -> bool {
    port_mapping_changed && (ip_changed || server_changed || mtu_changed || tun_name_changed)
}

impl VntApi {
    pub(crate) fn new(
        app_state: AppState,
        server_rpc: ServerRPC,
        ip_update: IpUpdateContext,
        node_identity: SharedNodeIdentity,
        runtime_config: RuntimeConfigController,
    ) -> Self {
        Self {
            app_state,
            server_rpc,
            ip_update,
            node_identity,
            runtime_config,
        }
    }

    /// Atomically applies the subset of configuration backed by live runtime
    /// controls. If any changed field needs a restart, no live mutation is
    /// performed and the caller receives `InstanceRestart`.
    pub async fn reconfigure(
        &self,
        mut candidate: Box<Config>,
    ) -> Result<ReconfigureReport, ReconfigureError> {
        let _apply_guard = self.runtime_config.lock().await;
        let current = self.app_state.get_config().ok_or_else(|| {
            ReconfigureError::new(
                ReconfigureStage::Prepare,
                ReconfigureFallback::KeepCurrent,
                "网络实例尚未运行",
            )
        })?;
        // Runtime identity belongs to the active subscription/instance. Do
        // this before validation as well, so ignored remote identity cannot
        // make an otherwise valid revision fail.
        candidate.network_code = current.network_code.clone();
        candidate.device_id = current.device_id.clone();
        candidate.managed = current.managed.clone();
        // Event scripts are process-local and deliberately excluded from
        // managed configuration. Never let a generic JNI/API candidate make
        // AppState claim that a script changed while IpUpdateContext still
        // owns the original executable.
        candidate.event_script = current.event_script.clone();
        candidate.normalize().map_err(|error| {
            ReconfigureError::new(
                ReconfigureStage::Validate,
                ReconfigureFallback::KeepCurrent,
                error,
            )
        })?;
        candidate.check().map_err(|error| {
            ReconfigureError::new(
                ReconfigureStage::Validate,
                ReconfigureFallback::KeepCurrent,
                error,
            )
        })?;
        let changed_fields = config_diff(&current, &candidate);

        if changed_fields.is_empty() {
            return Ok(ReconfigureReport {
                action: ApplyAction::NoChange,
                changed_fields,
            });
        }

        let has_restart = changed_fields
            .iter()
            .any(|field| matches!(field.as_str(), "password" | "device_mode"));
        if has_restart {
            return Ok(ReconfigureReport {
                action: ApplyAction::InstanceRestart,
                changed_fields,
            });
        }

        let has_conditional_restart = changed_fields.iter().any(|field| {
            matches!(
                field.as_str(),
                "tunnel_addr" | "tunnel_port" | "outbound_interface"
            )
        });
        if has_conditional_restart {
            return Ok(ReconfigureReport {
                action: ApplyAction::InstanceRestart,
                changed_fields,
            });
        }
        let port_mapping_changed = current.port_mapping != candidate.port_mapping;
        let ip_changed = current.ip != candidate.ip;
        let tun_name_changed = current.tun_name != candidate.tun_name;
        let server_changed = current.server_addr != candidate.server_addr
            || current.cert_mode != candidate.cert_mode;
        let mtu_changed =
            current.mtu.unwrap_or(DEFAULT_MTU) != candidate.mtu.unwrap_or(DEFAULT_MTU);
        if port_mapping_update_requires_restart(
            port_mapping_changed,
            ip_changed,
            server_changed,
            mtu_changed,
            tun_name_changed,
        ) {
            // These independently replace resources. Until their preparation
            // can be committed through one dispatcher transaction, use the
            // one-shot generation-safe restart path instead of risking a
            // partially applied revision.
            return Ok(ReconfigureReport {
                action: ApplyAction::InstanceRestart,
                changed_fields,
            });
        }
        let mut component_reload = changed_fields.iter().any(|field| {
            matches!(
                field.as_str(),
                "server"
                    | "cert_mode"
                    | "peer_address"
                    | "no_punch"
                    | "udp_stun"
                    | "tcp_stun"
                    | "port_mapping"
                    | "rtx"
                    | "no_nat"
                    | "mtu"
            )
        });

        if port_mapping_changed {
            match self
                .runtime_config
                .reload_port_mappings(&candidate.port_mapping)
                .await
            {
                Ok(PortMappingReload::Reloaded) => {}
                Ok(PortMappingReload::RestartRequired) => {
                    return Ok(ReconfigureReport {
                        action: ApplyAction::InstanceRestart,
                        changed_fields,
                    });
                }
                Err(error) => {
                    return Err(ReconfigureError::new(
                        ReconfigureStage::Prepare,
                        ReconfigureFallback::KeepCurrent,
                        error,
                    ));
                }
            }
        }

        let mut prepared_mtu = if mtu_changed {
            Some(
                self.runtime_config
                    .prepare_mtu_reload(&candidate)
                    .await
                    .map_err(|error| {
                        ReconfigureError::new(
                            ReconfigureStage::Prepare,
                            ReconfigureFallback::KeepCurrent,
                            error,
                        )
                    })?,
            )
        } else {
            None
        };

        let previous_network = self
            .app_state
            .get_network()
            .and_then(|network| VirtualIp::new(network.ip, network.prefix_len).ok());
        let mut network_applied = false;
        if ip_changed || mtu_changed || tun_name_changed {
            let target = match candidate.ip {
                Some(target) => target,
                None if !ip_changed => match previous_network {
                    Some(target) => target,
                    None => {
                        if let Some(prepared) = prepared_mtu.take() {
                            self.runtime_config.abort_mtu_reload(prepared).await;
                        }
                        return Err(ReconfigureError::new(
                            ReconfigureStage::Prepare,
                            ReconfigureFallback::KeepCurrent,
                            "客户端尚未完成网络注册",
                        ));
                    }
                },
                None => {
                    if let Some(prepared) = prepared_mtu.take() {
                        self.runtime_config.abort_mtu_reload(prepared).await;
                    }
                    return Ok(ReconfigureReport {
                        action: ApplyAction::InstanceRestart,
                        changed_fields,
                    });
                }
            };
            let network_apply = self
                .ip_update
                .apply_managed_network(
                    target,
                    candidate.mtu.unwrap_or(DEFAULT_MTU),
                    self.app_state.subnet_route.all_route(),
                    tun_name_changed.then(|| candidate.tun_name.clone()),
                )
                .await;
            let network_apply = match network_apply {
                Ok(action) => action,
                Err(error) => {
                    if let Some(prepared) = prepared_mtu.take() {
                        self.runtime_config.abort_mtu_reload(prepared).await;
                    }
                    #[cfg(not(target_os = "android"))]
                    let fallback = if error
                        .downcast_ref::<DeviceNetworkUpdateError>()
                        .is_some_and(|error| error.rollback_failed)
                    {
                        ReconfigureFallback::InstanceRestart
                    } else {
                        ReconfigureFallback::KeepCurrent
                    };
                    #[cfg(target_os = "android")]
                    let fallback = if error
                        .downcast_ref::<AndroidTunRebuildError>()
                        .is_some_and(|error| error.restart_required)
                    {
                        ReconfigureFallback::InstanceRestart
                    } else {
                        ReconfigureFallback::KeepCurrent
                    };
                    return Err(ReconfigureError::new(
                        ReconfigureStage::Commit,
                        fallback,
                        error,
                    ));
                }
            };
            if network_apply == ManagedNetworkApply::ComponentReload {
                component_reload = true;
            }
            network_applied = true;
            if ip_changed {
                self.node_identity.notify_changed();
            }
        }
        if server_changed && let Err(error) = self.runtime_config.reload_servers(&candidate).await {
            if network_applied {
                let rollback = previous_network.ok_or_else(|| {
                    ReconfigureError::new(
                        ReconfigureStage::Rollback,
                        ReconfigureFallback::InstanceRestart,
                        "cannot roll back an unavailable virtual address",
                    )
                })?;
                if let Err(rollback_error) = self
                    .ip_update
                    .apply_managed_network(
                        rollback,
                        current.mtu.unwrap_or(DEFAULT_MTU),
                        self.app_state.subnet_route.all_route(),
                        tun_name_changed.then(|| current.tun_name.clone()),
                    )
                    .await
                {
                    return Err(ReconfigureError::new(
                        ReconfigureStage::Rollback,
                        ReconfigureFallback::InstanceRestart,
                        format!(
                            "server reload failed ({error:#}) and IP rollback failed ({rollback_error:#})"
                        ),
                    ));
                }
                self.node_identity.notify_changed();
            }
            if let Some(prepared) = prepared_mtu.take() {
                self.runtime_config.abort_mtu_reload(prepared).await;
            }
            return Err(ReconfigureError::new(
                ReconfigureStage::Prepare,
                ReconfigureFallback::KeepCurrent,
                error,
            ));
        }
        if let Some(prepared) = prepared_mtu.take()
            && let Err(error) = self.runtime_config.commit_mtu_reload(prepared).await
        {
            return Err(ReconfigureError::new(
                ReconfigureStage::Commit,
                ReconfigureFallback::InstanceRestart,
                error,
            ));
        }
        if current.input != candidate.input {
            self.app_state
                .subnet_route
                .set_route_table(candidate.input.clone());
        }
        if current.device_name != candidate.device_name
            || current.output != candidate.output
            || current.subnet_mapping != candidate.subnet_mapping
        {
            self.node_identity.set(NodeIdentityTemplate {
                name: candidate.device_name.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                network_code: current.network_code.clone(),
                advertised_subnets: advertised_subnets(
                    &candidate.output,
                    &candidate.subnet_mapping,
                ),
            });
        }
        self.runtime_config.commit_policy(&candidate);
        // Managed identity and revision state are runtime-owned and cannot be
        // replaced by the parsed candidate.
        self.app_state.set_config(candidate);
        Ok(ReconfigureReport {
            action: if component_reload {
                ApplyAction::ComponentReload
            } else {
                ApplyAction::Live
            },
            changed_fields,
        })
    }
    pub fn server_rpc(&self) -> &ServerRPC {
        &self.server_rpc
    }
    /// 获取启动配置
    pub fn get_config(&self) -> Option<Box<Config>> {
        self.app_state.get_config()
    }
    /// 获取所有客户端ip
    pub fn client_ips(&self) -> Vec<ClientSimpleInfo> {
        self.app_state.client_ips()
    }
    /// 判断目标IP是否直连
    pub fn is_direct(&self, ip: &Ipv4Addr) -> bool {
        self.app_state.route_table.p2p_num(ip) > 0
    }
    /// 查找路由
    pub fn find_route(&self, ip: &Ipv4Addr) -> Option<Route> {
        self.app_state.route_table.get_route_by_id(ip).ok()
    }
    pub fn get_rtt(&self, ip: &Ipv4Addr) -> Option<u32> {
        if let Some(route) = self.find_route(ip) {
            Some(route.rtt())
        } else {
            self.server_node_rtt(ip).map(|v| v * 2)
        }
    }
    /// 获取所有路由
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.app_state.route_table.route_table()
    }
    /// Returns identities learned from direct handshakes and Gossip
    /// announcements. Entries disappear with their last route.
    pub fn gossip_node_list(&self) -> Vec<ApiNodeInfo> {
        self.app_state
            .node_info_map
            .list()
            .into_iter()
            .map(|node| ApiNodeInfo {
                ip: node.ip,
                name: node.name,
                version: node.version,
                advertised_subnets: node.advertised_subnets,
            })
            .collect()
    }
    /// 获取服务器自动同步得到的子网路由
    pub fn automatic_subnet_routes(&self) -> Vec<NetInput> {
        self.app_state.subnet_route.automatic_routes()
    }
    /// 获取服务器节点
    pub fn server_node_list(&self) -> Vec<ServerNodeInfo> {
        self.app_state.server_info_collection.server_node_list()
    }
    pub fn server_node_rtt(&self, ip: &Ipv4Addr) -> Option<u32> {
        self.app_state.server_info_collection.get_server_rtt(ip)
    }
    /// 获取网络配置
    pub fn network(&self) -> Option<NetworkAddr> {
        self.app_state.get_network()
    }
    /// 获取当前的nat信息
    pub fn nat_info(&self) -> Option<NatInfo> {
        self.app_state.get_nat_info()
    }
    /// Returns the P2P TCP/UDP sockets that are actually bound by this instance.
    pub fn p2p_listen_addrs(&self) -> Vec<TunnelListenAddr> {
        self.app_state.p2p_listen_addrs()
    }
    /// Drain configuration updates pushed by the management server. The outer
    /// application owns validation, atomic persistence, rollback and restart.
    pub fn take_subscription_config_updates(&self) -> Vec<SubscriptionConfigEnvelope> {
        self.app_state.take_subscription_config_updates()
    }

    /// Wait for the next managed configuration update without polling.
    pub async fn next_subscription_config_updates(
        &self,
    ) -> Option<Vec<SubscriptionConfigEnvelope>> {
        self.app_state.next_subscription_config_updates().await
    }

    /// Advances the locally reported managed revision without sending an ACK.
    /// Hosts use this after a fetched configuration has successfully completed
    /// initial startup: the next registration must describe the running state,
    /// while startup itself is not a configuration-application acknowledgement.
    pub fn mark_subscription_applied_locally(&self, revision: u64) -> anyhow::Result<()> {
        let config = self
            .app_state
            .get_config()
            .context("Network instance is not running")?;
        let managed = config
            .managed
            .as_ref()
            .context("Network instance is not subscription-managed")?;
        managed.mark_applied(revision);
        Ok(())
    }

    pub async fn acknowledge_subscription_config(
        &self,
        ack: SubscriptionConfigAck,
    ) -> anyhow::Result<usize> {
        let revision = ack.revision;
        let applied = ack.status
            == crate::protocol::control_message::SubscriptionConfigApplyStatus::SubscriptionConfigApplied;
        if applied
            && let Some(config) = self.app_state.get_config()
            && let Some(managed) = &config.managed
        {
            // The registration revision represents local committed state, not
            // ACK delivery. Advance it before best-effort network reporting so
            // reconnect catch-up never advertises an older revision.
            managed.mark_applied(revision);
        }
        let sent = self.server_rpc.acknowledge_subscription_config(ack).await?;
        Ok(sent)
    }
    pub fn has_verified_config_server(&self) -> bool {
        self.server_rpc.has_verified_config_server()
    }
    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.app_state.get_peer_info(ip).and_then(|v| v.nat_info)
    }
    /// 获取指定 IP 的聚合丢包信息（所有路由合并）
    pub fn packet_loss_info(&self, ip: &Ipv4Addr) -> Option<PacketLossInfo> {
        self.app_state
            .packet_loss_stats
            .get_aggregated_loss_info(ip)
    }
    /// 获取指定 IP 的所有路由的丢包信息
    pub fn packet_loss_info_by_routes(&self, ip: &Ipv4Addr) -> Vec<PacketLossInfo> {
        self.app_state.packet_loss_stats.get_loss_info_by_ip(ip)
    }
    pub fn all_packet_loss_info(&self) -> Vec<PacketLossInfo> {
        self.app_state.packet_loss_stats.get_all_loss_info()
    }
    pub fn reset_packet_loss(&self, ip: &Ipv4Addr) {
        // 重置该 IP 的所有路由统计
        for info in self.app_state.packet_loss_stats.get_loss_info_by_ip(ip) {
            if let Some(route_key) = info.route_key {
                self.app_state.packet_loss_stats.reset(ip, &route_key);
            }
        }
    }
    pub fn reset_all_packet_loss(&self) {
        self.app_state.packet_loss_stats.reset_all()
    }
    pub fn traffic_info(&self, ip: &Ipv4Addr) -> Option<TrafficInfo> {
        self.app_state.traffic_stats.get_traffic_info(ip)
    }
    pub fn all_traffic_info(&self) -> Vec<TrafficInfo> {
        self.app_state.traffic_stats.get_all_traffic_info()
    }
    pub fn reset_traffic(&self, ip: &Ipv4Addr) {
        self.app_state.traffic_stats.reset(ip)
    }
    pub fn reset_all_traffic(&self) {
        self.app_state.traffic_stats.reset_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_diff_is_stable_and_ignores_identity() {
        let current = Config {
            network_code: "network-a".into(),
            device_id: "device-a".into(),
            ..Default::default()
        };
        let mut candidate = current.clone();
        candidate.network_code = "forged-network".into();
        candidate.device_id = "forged-device".into();
        candidate.device_name = "new-name".into();
        candidate.no_nat = true;
        candidate.allow_port_mapping = true;

        assert_eq!(
            config_diff(&current, &candidate),
            vec!["device_name", "no_nat", "allow_mapping"]
        );
    }

    #[test]
    fn implicit_and_explicit_default_mtu_are_semantically_equal() {
        let current = Config::default();
        let mut explicit_default = current.clone();
        explicit_default.mtu = Some(DEFAULT_MTU);
        assert!(
            !config_diff(&current, &explicit_default)
                .iter()
                .any(|field| field == "mtu")
        );

        explicit_default.mtu = Some(DEFAULT_MTU - 1);
        assert!(
            config_diff(&current, &explicit_default)
                .iter()
                .any(|field| field == "mtu")
        );
    }

    #[test]
    fn port_mapping_and_tun_name_combination_requires_instance_restart() {
        assert!(!port_mapping_update_requires_restart(
            true, false, false, false, false
        ));
        assert!(!port_mapping_update_requires_restart(
            false, false, false, false, true
        ));
        assert!(port_mapping_update_requires_restart(
            true, false, false, false, true
        ));
    }

    #[test]
    fn reconfigure_reports_have_protocol_stable_names() {
        let report = ReconfigureReport {
            action: ApplyAction::ComponentReload,
            changed_fields: vec!["server".into()],
        };
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            serde_json::json!({
                "action": "COMPONENT_RELOAD",
                "changed_fields": ["server"]
            })
        );
    }
}
