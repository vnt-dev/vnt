use crate::context::config::Config;
use crate::context::nat::{MyNatInfo, PunchBackoff};
use crate::context::{AppState, NetworkRoute, PeerInfoMap, ServerInfoCollection};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::event_script::{EventScript, EventScriptType};
use crate::fec::FecDecoder;
use crate::protocol::client_message::SharedNodeIdentity;
use crate::protocol::control_message::{RegistrationMode, RequestMessage, ResponseMessage};
use crate::runtime_config::RuntimePolicyStore;
use crate::tunnel_core::outbound::BasicOutbound;
use crate::tunnel_core::p2p::transport::punch::NatPuncher;
use crate::tunnel_core::server::inbound::ServerTurnInboundHandler;
use crate::tunnel_core::server::outbound::ServerOutbound;
use crate::tunnel_core::server::rpc::{RpcNotifier, ServerRPC};
use crate::tunnel_core::server::transport::TransportClient;
use crate::tunnel_core::server::transport::config::{
    ConnectConfig, ConnectRegConfig, ProtocolAddress,
};
use crate::utils::task_control::{SubTask, TaskGroup};
use anyhow::bail;
use bytes::Bytes;
use futures::stream::{FuturesUnordered, Stream, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};

fn should_notify_reconnected(already_connected: bool, has_connected_once: bool) -> bool {
    !already_connected && has_connected_once
}

pub struct InboundHandlerConfig {
    pub network_route: NetworkRoute,
    pub server_info: ServerInfoCollection,
    pub nat_info: MyNatInfo,
    pub peer_map: PeerInfoMap,
    pub punch_backoff: PunchBackoff,
    pub puncher: NatPuncher,
    pub packet_crypto: PacketCrypto,
    pub enhanced_inbound: EnhancedInbound,
    pub fec_decoder: FecDecoder,
    pub policy: RuntimePolicyStore,
    pub basic_outbound: BasicOutbound,
    pub app_state: AppState,
}

pub struct ServerTurnManager {
    server_id: u32,
    config: ConnectRegConfig,
    receiver: Option<Receiver<(Bytes, Instant)>>,
    notifier: RpcNotifier,
    transport_client: TransportClient,
    event_script: EventScript,
    subnet_sync_supported: bool,
    subscription_verified: Arc<AtomicBool>,
}
pub(crate) fn create_server_tunnel(
    app_state: AppState,
    config: &Config,
    packet_crypto: PacketCrypto,
    default_interface: Option<rustp2p_core::socket::LocalInterface>,
    identity: SharedNodeIdentity,
    client_instance_id: Arc<Vec<u8>>,
) -> (Vec<ServerTurnManager>, ServerOutbound, ServerRPC) {
    let mut rpc_notifier: HashMap<u32, RpcNotifier> = HashMap::new();
    let mut sender_map: HashMap<u32, Sender<(Bytes, Instant)>> = HashMap::new();
    let mut subscription_verified_map = HashMap::new();
    let mut server_manager_list = Vec::with_capacity(config.server_addr.len());
    // 重注册声称的 IP 直接读共享网络地址：地址变更只写 app_state.network
    let network = app_state.network.clone();
    for (index, _server_addr) in config.server_addr.iter().enumerate() {
        let connect_reg_config = config.to_connect_config(
            index,
            default_interface.clone(),
            network.clone(),
            identity.clone(),
            client_instance_id.clone(),
        );

        let server_id = index as u32;

        let (s, r) = tokio::sync::mpsc::channel(1024);

        let notifier = RpcNotifier::new();
        let manager = ServerTurnManager::new(
            server_id,
            connect_reg_config.clone(),
            r,
            notifier.clone(),
            EventScript::new(config.event_script.clone()),
        );
        subscription_verified_map.insert(server_id, manager.subscription_verified.clone());
        rpc_notifier.insert(server_id, notifier);
        sender_map.insert(server_id, s);
        server_manager_list.push(manager);
    }
    let server_info_collection = app_state.server_info_collection.clone();
    let tunnel_to_server =
        ServerOutbound::new(Arc::new(sender_map), server_info_collection, packet_crypto);

    let server_rpc = ServerRPC::new(
        tunnel_to_server.clone(),
        rpc_notifier,
        subscription_verified_map,
    );

    (server_manager_list, tunnel_to_server, server_rpc)
}

pub(crate) fn server_addresses(
    config: &Config,
) -> Vec<(
    u32,
    crate::tunnel_core::server::transport::config::ProtocolAddress,
)> {
    config
        .server_addr
        .iter()
        .enumerate()
        .map(|(index, address)| (index as u32, address.clone()))
        .collect()
}

/// 按需新建一个服务端连接的全部构件：连接管理器、出站发送通道、RPC
/// 通知器与订阅校验标记。调用方负责把它们登记到 [`ServerLinkRegistry`]
/// 并通过 [`ServerRPC`] 发布。
pub(crate) struct NewServerLink {
    pub(crate) manager: ServerTurnManager,
    pub(crate) sender: Sender<(Bytes, Instant)>,
    pub(crate) notifier: RpcNotifier,
    pub(crate) subscription_verified: Arc<AtomicBool>,
}

/// 为单个服务端地址构建连接构件。`config.server_addr` 应只包含该地址。
pub(crate) fn create_server_manager(
    server_id: u32,
    config: &Config,
    default_interface: Option<rustp2p_core::socket::LocalInterface>,
    identity: SharedNodeIdentity,
    client_instance_id: Arc<Vec<u8>>,
    network: crate::context::SharedNetworkAddr,
) -> NewServerLink {
    let connect_reg_config =
        config.to_connect_config(0, default_interface, network, identity, client_instance_id);
    let (sender, receiver) = tokio::sync::mpsc::channel(1024);
    let notifier = RpcNotifier::new();
    let manager = ServerTurnManager::new(
        server_id,
        connect_reg_config,
        receiver,
        notifier.clone(),
        EventScript::new(config.event_script.clone()),
    );
    NewServerLink {
        subscription_verified: manager.subscription_verified.clone(),
        manager,
        sender,
        notifier,
    }
}

/// 运行期服务端连接登记表：server_id 到地址与连接任务的映射，以及
/// 出站/RPC 发布所需的通道、通知器与订阅校验标记。
pub(crate) struct ServerLinkRegistry {
    links: HashMap<u32, ServerLinkEntry>,
    senders: HashMap<u32, Sender<(Bytes, Instant)>>,
    notifiers: HashMap<u32, RpcNotifier>,
    verified: HashMap<u32, Arc<AtomicBool>>,
    next_server_id: u32,
}

struct ServerLinkEntry {
    address: ProtocolAddress,
    task: Option<SubTask>,
}

/// 一次发布到出站/RPC 的完整服务端登记快照。
pub(crate) struct ServerLinkTables {
    pub(crate) senders: Arc<HashMap<u32, Sender<(Bytes, Instant)>>>,
    pub(crate) notifiers: HashMap<u32, RpcNotifier>,
    pub(crate) verified: HashMap<u32, Arc<AtomicBool>>,
}

impl ServerLinkRegistry {
    pub(crate) fn new() -> Self {
        Self {
            links: HashMap::new(),
            senders: HashMap::new(),
            notifiers: HashMap::new(),
            verified: HashMap::new(),
            next_server_id: 0,
        }
    }

    /// 登记建网时创建的初始服务端（连接任务由注册任务稍后挂入）。
    pub(crate) fn insert_initial(&mut self, server_id: u32, address: ProtocolAddress) {
        self.links.insert(
            server_id,
            ServerLinkEntry {
                address,
                task: None,
            },
        );
        self.next_server_id = self.next_server_id.max(server_id + 1);
    }

    pub(crate) fn attach_task(&mut self, server_id: u32, task: SubTask) {
        if let Some(entry) = self.links.get_mut(&server_id) {
            entry.task = Some(task);
        }
    }

    /// 分配一个新的 server_id（新地址不复用已删除地址的 id）。
    pub(crate) fn next_id(&mut self) -> u32 {
        let server_id = self.next_server_id;
        self.next_server_id += 1;
        server_id
    }

    /// 当前已不在 `new_addresses` 中的 server_id（待删除）。
    pub(crate) fn removed_by(&self, new_addresses: &[ProtocolAddress]) -> Vec<u32> {
        self.links
            .iter()
            .filter(|(_, entry)| !new_addresses.contains(&entry.address))
            .map(|(server_id, _)| *server_id)
            .collect()
    }

    pub(crate) fn is_known(&self, address: &ProtocolAddress) -> bool {
        self.links.values().any(|entry| &entry.address == address)
    }

    /// 登记一个新增的服务端连接。
    pub(crate) fn add(
        &mut self,
        server_id: u32,
        address: ProtocolAddress,
        sender: Sender<(Bytes, Instant)>,
        notifier: RpcNotifier,
        verified: Arc<AtomicBool>,
        task: SubTask,
    ) {
        self.senders.insert(server_id, sender);
        self.notifiers.insert(server_id, notifier);
        self.verified.insert(server_id, verified);
        self.links.insert(
            server_id,
            ServerLinkEntry {
                address,
                task: Some(task),
            },
        );
    }

    /// 摘除不在 `new_addresses` 中的服务端登记，返回待停止的连接任务。
    /// 调用方在锁外 await 任务停止。
    pub(crate) fn plan_removals(
        &mut self,
        new_addresses: &[ProtocolAddress],
    ) -> Vec<(u32, ProtocolAddress, Option<SubTask>)> {
        let removed = self.removed_by(new_addresses);
        removed
            .into_iter()
            .filter_map(|server_id| {
                let entry = self.links.remove(&server_id)?;
                self.senders.remove(&server_id);
                self.notifiers.remove(&server_id);
                self.verified.remove(&server_id);
                Some((server_id, entry.address, entry.task))
            })
            .collect()
    }

    /// 当前 server_id 与地址的对应关系（发布给服务端信息集合）。
    pub(crate) fn id_address_pairs(&self) -> Vec<(u32, ProtocolAddress)> {
        self.links
            .iter()
            .map(|(server_id, entry)| (*server_id, entry.address.clone()))
            .collect()
    }

    /// 生成一次完整发布快照。
    pub(crate) fn publish(&self) -> ServerLinkTables {
        ServerLinkTables {
            senders: Arc::new(self.senders.clone()),
            notifiers: self.notifiers.clone(),
            verified: self.verified.clone(),
        }
    }
}

impl ServerTurnManager {
    pub fn new(
        server_id: u32,
        config: ConnectRegConfig,
        receiver: Receiver<(Bytes, Instant)>,
        notifier: RpcNotifier,
        event_script: EventScript,
    ) -> Self {
        let connector = TransportClient::new();
        Self {
            server_id,
            transport_client: connector,
            config,
            receiver: Some(receiver),
            notifier,
            event_script,
            subnet_sync_supported: false,
            subscription_verified: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn disconnect(&mut self) {
        self.transport_client.disconnect();
    }

    pub async fn connect_and_reg(
        &mut self,
        mode: RegistrationMode,
    ) -> anyhow::Result<ResponseMessage> {
        // 域名/动态发现可能解析出多个候选地址，逐个尝试直到有能连上的。
        // 连接成功不代表地址可用，注册请求/响应也纳入本次尝试，
        // 任何一步失败都切换下一个地址
        let connect_configs = self.config.to_connect_config().await?;
        let mut last_error: Option<anyhow::Error> = None;
        for connect_config in &connect_configs {
            match self.try_connect_and_reg(connect_config, mode).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    log::warn!(
                        "server[{}] {} connect/register failed: {error:#}",
                        self.server_id,
                        connect_config.server_addr()
                    );
                    self.disconnect();
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::Error::msg("no server address to connect")))
    }

    /// 对一个候选地址执行完整的「连接 → 注册 → 等待响应」流程。
    /// 只有注册响应成功收到才算该地址可用，任何一步失败都返回错误。
    async fn try_connect_and_reg(
        &mut self,
        connect_config: &ConnectConfig,
        mode: RegistrationMode,
    ) -> anyhow::Result<ResponseMessage> {
        log::info!(
            "Connecting to server[{}] {:?} with mode {:?}",
            self.server_id,
            connect_config,
            mode,
        );
        self.transport_client
            .connect_timeout(connect_config, Duration::from_secs(10))
            .await?;
        let reg_msg = self.config.reg_msg_request(self.server_id, mode);
        let subscription_registration = reg_msg.subscription.clone();
        let request_msg = RequestMessage::Reg(reg_msg);
        let encoded = request_msg.encode();

        self.transport_client.send(encoded.freeze()).await?;
        let buf = self
            .transport_client
            .next_timeout(Duration::from_secs(10))
            .await?;
        let response = ResponseMessage::from_slice(&buf)?;
        self.subnet_sync_supported = matches!(
            &response,
            ResponseMessage::Reg(reg) if reg.subnet_sync_supported
        );
        let subscription_verified = match (
            self.config.managed.as_ref(),
            subscription_registration.as_ref(),
            &response,
        ) {
            (Some(managed), Some(registration), ResponseMessage::Reg(reg)) => reg
                .subscription
                .as_ref()
                .is_some_and(|proof| managed.verify_server_proof(registration, proof)),
            _ => false,
        };
        self.subscription_verified
            .store(subscription_verified, Ordering::Release);
        if self.config.managed.is_some() && !subscription_verified {
            log::warn!(
                "服务器 {} 未通过订阅链接凭据校验；该连接不会应用服务端配置",
                self.config.server_addr
            );
        }
        match &response {
            ResponseMessage::Reg(_) => {}
            ResponseMessage::Error(_e) => {
                self.disconnect();
            }
            ResponseMessage::ConfirmReg(_) => {
                self.disconnect();
            }
            ResponseMessage::FastReg(_) => {
                self.disconnect();
            }
            ResponseMessage::SubscriptionConfig(_) => {
                self.disconnect();
            }
            ResponseMessage::SubscriptionRegister(_)
            | ResponseMessage::SubscriptionPush(_)
            | ResponseMessage::SubscriptionPong(_) => {
                self.disconnect();
            }
        }
        Ok(response)
    }

    /// Start a server data task. Servers which were not part of the successful
    /// initial registration enter the normal reconnect loop immediately.
    /// Returns the task handle so the caller can stop this server alone.
    pub fn data_handle_task(
        mut self,
        task_group: &TaskGroup,
        config: Box<InboundHandlerConfig>,
        initially_connected: bool,
    ) -> SubTask {
        let subscription_identity = self
            .config
            .managed
            .as_ref()
            .map(|managed| (managed.network_code.clone(), managed.device_id.clone()));
        let data_handler = ServerTurnInboundHandler::new(
            self.server_id,
            config,
            self.subscription_verified.clone(),
            subscription_identity,
        );
        data_handler.set_subnet_sync_supported(self.subnet_sync_supported);
        let Some(mut receiver) = self.receiver.take() else {
            unreachable!()
        };

        // 服务端连接任务可被单独停止/重建（运行期增删服务器）：用
        // spawn_restartable，任务退出（含被停止）不会因任务组空置而
        // 把组关停，后续新增服务器仍可 spawn 进来
        task_group.spawn_restartable(async move {
            let mut already_connected = initially_connected;
            let mut has_connected_once = initially_connected;
            loop {
                if !already_connected {
                    self.disconnect();
                    data_handler.handle_disconnected();
                    let msg = match self.connect_and_reg(RegistrationMode::Normal).await {
                        Ok(msg) => msg,
                        Err(e) => {
                            log::error!("连接服务器失败:{e:?}");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    };
                    match &msg {
                        ResponseMessage::Reg(reg) => {
                            data_handler.set_subnet_sync_supported(reg.subnet_sync_supported);
                            data_handler.set_server_identity(
                                reg.server_instance_id.clone(),
                                reg.multi_link_supported,
                            );
                            let Some(_current_network) = data_handler.network_addr() else {
                                log::error!("客户端当前虚拟网络状态不存在，5秒后重试");
                                self.disconnect();
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                continue;
                            };
                            if !data_handler.reconcile_server_network(
                                reg.ip,
                                reg.prefix_len,
                                reg.gateway,
                            ) {
                                // 该服务器分配的虚拟网络与当前不一致，
                                // 断开本次连接并降低重试频率，不影响其他服务器。
                                log::error!(
                                    "服务器{}虚拟网络发生变化，1分钟后重试",
                                    self.config.server_addr
                                );
                                self.disconnect();
                                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                                continue;
                            }
                            // 保存服务器版本
                            if !reg.server_version.is_empty() {
                                data_handler.set_server_version(reg.server_version.clone());
                            }
                        }
                        ResponseMessage::Error(e) => {
                            // 单台服务器注册失败只影响本服务器的重连，
                            // 退避后重试，不能拖垮整个任务组
                            log::error!("注册失败 {e:?}，5秒后重试");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            continue;
                        }
                        _ => {
                            log::error!("错误的注册消息，5秒后重试");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    }
                }
                // 重连成功后触发事件脚本（首次连接不算重连）
                if should_notify_reconnected(already_connected, has_connected_once) {
                    let mut params = vec![("server", self.config.server_addr.to_string())];
                    if let Some(network) = data_handler.network_addr() {
                        params.push(("ip", network.ip.to_string()));
                        params.push(("prefix-length", network.prefix_len.to_string()));
                        params.push((
                            "gateway",
                            network
                                .gateway
                                .map(|gateway| gateway.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                        ));
                        params.push(("broadcast", network.broadcast.to_string()));
                    }
                    self.event_script
                        .notify(EventScriptType::Reconnected, &params)
                        .await;
                }
                log::info!("已连接服务器:{}", self.config.server_addr);
                data_handler.handle_connected();
                has_connected_once = true;

                if let Err(e) = self.data_handle_loop(&mut receiver, &data_handler).await {
                    log::error!("Error on data_handle_loop: {:?}", e);
                    // data_handle_loop is entered only after a successful
                    // connection, including background and reconnected
                    // servers, so every exit is a real disconnect event.
                    self.event_script
                        .notify(
                            EventScriptType::Disconnected,
                            &[("server", self.config.server_addr.to_string())],
                        )
                        .await;
                }
                // Remove the server's reachability immediately. Waiting until
                // the next reconnect iteration leaves a window where cached
                // clients suppress decentralized discovery.
                data_handler.handle_disconnected();
                already_connected = false;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        })
    }

    pub async fn data_handle_loop(
        &mut self,
        receiver: &mut Receiver<(Bytes, Instant)>,
        data_handler: &ServerTurnInboundHandler,
    ) -> anyhow::Result<()> {
        let mut time = crate::utils::time::now_ts_ms();
        let mut ping_interval = tokio::time::interval(Duration::from_secs(5));
        let mut subnet_sync_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(10),
            Duration::from_secs(10),
        );
        subnet_sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                Some((buf,expired)) = receiver.recv() => {
                    if expired < Instant::now(){
                        continue;
                    }
                    self.transport_client.send(buf).await?;
                }
                rs = self.transport_client.next() => {
                    time = crate::utils::time::now_ts_ms();
                    let data = rs?;
                    if let Err(e) = data_handler.handle(&mut self.transport_client,data, &self.notifier,time).await{
                        log::warn!("Error handling data: {:?}", e);
                    }
                }
                _ = ping_interval.tick() => {
                    let now = crate::utils::time::now_ts_ms();
                    if now > time + Duration::from_secs(20).as_millis() as i64 {
                        bail!("timeout")
                    }
                    data_handler.handle_ping(&mut self.transport_client,now).await?;
                }
                _ = subnet_sync_interval.tick() => {
                    data_handler.handle_subnet_sync(&mut self.transport_client).await?;
                }
                else => {
                    bail!("receiver closed");
                }
            }
        }
    }
}

/// Register with all configured servers concurrently and return as soon as one
/// server accepts the fixed virtual IP. Dropping the remaining futures cancels
/// their initial attempts; their data tasks will subsequently reconnect them.
pub async fn register_with_first_available(
    managers: &mut [ServerTurnManager],
) -> anyhow::Result<(usize, ResponseMessage)> {
    if managers.is_empty() {
        bail!("No servers to register");
    }

    log::info!("Registering concurrently with {} servers", managers.len());

    let attempts = FuturesUnordered::new();
    for (index, manager) in managers.iter_mut().enumerate() {
        attempts.push(async move {
            (
                index,
                manager.connect_and_reg(RegistrationMode::Normal).await,
            )
        });
    }

    select_first_available(attempts).await
}

async fn select_first_available<S>(mut attempts: S) -> anyhow::Result<(usize, ResponseMessage)>
where
    S: Stream<Item = (usize, anyhow::Result<ResponseMessage>)> + Unpin,
{
    let mut first_rejection = None;
    let mut connection_errors = Vec::new();
    while let Some((index, result)) = attempts.next().await {
        match result {
            Ok(response) => match response {
                response @ ResponseMessage::Reg(_) => {
                    log::info!("Server {index} completed initial registration");
                    drop(attempts);
                    return Ok((index, response));
                }
                ResponseMessage::Error(error) => {
                    log::warn!("Server {index} rejected registration: {}", error.message);
                    if first_rejection.is_none() {
                        first_rejection = Some((index, ResponseMessage::Error(error)));
                    }
                }
                response => {
                    log::warn!("Server {index} returned an unexpected registration response");
                    connection_errors.push(format!(
                        "server {index} returned unexpected response: {response:?}"
                    ));
                }
            },
            Err(error) => {
                log::warn!("Server {index} initial registration failed: {error:#}");
                connection_errors.push(format!("server {index}: {error:#}"));
            }
        }
    }

    if let Some(rejection) = first_rejection {
        return Ok(rejection);
    }

    bail!(
        "All servers failed to connect/register: {}",
        connection_errors.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_event_requires_a_previous_successful_connection() {
        assert!(!should_notify_reconnected(false, false));
        assert!(!should_notify_reconnected(true, true));
        assert!(should_notify_reconnected(false, true));
    }
    use crate::protocol::control_message::{ErrorResponseMsg, RegResponseMsg};
    use futures::FutureExt;

    fn registration(ip: [u8; 4]) -> ResponseMessage {
        ResponseMessage::Reg(RegResponseMsg {
            ip: ip.into(),
            prefix_len: 24,
            gateway: [ip[0], ip[1], ip[2], 1].into(),
            server_version: "test".to_string(),
            subnet_sync_supported: false,
            subscription_config_supported: false,
            subscription: None,
            server_instance_id: vec![2; 32],
            multi_link_supported: true,
        })
    }

    #[tokio::test]
    async fn first_available_ignores_earlier_connection_failure() {
        let attempts = futures::stream::iter(vec![
            (0, Err(anyhow::anyhow!("offline"))),
            (1, Ok(registration([10, 26, 0, 2]))),
        ]);
        let (index, response) = select_first_available(attempts).await.unwrap();
        assert_eq!(index, 1);
        assert!(matches!(response, ResponseMessage::Reg(_)));
    }

    #[tokio::test]
    async fn first_available_does_not_wait_for_a_pending_server() {
        let attempts = FuturesUnordered::new();
        attempts
            .push(futures::future::pending::<(usize, anyhow::Result<ResponseMessage>)>().boxed());
        attempts.push(futures::future::ready((1, Ok(registration([10, 26, 0, 2])))).boxed());

        let result =
            tokio::time::timeout(Duration::from_millis(100), select_first_available(attempts))
                .await
                .expect("a ready server must not wait for a pending server")
                .unwrap();
        assert_eq!(result.0, 1);
    }

    #[tokio::test]
    async fn first_available_returns_retryable_error_when_all_connections_fail() {
        let attempts = futures::stream::iter(vec![
            (0, Err(anyhow::anyhow!("offline"))),
            (1, Err(anyhow::anyhow!("timeout"))),
        ]);
        let error = select_first_available(attempts)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("offline"));
        assert!(error.contains("timeout"));
    }

    #[tokio::test]
    async fn first_available_returns_server_rejection_when_none_succeed() {
        let rejection = ResponseMessage::Error(ErrorResponseMsg {
            code: 1,
            message: "denied".to_string(),
        });
        let attempts = futures::stream::iter(vec![
            (0, Ok(rejection)),
            (1, Err(anyhow::anyhow!("offline"))),
        ]);
        let (index, response) = select_first_available(attempts).await.unwrap();
        assert_eq!(index, 0);
        assert!(matches!(response, ResponseMessage::Error(_)));
    }
}
