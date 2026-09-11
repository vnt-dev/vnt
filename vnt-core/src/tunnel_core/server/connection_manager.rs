use crate::compression::PacketCompression;
use crate::context::config::{Config, PunchRule, TurnRule};
use crate::context::nat::{MyNatInfo, PunchBackoff};
use crate::context::{AppState, NetworkRoute, PeerInfoMap, ServerInfoCollection};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::event_script::{EventScript, EventScriptType};
use crate::fec::FecDecoder;
use crate::nat::AllowSubnetExternalRoute;
use crate::protocol::client_message::NodeIdentityTemplate;
use crate::protocol::control_message::{RegistrationMode, RequestMessage, ResponseMessage};
use crate::tunnel_core::outbound::BasicOutbound;
use crate::tunnel_core::p2p::transport::punch::NatPuncher;
use crate::tunnel_core::server::inbound::{IpUpdateContext, ServerTurnInboundHandler};
use crate::tunnel_core::server::outbound::ServerOutbound;
use crate::tunnel_core::server::rpc::{RpcNotifier, ServerRPC};
use crate::tunnel_core::server::transport::TransportClient;
use crate::tunnel_core::server::transport::config::{
    ConnectConfig, ConnectRegConfig, SharedRegistrationIp,
};
use crate::utils::task_control::TaskGroup;
use anyhow::bail;
use bytes::Bytes;
use futures::stream::{FuturesUnordered, Stream, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};

pub struct InboundHandlerConfig {
    pub network_route: NetworkRoute,
    pub ip_update: IpUpdateContext,
    pub server_info: ServerInfoCollection,
    pub nat_info: MyNatInfo,
    pub peer_map: PeerInfoMap,
    pub punch_backoff: PunchBackoff,
    pub puncher: NatPuncher,
    pub punch_model: Arc<Vec<PunchRule>>,
    pub packet_crypto: PacketCrypto,
    pub packet_compression: PacketCompression,
    pub enhanced_inbound: EnhancedInbound,
    pub fec_decoder: FecDecoder,
    pub turn: Arc<Vec<TurnRule>>,
    pub auto_sync_subnet: bool,
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub relay_subnets: AllowSubnetExternalRoute,
    pub basic_outbound: BasicOutbound,
    pub node_identity: NodeIdentityTemplate,
}

pub struct ServerTurnManager {
    server_id: u32,
    config: ConnectRegConfig,
    receiver: Option<Receiver<(Bytes, Instant)>>,
    notifier: RpcNotifier,
    transport_client: TransportClient,
    event_script: EventScript,
    subnet_sync_supported: bool,
}
pub(crate) fn create_server_tunnel(
    app_state: AppState,
    config: &Config,
    packet_crypto: PacketCrypto,
    default_interface: Option<rustp2p_core::socket::LocalInterface>,
) -> (
    Vec<ServerTurnManager>,
    ServerOutbound,
    ServerRPC,
    SharedRegistrationIp,
) {
    let mut rpc_notifier: HashMap<u32, RpcNotifier> = HashMap::new();
    let mut sender_map: HashMap<u32, Sender<(Bytes, Instant)>> = HashMap::new();
    let mut server_manager_list = Vec::with_capacity(config.server_addr.len());
    let mut server_addr_list = Vec::with_capacity(config.server_addr.len());
    let registration_ip = SharedRegistrationIp::new(config.ip.map(|ip| ip.ip()));
    for (index, server_addr) in config.server_addr.iter().enumerate() {
        let connect_reg_config =
            config.to_connect_config(index, default_interface.clone(), registration_ip.clone());

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
        server_addr_list.push((server_id, server_addr.clone()));
        rpc_notifier.insert(server_id, notifier);
        sender_map.insert(server_id, s);
        server_manager_list.push(manager);
    }
    let server_info_collection = app_state.server_info_collection.clone();
    server_info_collection.update_server(server_addr_list);
    let tunnel_to_server =
        ServerOutbound::new(Arc::new(sender_map), server_info_collection, packet_crypto);

    let server_rpc = ServerRPC::new(tunnel_to_server.clone(), rpc_notifier);

    (
        server_manager_list,
        tunnel_to_server,
        server_rpc,
        registration_ip,
    )
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
        }
        Ok(response)
    }

    /// Start a server data task. Servers which were not part of the successful
    /// initial registration enter the normal reconnect loop immediately.
    pub fn data_handle_task(
        mut self,
        task_group: &TaskGroup,
        config: Box<InboundHandlerConfig>,
        initially_connected: bool,
    ) {
        let data_handler = ServerTurnInboundHandler::new(self.server_id, config);
        data_handler.set_subnet_sync_supported(self.subnet_sync_supported);
        let Some(mut receiver) = self.receiver.take() else {
            unreachable!()
        };

        task_group.spawn(async move {
            let mut already_connected = initially_connected;
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
                if !already_connected {
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

                if let Err(e) = self.data_handle_loop(&mut receiver, &data_handler).await {
                    log::error!("Error on data_handle_loop: {:?}", e);
                    // 从已连接状态掉线时触发事件脚本
                    if already_connected {
                        self.event_script
                            .notify(
                                EventScriptType::Disconnected,
                                &[("server", self.config.server_addr.to_string())],
                            )
                            .await;
                    }
                }
                already_connected = false;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
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
    use crate::protocol::control_message::{ErrorResponseMsg, RegResponseMsg};
    use futures::FutureExt;

    fn registration(ip: [u8; 4]) -> ResponseMessage {
        ResponseMessage::Reg(RegResponseMsg {
            ip: ip.into(),
            prefix_len: 24,
            gateway: [ip[0], ip[1], ip[2], 1].into(),
            server_version: "test".to_string(),
            subnet_sync_supported: false,
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
