use crate::compression::PacketCompression;
use crate::context::config::Config;
use crate::context::nat::{MyNatInfo, PunchBackoff};
use crate::context::{AppState, NetworkAddr, NetworkRoute, PeerInfoMap, ServerInfoCollection};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::fec::FecDecoder;
use crate::protocol::control_message::{
    ConfirmRegResponseMsg, RegistrationMode, RequestMessage, ResponseMessage,
};
use crate::tunnel_core::p2p::transport::punch::NatPuncher;
use crate::tunnel_core::server::inbound::ServerTurnInboundHandler;
use crate::tunnel_core::server::outbound::ServerOutbound;
use crate::tunnel_core::server::rpc::{RpcNotifier, ServerRPC};
use crate::tunnel_core::server::transport::TransportClient;
use crate::tunnel_core::server::transport::config::ConnectRegConfig;
use crate::utils::task_control::TaskGroup;
use anyhow::bail;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};

pub struct InboundHandlerConfig {
    pub network_route: NetworkRoute,
    pub server_info: ServerInfoCollection,
    pub nat_info: MyNatInfo,
    pub peer_map: PeerInfoMap,
    pub punch_backoff: PunchBackoff,
    pub puncher: NatPuncher,
    pub packet_crypto: PacketCrypto,
    pub packet_compression: PacketCompression,
    pub enhanced_inbound: EnhancedInbound,
    pub fec_decoder: FecDecoder,
}

pub struct ServerTurnManager {
    server_id: u32,
    config: ConnectRegConfig,
    receiver: Option<Receiver<(Bytes, Instant)>>,
    notifier: RpcNotifier,
    transport_client: TransportClient,
}
pub(crate) fn create_server_tunnel(
    app_state: AppState,
    config: &Config,
    packet_crypto: PacketCrypto,
) -> (Vec<ServerTurnManager>, ServerOutbound, ServerRPC) {
    let mut rpc_notifier: HashMap<u32, RpcNotifier> = HashMap::new();
    let mut sender_map: HashMap<u32, Sender<(Bytes, Instant)>> = HashMap::new();
    let mut server_manager_list = Vec::with_capacity(config.server_addr.len());
    let mut server_addr_list = Vec::with_capacity(config.server_addr.len());
    for (index, server_addr) in config.server_addr.iter().enumerate() {
        let connect_reg_config = config.to_connect_config(index);

        let server_id = index as u32;

        let (s, r) = tokio::sync::mpsc::channel(1024);

        let notifier = RpcNotifier::new();
        let manager =
            ServerTurnManager::new(server_id, connect_reg_config.clone(), r, notifier.clone());
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

    (server_manager_list, tunnel_to_server, server_rpc)
}

impl ServerTurnManager {
    pub fn new(
        server_id: u32,
        config: ConnectRegConfig,
        receiver: Receiver<(Bytes, Instant)>,
        notifier: RpcNotifier,
    ) -> Self {
        let connector = TransportClient::new();
        Self {
            server_id,
            transport_client: connector,
            config,
            receiver: Some(receiver),
            notifier,
        }
    }
    pub fn disconnect(&mut self) {
        self.transport_client.disconnect();
    }

    pub async fn connect_and_reg(
        &mut self,
        mode: RegistrationMode,
    ) -> anyhow::Result<ResponseMessage> {
        let connect_config = self.config.to_connect_config().await?;
        log::info!(
            "Connecting to server[{}] {:?} with mode {:?}",
            self.server_id,
            connect_config,
            mode,
        );

        self.transport_client
            .connect_timeout(&connect_config, Duration::from_secs(10))
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
        match &response {
            ResponseMessage::Reg(_) => {}
            ResponseMessage::Error(_e) => {
                self.disconnect();
            }
            ResponseMessage::ConfirmReg(_) => {
                self.disconnect();
            }
        }
        Ok(response)
    }

    pub async fn send_confirm(&mut self) -> anyhow::Result<ConfirmRegResponseMsg> {
        self.transport_client
            .send(RequestMessage::ConfirmReg.encode().freeze())
            .await?;
        let buf = self
            .transport_client
            .next_timeout(Duration::from_secs(10))
            .await?;
        let response = ResponseMessage::from_slice(&buf)?;
        match response {
            ResponseMessage::ConfirmReg(msg) => Ok(msg),
            ResponseMessage::Error(e) => bail!("Confirm failed: {}", e.message),
            _ => bail!("Unexpected response"),
        }
    }

    pub fn set_ip(&mut self, ip: Ipv4Addr) {
        self.config.ip = Some(ip);
    }

    /// Start data handling task with an already established connection.
    pub fn data_handle_task_connected(
        mut self,
        task_group: &TaskGroup,
        config: Box<InboundHandlerConfig>,
        initial_response: NetworkAddr,
    ) {
        let data_handler = ServerTurnInboundHandler::new(self.server_id, initial_response, config);
        let task_group_ = task_group.clone();
        let Some(mut receiver) = self.receiver.take() else {
            unreachable!()
        };

        task_group.spawn(async move {
            let mut already_connected = true;
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
                            if reg.ip != initial_response.ip
                                || reg.prefix_len != initial_response.prefix_len
                                || reg.gateway != initial_response.gateway
                            {
                                log::error!("虚拟网络发生变化");
                                break;
                            }
                            // 保存服务器版本
                            if !reg.server_version.is_empty() {
                                data_handler.set_server_version(reg.server_version.clone());
                            }
                        }
                        ResponseMessage::Error(e) => {
                            log::error!("注册失败 {e:?}");
                            break;
                        }
                        _ => {
                            log::error!("错误的注册消息");
                            break;
                        }
                    }
                }
                log::info!("已连接服务器:{}", self.config.server_addr);
                data_handler.handle_connected();

                if let Err(e) = self.data_handle_loop(&mut receiver, &data_handler).await {
                    log::error!("Error on data_handle_loop: {:?}", e);
                }
                already_connected = false;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            self.disconnect();
            data_handler.handle_disconnected();
            task_group_.stop();
        });
    }

    pub async fn data_handle_loop(
        &mut self,
        receiver: &mut Receiver<(Bytes, Instant)>,
        data_handler: &ServerTurnInboundHandler,
    ) -> anyhow::Result<()> {
        let mut time = crate::utils::time::now_ts_ms();
        let mut ping_interval = tokio::time::interval(Duration::from_secs(5));
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
                else => {
                    bail!("receiver closed");
                }
            }
        }
    }
}

/// Coordinated multi-server pre-registration.
/// 1. First server uses PRE_REGISTER mode to get IP
/// 2. Other servers pre-register with the obtained IP
/// 3. Send confirmation to all servers
/// 4. Return the registration response
pub async fn coordinated_registration(
    managers: &mut Vec<ServerTurnManager>,
) -> anyhow::Result<ResponseMessage> {
    if managers.is_empty() {
        bail!("No servers to register");
    }

    // Step 1: First server pre-register to get IP
    log::info!(
        "Starting coordinated registration with {} servers",
        managers.len()
    );
    let first_response = managers[0]
        .connect_and_reg(RegistrationMode::PreRegister)
        .await?;

    let ip = match &first_response {
        ResponseMessage::Reg(reg) => reg.ip,
        ResponseMessage::Error(e) => {
            log::info!("First server registration failed: {}", e.message);
            return Ok(first_response);
        }
        _ => bail!("Unexpected response from first server"),
    };
    log::info!("Got IP {} from first server", ip);

    // Step 2: Set IP and pre-register with other servers
    for manager in managers.iter_mut().skip(1) {
        manager.set_ip(ip);
    }

    if managers.len() > 1 {
        let other_results: Vec<_> = futures::future::join_all(
            managers
                .iter_mut()
                .skip(1)
                .map(|m| m.connect_and_reg(RegistrationMode::PreRegister)),
        )
        .await;

        // Check all responses
        for (i, result) in other_results.iter().enumerate() {
            match result {
                Ok(ResponseMessage::Reg(_)) => {
                    log::info!("Server {} pre-registered successfully", i + 1);
                }
                Ok(ResponseMessage::Error(e)) => {
                    log::info!("Server {} registration failed: {}", i + 1, e.message);
                    return Ok(ResponseMessage::Error(e.clone()));
                }
                Err(e) => bail!("Server {} registration failed: {}", i + 1, e),
                _ => bail!("Unexpected response from server {}", i + 1),
            }
        }
    }

    // Step 3: Send confirmation to all servers
    log::info!("Sending confirmation to all servers");
    let confirm_results: Vec<_> =
        futures::future::join_all(managers.iter_mut().map(|m| m.send_confirm())).await;

    // Check all confirmation responses
    for (i, result) in confirm_results.into_iter().enumerate() {
        match result {
            Ok(msg) if msg.success => {
                log::info!("Server {} confirmed successfully", i);
            }
            Ok(_) => bail!("Server {} confirmation failed", i),
            Err(e) => bail!("Server {} confirmation failed: {}", i, e),
        }
    }

    log::info!("Coordinated registration completed successfully");
    // Return first server's response (contains IP info)
    Ok(first_response)
}
