use crate::protocol::control_message::SubscriptionConfigAck;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::rpc_message::rpc_message_request::RpcReqPayload;
use crate::protocol::rpc_message::rpc_message_response::RpcResPayload;
use crate::protocol::rpc_message::{
    ClientInfo, ClientListRequest, ClientListResponse, RpcMessageRequest, RpcMessageResponse,
};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::server::connection_manager::ServerLinkTables;
use crate::tunnel_core::server::outbound::ServerOutbound;
use anyhow::bail;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender;

#[derive(Clone)]
pub struct ServerRPC {
    tunnel_to_server: ServerOutbound,
    state: Arc<ArcSwap<ServerRpcState>>,
}

struct ServerRpcState {
    rpc_notifier: HashMap<u32, RpcNotifier>,
    subscription_verified: HashMap<u32, Arc<AtomicBool>>,
}
#[derive(Clone)]
pub(crate) struct RpcNotifier {
    pending_requests: Arc<Mutex<HashMap<u64, Sender<RpcMessageResponse>>>>,
    rpc_id: Arc<Mutex<u64>>,
}

impl RpcNotifier {
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            rpc_id: Arc::new(Mutex::new(0)),
        }
    }

    pub fn create_request_and_waiter(&self) -> RpcResponseWaiter {
        let id: u64 = {
            let mut id_lock = self.rpc_id.lock();
            *id_lock += 1;
            *id_lock
        };

        let (tx, rx) = oneshot::channel();

        {
            let mut pending = self.pending_requests.lock();
            pending.insert(id, tx);
        }

        RpcResponseWaiter {
            id,
            pending_requests_handle: Arc::clone(&self.pending_requests),
            rx,
        }
    }

    pub fn notify_response(&self, response: RpcMessageResponse) {
        let mut pending = self.pending_requests.lock();

        if let Some(tx) = pending.remove(&response.id) {
            let _ = tx.send(response);
        }
    }
}

pub(crate) struct RpcResponseWaiter {
    id: u64,
    pending_requests_handle: Arc<Mutex<HashMap<u64, Sender<RpcMessageResponse>>>>,
    rx: oneshot::Receiver<RpcMessageResponse>,
}

impl RpcResponseWaiter {
    pub async fn wait_for_response(
        mut self,
        timeout: Duration,
    ) -> anyhow::Result<RpcMessageResponse> {
        let result = tokio::time::timeout(timeout, &mut self.rx).await;

        match result {
            Err(_) => bail!("timeout waiting for response"),
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => bail!("closed connection"),
        }
    }
}

impl Drop for RpcResponseWaiter {
    fn drop(&mut self) {
        let mut pending = self.pending_requests_handle.lock();
        let _ = pending.remove(&self.id);
    }
}

impl ServerRPC {
    pub(crate) fn new(
        tunnel_to_server: ServerOutbound,
        rpc_notifier: HashMap<u32, RpcNotifier>,
        subscription_verified: HashMap<u32, Arc<AtomicBool>>,
    ) -> Self {
        Self {
            tunnel_to_server,
            state: Arc::new(ArcSwap::from_pointee(ServerRpcState {
                rpc_notifier,
                subscription_verified,
            })),
        }
    }

    /// 用新的服务端登记快照整体替换出站通道与 RPC 通知器
    /// （运行期服务端增删后发布）。
    pub(crate) fn update_server_links(&self, tables: ServerLinkTables) {
        let ServerLinkTables {
            senders,
            notifiers,
            verified,
        } = tables;
        self.tunnel_to_server.update_senders(senders);
        self.state
            .store(Arc::new(ServerRpcState {
                rpc_notifier: notifiers,
                subscription_verified: verified,
            }));
    }

    pub async fn acknowledge_subscription_config(
        &self,
        ack: SubscriptionConfigAck,
    ) -> anyhow::Result<usize> {
        let payload = ack.encode();
        let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + payload.len()))?;
        packet.set_msg_type(MsgType::SubscriptionConfigAck);
        packet.set_gateway_flag(true);
        packet.set_ttl(1);
        packet.set_payload(&payload)?;
        let bytes = packet.into_buffer().into_bytes().freeze();
        let mut sent = 0;
        let state = self.state.load_full();
        let mut seen_instances = HashSet::new();
        for (&server_id, verified) in &state.subscription_verified {
            if !verified.load(Ordering::Acquire) {
                continue;
            }
            let instance_id = self.tunnel_to_server.server_instance_id(server_id);
            if instance_id
                .as_ref()
                .is_some_and(|instance_id| seen_instances.contains(instance_id))
            {
                continue;
            }
            match self
                .tunnel_to_server
                .send_gateway_to_server(server_id, bytes.clone(), Duration::from_secs(5))
                .await
            {
                Ok(true) => {
                    sent += 1;
                    if let Some(instance_id) = instance_id {
                        seen_instances.insert(instance_id);
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    log::warn!("subscription acknowledgement send failed: {error}");
                }
            }
        }
        Ok(sent)
    }

    pub fn has_verified_config_server(&self) -> bool {
        self.state
            .load()
            .subscription_verified
            .iter()
            .any(|(&server_id, verified)| {
                verified.load(Ordering::Acquire)
                    && self.tunnel_to_server.is_server_connected(server_id)
            })
    }

    pub async fn client_list(&self) -> anyhow::Result<ClientListResponse> {
        let mut map: HashMap<String, ClientInfo> = HashMap::new();
        let mut seen_instances = HashSet::new();
        for server_id in self.tunnel_to_server.server_id_list().iter().copied() {
            if !self.tunnel_to_server.is_server_connected(server_id) {
                continue;
            }
            let instance_id = self.tunnel_to_server.server_instance_id(server_id);
            if instance_id
                .as_ref()
                .is_some_and(|instance_id| seen_instances.contains(instance_id))
            {
                continue;
            }
            match self.client_list_target(server_id).await {
                Ok(rs) => {
                    if let Some(instance_id) = instance_id {
                        seen_instances.insert(instance_id);
                    }
                    for client in rs.list {
                        map.entry(client.id.clone()).or_insert(client);
                    }
                }
                Err(e) => {
                    log::error!("client list target failed: {}", e);
                }
            }
        }

        Ok(ClientListResponse {
            list: map.into_values().collect(),
        })
    }
    pub async fn client_list_target(&self, server_id: u32) -> anyhow::Result<ClientListResponse> {
        let state = self.state.load_full();
        let Some(rpc_notifier) = state.rpc_notifier.get(&server_id) else {
            bail!("no RPC notifier");
        };
        let waiter = rpc_notifier.create_request_and_waiter();
        let request = RpcMessageRequest {
            id: waiter.id,
            rpc_req_payload: Some(RpcReqPayload::ClientListReq(ClientListRequest::default())),
        };
        let buf = request.encode_to_vec();
        let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + buf.len()))?;
        packet.set_msg_type(MsgType::RpcReq);
        packet.set_gateway_flag(true);
        packet.set_ttl(1);
        packet.set_payload(&buf)?;

        self.tunnel_to_server
            .send_to_gateway_expired(server_id, packet, Duration::from_secs(1))
            .await?;
        let response = waiter.wait_for_response(Duration::from_secs(3)).await?;
        if let Some(RpcResPayload::ClientListRes(res)) = response.rpc_res_payload {
            return Ok(res);
        }
        bail!("unexpected response: {:?}", response);
    }
}
