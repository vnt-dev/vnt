use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::rpc_message::rpc_message_request::RpcReqPayload;
use crate::protocol::rpc_message::rpc_message_response::RpcResPayload;
use crate::protocol::rpc_message::{
    ClientInfo, ClientListRequest, ClientListResponse, RpcMessageRequest, RpcMessageResponse,
};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::server::outbound::ServerOutbound;
use anyhow::bail;
use parking_lot::Mutex;
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender;

#[derive(Clone)]
pub struct ServerRPC {
    tunnel_to_server: ServerOutbound,
    rpc_notifier: HashMap<u32, RpcNotifier>,
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
    ) -> Self {
        Self {
            tunnel_to_server,
            rpc_notifier,
        }
    }

    pub async fn client_list(&self) -> anyhow::Result<ClientListResponse> {
        let mut map: HashMap<String, ClientInfo> = HashMap::new();
        for server_id in self.tunnel_to_server.server_id_list() {
            match self.client_list_target(*server_id).await {
                Ok(rs) => {
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
        let Some(rpc_notifier) = self.rpc_notifier.get(&server_id) else {
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
