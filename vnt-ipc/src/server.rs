use crate::{DEFAULT_PORT, get_port_file_path};

use crate::message::ipc_request::IpcCmd;
use crate::message::ipc_response::ResponsePayload;
use crate::message::{
    AppInfo, ClientInfoItem, ClientInfoList, ClientIpItem, ClientIpList, ClientRouteItem,
    ClientRouteList, IpcRequest, IpcResponse, PacketLoss, Route, ServerInfo,
};
use anyhow::bail;
use futures::{SinkExt, StreamExt};
use prost::Message;
use std::fs;
use std::net::Ipv4Addr;
use tokio::io::{self};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use vnt_core::api::VntApi;

async fn handle_connection(stream: TcpStream, vnt_api: VntApi) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

    if let Some(Ok(message)) = framed.next().await {
        let request = IpcRequest::decode(message.as_ref())?;
        let Some(cmd) = request.ipc_cmd else {
            bail!("Received an IpcRequest but it was None");
        };
        let rs = match cmd {
            IpcCmd::AppInfo(_) => {
                let info = app_info(&vnt_api);
                ResponsePayload::AppInfo(info)
            }
            IpcCmd::ClientIps(_) => {
                let items = vnt_api
                    .client_ips()
                    .into_iter()
                    .map(|v| {
                        let rtt = if let Some(v) = vnt_api.find_route(&v.ip) {
                            Some(v.rtt())
                        } else {
                            vnt_api.server_node_rtt(&v.ip).map(|v| v * 2)
                        };
                        ClientIpItem {
                            ip: v.ip.into(),
                            online: v.online,
                            is_direct: vnt_api.is_direct(&v.ip),
                            rtt,
                        }
                    })
                    .collect();
                ResponsePayload::ClientIps(ClientIpList { items })
            }
            IpcCmd::ClientList(_) => {
                let client_list = vnt_api.server_rpc().client_list().await?;
                let key_sign = vnt_api.get_config().and_then(|config| config.key_sign());
                let items = client_list
                    .list
                    .into_iter()
                    .map(|v| {
                        let ip = Ipv4Addr::from(v.ip);
                        let rtt = if let Some(v) = vnt_api.find_route(&ip) {
                            Some(v.rtt())
                        } else {
                            vnt_api.server_node_rtt(&ip).map(|v| v * 2)
                        };
                        let packet_loss = vnt_api.packet_loss_info(&ip).map(|info| PacketLoss {
                            sent: info.sent,
                            received: info.received,
                            loss_rate: info.loss_rate,
                        });
                        ClientInfoItem {
                            ip: v.ip,
                            name: v.name,
                            version: v.version,
                            online: v.online,
                            is_direct: vnt_api.is_direct(&Ipv4Addr::from(v.ip)),
                            last_connected_time: v.last_connected_time,
                            rtt,
                            key_equal: key_sign == v.key_sign,
                            packet_loss,
                        }
                    })
                    .collect();
                ResponsePayload::ClientList(ClientInfoList { items })
            }
            IpcCmd::AllRoute(_) => {
                let route_list = all_route(&vnt_api);
                ResponsePayload::AllRoute(route_list)
            }
        };
        let rs = IpcResponse {
            response_payload: Some(rs),
        };
        framed.send(rs.encode_to_vec().into()).await?;
    }

    Ok(())
}
fn app_info(vnt_api: &VntApi) -> AppInfo {
    let config = vnt_api.get_config();
    let ips = vnt_api.client_ips();
    let online_client_num = ips.iter().filter(|v| v.online).count() as _;
    let offline_client_num = ips.iter().filter(|v| !v.online).count() as _;
    let direct_client_num = ips.iter().filter(|ip| vnt_api.is_direct(&ip.ip)).count() as _;
    let server_node_list = vnt_api.server_node_list();
    let nat_info = vnt_api.nat_info();
    AppInfo {
        server_info: server_node_list
            .into_iter()
            .map(|v| ServerInfo {
                server: v.server_addr.to_string(),
                connected: v.connected,
                server_rtt: v.rtt,
                last_connected_time: v.last_connected_time,
            })
            .collect(),
        name: config
            .as_ref()
            .map(|v| v.device_name.clone())
            .unwrap_or_default(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        ip: vnt_api.network().map(|v| v.ip.into()),
        online_client_num,
        offline_client_num,
        direct_client_num,
        device_id: config.map(|v| v.device_id.clone()).unwrap_or_default(),
        nat_type: nat_info.as_ref().map(|v| format!("{:?}", v.nat_type)),
        public_ipv4s: nat_info
            .as_ref()
            .map(|v| {
                v.public_ips
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default(),
        public_ipv6: nat_info
            .as_ref()
            .and_then(|v| v.ipv6.map(|v| v.to_string())),
    }
}
fn all_route(vnt_api: &VntApi) -> ClientRouteList {
    let vec = vnt_api.route_table();
    let mut items = Vec::with_capacity(vec.len());
    for (ip, route_list) in vec {
        items.push(ClientRouteItem {
            ip: ip.into(),
            route_list: route_list
                .into_iter()
                .map(|v| Route {
                    addr: v.route_key().to_string(),
                    metric: v.metric() as _,
                    rtt: v.rtt(),
                })
                .collect(),
        })
    }
    ClientRouteList { items }
}

pub async fn run_server(bind_port: Option<u16>, vnt_api: VntApi) -> anyhow::Result<()> {
    let mut port = bind_port.unwrap_or(DEFAULT_PORT);
    let listener;

    loop {
        match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
            Ok(l) => {
                listener = l;
                break;
            }
            Err(e) if bind_port.is_none() && e.kind() == io::ErrorKind::AddrInUse => {
                port = 0;
            }
            Err(e) => bail!("bind :{e:?}"),
        }
    }

    let bound_addr = listener.local_addr()?;
    log::info!("IPC Listening on {}", bound_addr);
    let actual_port = bound_addr.port();

    let path = get_port_file_path();
    fs::write(&path, actual_port.to_string())?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        log::info!("IPC Connection from {}", peer_addr);
        let vnt_api = vnt_api.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, vnt_api).await {
                log::warn!("IPC Error handling client: {:?},peer_addr={peer_addr}", e);
            }
        });
    }
}
