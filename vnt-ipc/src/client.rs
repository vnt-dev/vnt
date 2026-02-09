use crate::message::ipc_request::IpcCmd;
use crate::message::ipc_response::ResponsePayload;
use crate::message::{
    AppInfo, ClientInfoList, ClientIpList, ClientRouteList, IpcRequest, IpcResponse,
};
use crate::{DEFAULT_PORT, get_port_file_path};
use anyhow::Context;
use cli_table::{Cell, Style, Table, print_stdout};
use console::style;
use futures::{SinkExt, StreamExt};
use prost::Message;
use std::fs;
use std::net::Ipv4Addr;
use std::time::Duration;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub async fn run_client(cmd: IpcCmd, port: Option<u16>) -> anyhow::Result<()> {
    let path = get_port_file_path();
    let port = if let Some(port) = port {
        port
    } else {
        match fs::read_to_string(&path) {
            Ok(port_string) => port_string.trim().parse().context("parse port error")?,
            Err(_) => DEFAULT_PORT,
        }
    };

    let addr = format!("127.0.0.1:{}", port);

    let stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr))
        .await
        .context("Connection timed out")??;

    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

    framed
        .send(IpcRequest { ipc_cmd: Some(cmd) }.encode_to_vec().into())
        .await?;
    let response = framed.next().await.context("Unexpected end of stream")??;
    let response = IpcResponse::decode(response).context("decode response error")?;
    match response
        .response_payload
        .context("response payload is empty")?
    {
        ResponsePayload::AppInfo(info) => {
            print_app_info(info);
        }
        ResponsePayload::ClientIps(list) => print_client_ip_list(list)?,
        ResponsePayload::ClientList(list) => {
            print_client_list(list)?;
        }
        ResponsePayload::AllRoute(route_list) => {
            print_route_list(route_list)?;
        }
    };
    Ok(())
}

fn key_style(s: &str) -> console::StyledObject<&str> {
    style(s).cyan().bright().bold()
}
pub fn print_app_info(info: AppInfo) {
    println!(
        "\n{}",
        style("--- Application Information ---").italic().dim()
    );

    for server_info in info.server_info {
        let status_colored = if server_info.connected {
            if let Some(rtt) = server_info.server_rtt {
                style(format!("Online {rtt}ms"))
                    .green()
                    .bright()
                    .to_string()
            } else {
                style("Online").green().bright().to_string()
            }
        } else {
            style("Offline").red().bright().to_string()
        };

        println!(
            "{:24}{} ({})",
            key_style("Server:"),
            style(&server_info.server).white(),
            status_colored
        );

        let time_str = server_info
            .last_connected_time
            .map(|v| style(ts_to_string(v / 1000)).white().to_string())
            .unwrap_or_else(|| "Never".to_string());

        println!("{:24}{}", key_style("Last Connected Time:"), time_str);
    }

    println!("{:24}{}", key_style("Name:"), style(&info.name).white());
    println!("{:24}{}", key_style("Id:"), style(&info.device_id).white());
    println!(
        "{:24}{}",
        key_style("Version:"),
        style(&info.version).white()
    );

    let ip_str = info
        .ip
        .map(|v| {
            style(Ipv4Addr::from(v).to_string())
                .yellow()
                .bright()
                .to_string()
        })
        .unwrap_or_else(|| style("N/A").red().bright().to_string());

    println!("{:24}{}", key_style("IP:"), ip_str);

    let total_clients = info.online_client_num + info.offline_client_num;

    println!(
        "{:24}{}",
        key_style("Total Clients:"),
        style(total_clients).color256(213)
    );

    println!(
        "{:24}{}",
        key_style("Online Clients:"),
        style(info.online_client_num).color256(82)
    );

    println!(
        "{:24}{}",
        key_style("P2P Clients:"),
        style(info.direct_client_num).color256(117)
    );
    println!(
        "{:24}{}",
        key_style("Nat Type:"),
        style(info.nat_type.unwrap_or_else(|| "Unknown".to_string())).color256(117)
    );
    println!(
        "{:24}{}",
        key_style("Ipv6:"),
        style(info.public_ipv6.unwrap_or_default()).color256(117)
    );
    println!(
        "{:24}{}",
        key_style("Public Ipv4:"),
        style(info.public_ipv4s.join(",")).color256(117)
    );
    println!(
        "{}",
        style("-------------------------------").italic().dim()
    );
}

fn print_client_ip_list(list: ClientIpList) -> anyhow::Result<()> {
    println!("\n--- Client List ({}) ---", list.items.len());

    let table = list
        .items
        .iter()
        .map(|item| {
            vec![
                Ipv4Addr::from(item.ip).to_string().cell(),
                item.online.to_string().cell(),
                item.is_direct.to_string().cell(),
                item.rtt.map(|v| v.to_string()).unwrap_or_default().cell(),
            ]
        })
        .table()
        .title(vec![
            "IP".cell().bold(true),
            "Online".cell().bold(true),
            "P2P".cell().bold(true),
            "RTT".cell().bold(true),
        ]);

    print_stdout(table)?;
    println!("\n");
    Ok(())
}

fn print_client_list(list: ClientInfoList) -> anyhow::Result<()> {
    println!("\n--- Client List ({}) ---", list.items.len());

    let table = list
        .items
        .iter()
        .map(|item| {
            let key_equal: bool = item.key_equal;
            let mut ip_str = Ipv4Addr::from(item.ip).to_string();
            if !key_equal {
                ip_str.push_str("(Key Mismatch)");
            }
            let loss_str = item
                .packet_loss
                .as_ref()
                .map(|v| format!("{:.1}%", v.loss_rate))
                .unwrap_or_default();

            vec![
                ip_str.cell(),
                item.name.clone().cell(),
                item.version.clone().cell(),
                item.online.to_string().cell(),
                item.is_direct.to_string().cell(),
                item.rtt.map(|v| v.to_string()).unwrap_or_default().cell(),
                loss_str.cell(),
                ts_to_string(item.last_connected_time).cell(),
            ]
        })
        .table()
        .title(vec![
            "IP".cell().bold(true),
            "Name".cell().bold(true),
            "Version".cell().bold(true),
            "Online".cell().bold(true),
            "P2P".cell().bold(true),
            "RTT".cell().bold(true),
            "Loss".cell().bold(true),
            "Last Connected Time".cell().bold(true),
        ]);

    print_stdout(table)?;
    println!("\n");
    Ok(())
}

pub fn print_route_list(route_list: ClientRouteList) -> anyhow::Result<()> {
    let total_routes: usize = route_list
        .items
        .iter()
        .map(|item| item.route_list.len())
        .sum();

    println!("\n--- All Routes List (Total: {}) ---", total_routes);

    let mut rows = Vec::new();
    for client_route in route_list.items {
        let client_ip_str = Ipv4Addr::from(client_route.ip).to_string();

        for route in client_route.route_list {
            rows.push(vec![
                client_ip_str.clone().cell(),
                route.metric.to_string().cell(),
                route.rtt.to_string().cell(),
                route.addr.clone().cell(),
            ]);
        }
    }

    let table = rows.table().title(vec![
        "Destination IP".cell().bold(true),
        "Metric".cell().bold(true),
        "RTT (ms)".cell().bold(true),
        "Remote Address".cell().bold(true),
    ]);

    print_stdout(table)?;
    println!("\n");
    Ok(())
}

pub fn ts_to_string(ts_secs: i64) -> String {
    let dt = match OffsetDateTime::from_unix_timestamp(ts_secs) {
        Ok(dt) => dt,
        Err(_) => {
            return String::new();
        }
    };
    let local_offset = match UtcOffset::local_offset_at(dt) {
        Ok(offset) => offset,
        Err(_e) => match UtcOffset::from_hms(8, 0, 0) {
            Ok(offset) => offset,
            Err(_) => return String::new(),
        },
    };
    let dt_local = dt.to_offset(local_offset);
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    dt_local.format(&format).unwrap()
}
