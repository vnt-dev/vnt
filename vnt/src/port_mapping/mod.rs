use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;

use anyhow::Context;

use crate::util::StopManager;

mod tcp_mapping;

mod udp_mapping;

pub fn convert(vec: Vec<String>) -> anyhow::Result<Vec<(bool, SocketAddr, String)>> {
    let mut rs = Vec::with_capacity(vec.len());
    for x in vec {
        let string = x.trim().to_lowercase();
        if let Some(udp_mapping) = string.strip_prefix("udp:") {
            let mut split = udp_mapping.split("-");
            let bind_addr = split.next().with_context(|| {
                format!(
                    "udp_mapping error {:?},eg: udp:127.0.0.1:80-10.26.0.10:8080",
                    x
                )
            })?;
            let bind_addr = SocketAddr::from_str(bind_addr)
                .with_context(|| format!("udp_mapping error {}", bind_addr))?;
            let dest = split.next().with_context(|| {
                format!(
                    "udp_mapping error {:?},eg: udp:127.0.0.1:80-10.26.0.10:8080",
                    x
                )
            })?;
            rs.push((false, bind_addr, dest.to_string()));
            continue;
        }
        if let Some(tcp_mapping) = string.strip_prefix("tcp:") {
            let mut split = tcp_mapping.split("-");
            let bind_addr = split.next().with_context(|| {
                format!(
                    "tcp_mapping error {:?},eg: tcp:127.0.0.1:80-10.26.0.10:8080",
                    x
                )
            })?;
            let bind_addr = SocketAddr::from_str(bind_addr)
                .with_context(|| format!("udp_mapping error {}", bind_addr))?;
            let dest = split.next().with_context(|| {
                format!(
                    "tcp_mapping error {:?},eg: tcp:127.0.0.1:80-10.26.0.10:8080",
                    x
                )
            })?;
            rs.push((true, bind_addr, dest.to_string()));
            continue;
        }
        Err(anyhow::anyhow!(
            "port_mapping error {:?},eg: tcp:127.0.0.1:80-10.26.0.10:8080",
            x
        ))?;
    }
    Ok(rs)
}
pub fn start_port_mapping(
    stop_manager: StopManager,
    vec: Vec<(bool, SocketAddr, String)>,
) -> anyhow::Result<()> {
    if vec.is_empty() {
        return Ok(());
    }

    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    let worker = stop_manager.add_listener("portMapping".into(), move || {
        let _ = sender.send(());
    })?;
    thread::Builder::new()
        .name("portMapping".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("portMapping")
                .build().unwrap();
            runtime.block_on(start_port_mapping0(vec)).unwrap();
            runtime.block_on(async {
                let _ = receiver.await;
            });
            runtime.shutdown_background();
            drop(worker);
        })?;

    Ok(())
}

async fn start_port_mapping0(vec: Vec<(bool, SocketAddr, String)>) -> anyhow::Result<()> {
    for (is_tcp, bind_addr, destination) in vec {
        if is_tcp {
            tcp_mapping::tcp_mapping(bind_addr, destination).await?;
        } else {
            udp_mapping::udp_mapping(bind_addr, destination).await?;
        }
    }
    Ok(())
}
