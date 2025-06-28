use crate::channel::{ConnectProtocol, RouteKey, BUFFER_SIZE};
use anyhow::Context;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use std::convert::Into;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::thread;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{Error, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::channel::context::ChannelContext;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::sender::PacketSender;
use crate::util::StopManager;

/// ws协议，
/// 暂时只允许用ws连服务端，不能用ws打洞/连客户端
pub fn ws_connect_accept<H>(
    receiver: Receiver<(Vec<u8>, String)>,
    recv_handler: H,
    context: ChannelContext,
    stop_manager: StopManager,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let worker = stop_manager.add_listener("wsChannel".into(), move || {
        let _ = stop_sender.send(());
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("ws tokio runtime build failed")?;
    thread::Builder::new()
        .name("wsChannel".into())
        .spawn(move || {
            runtime.spawn(async move { connect_ws_handle(receiver, recv_handler, context).await });
            runtime.block_on(async {
                let _ = stop_receiver.await;
            });
            runtime.shutdown_background();
            worker.stop_all();
        })
        .context("ws thread build failed")?;
    Ok(())
}

async fn connect_ws_handle<H>(
    mut receiver: Receiver<(Vec<u8>, String)>,
    recv_handler: H,
    context: ChannelContext,
) where
    H: RecvChannelHandler,
{
    let mut index = 0;
    while let Some((data, url)) = receiver.recv().await {
        let recv_handler = recv_handler.clone();
        let context = context.clone();
        tokio::spawn(async move {
            if let Err(e) = connect_ws(data, url, recv_handler, context, index).await {
                log::warn!("发送失败,ws链接终止:{:?}", e);
            }
        });
        index += 1;
    }
}
const WS_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

async fn connect_ws<H>(
    data: Vec<u8>,
    mut url: String,
    recv_handler: H,
    context: ChannelContext,
    index: usize,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let mut count = 0;
    log::info!("尝试建立连接 {:?}", url);
    let (mut ws, response) = loop {
        count += 1;
        if count > 3 {
            Err(anyhow::anyhow!("发生多次重定向，链接终止"))?
        }
        match tokio::time::timeout(Duration::from_secs(3), connect_async(url)).await? {
            Ok(rs) => break rs,
            Err(e) => {
                if let Error::Http(res) = &e {
                    if res.status() == StatusCode::MOVED_PERMANENTLY
                        || res.status() == StatusCode::FOUND
                        || res.status() == StatusCode::SEE_OTHER
                        || res.status() == StatusCode::TEMPORARY_REDIRECT
                        || res.status() == StatusCode::PERMANENT_REDIRECT
                    {
                        if let Some(v) = res.headers().get("Location") {
                            if let Ok(redirect) = v.to_str() {
                                log::info!("url重定向响应头 {:?}", res.headers());
                                log::info!("url重定向地址 {}", redirect);
                                // 替换协议前缀
                                if redirect.starts_with("http://") {
                                    url = redirect.replacen("http://", "ws://", 1);
                                } else if redirect.starts_with("https://") {
                                    url = redirect.replacen("https://", "wss://", 1);
                                } else {
                                    url = redirect.to_string();
                                }
                                println!("Location：{}", url);
                                log::info!("修改后的重定向地址: {}", url);
                                continue;
                            }
                        }
                    }
                }
                return Err(e)?;
            }
        }
    };
    log::info!("ws协议握手 {:?}", response);
    ws.send(Message::Binary(data)).await?;
    let (mut ws_write, ws_read) = ws.split();
    let (sender, mut receiver) = channel::<Vec<u8>>(100);
    let route_key = RouteKey::new(ConnectProtocol::WS, index, WS_ADDR);

    context
        .packet_map
        .write()
        .insert(route_key, PacketSender::new(sender));
    tokio::spawn(async move {
        while let Some(data) = receiver.recv().await {
            if let Err(e) = ws_write.send(Message::Binary(data)).await {
                log::warn!("websocket err {:?}", e);
                break;
            }
        }
        let _ = ws_write.close().await;
    });
    if let Err(e) = ws_read_handle(ws_read, recv_handler, &context, route_key).await {
        log::warn!("{:?}", e);
    }
    context.packet_map.write().remove(&route_key);
    Ok(())
}
async fn ws_read_handle<H>(
    mut ws_read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    recv_handler: H,
    context: &ChannelContext,
    route_key: RouteKey,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let mut extend = [0; BUFFER_SIZE];
    while let Some(msg) = ws_read.next().await {
        let msg = msg.context("Error during WebSocket ")?;
        match msg {
            Message::Text(txt) => log::info!("Received text message: {}", txt),
            Message::Binary(mut data) => {
                recv_handler.handle(&mut data, &mut extend, route_key, context);
            }
            Message::Ping(_) | Message::Pong(_) => (),
            Message::Close(_) => break,
            _ => {}
        }
    }
    Ok(())
}
