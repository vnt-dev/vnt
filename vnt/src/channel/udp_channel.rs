use std::collections::HashMap;
use std::net::UdpSocket as StdUdpSocket;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::{sync_channel, Receiver};
use std::{io, thread};

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::channel::context::Context;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::notify::AcceptNotify;
use crate::channel::sender::AcceptSocketSender;
use crate::channel::{RouteKey, BUFFER_SIZE};
use crate::util::StopManager;

pub fn udp_listen<H>(
    stop_manager: StopManager,
    recv_handler: H,
    context: Context,
) -> io::Result<AcceptSocketSender<Option<Vec<UdpSocket>>>>
where
    H: RecvChannelHandler,
{
    //根据通道数创建对应线程进行读取
    for index in 0..context.channel_num() {
        main_udp_listen(
            index,
            stop_manager.clone(),
            recv_handler.clone(),
            context.clone(),
        )?;
    }
    sub_udp_listen(stop_manager, recv_handler, context)
}

const NOTIFY: Token = Token(0);

fn sub_udp_listen<H>(
    stop_manager: StopManager,
    recv_handler: H,
    context: Context,
) -> io::Result<AcceptSocketSender<Option<Vec<UdpSocket>>>>
where
    H: RecvChannelHandler,
{
    let (udp_sender, udp_receiver) = sync_channel(64);
    let poll = Poll::new()?;
    let waker = AcceptNotify::new(Waker::new(poll.registry(), NOTIFY)?);
    let worker = {
        let waker = waker.clone();
        stop_manager.add_listener("sub_udp_listen".into(), move || {
            if let Err(e) = waker.stop() {
                log::error!("{:?}", e);
            }
        })?
    };
    let accept = AcceptSocketSender::new(waker.clone(), udp_sender);
    thread::Builder::new()
        .name("sub_udp读事件处理线程".into())
        .spawn(move || {
            if let Err(e) = sub_udp_listen0(poll, recv_handler, context, waker, udp_receiver) {
                log::error!("{:?}", e);
            }
            worker.stop_all();
        })?;
    Ok(accept)
}

fn sub_udp_listen0<H>(
    mut poll: Poll,
    mut recv_handler: H,
    context: Context,
    accept_notify: AcceptNotify,
    accept_receiver: Receiver<Option<Vec<UdpSocket>>>,
) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let mut events = Events::with_capacity(1024);
    let mut buf = [0; BUFFER_SIZE];
    let mut read_map: HashMap<Token, UdpSocket> = HashMap::with_capacity(32);
    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            match event.token() {
                NOTIFY => {
                    if accept_notify.is_stop() {
                        return Ok(());
                    }
                    if accept_notify.is_add_socket() {
                        while let Ok(option) = accept_receiver.try_recv() {
                            match option {
                                None => {
                                    log::info!("切换成锥形模式");
                                    for (_, mut udp_socket) in read_map.drain() {
                                        if let Err(e) = udp_socket.deregister(poll.registry()) {
                                            log::error!("{:?}", e);
                                        }
                                    }
                                }
                                Some(socket_list) => {
                                    log::info!("切换成对称模式 监听端口数：{}", socket_list.len());
                                    for (index, mut udp_socket) in
                                        socket_list.into_iter().enumerate()
                                    {
                                        let token = Token(index + context.channel_num());
                                        poll.registry().register(
                                            &mut udp_socket,
                                            token,
                                            Interest::READABLE,
                                        )?;
                                        read_map.insert(token, udp_socket);
                                    }
                                }
                            }
                        }
                    }
                }
                token => {
                    if let Some(udp_socket) = read_map.get(&token) {
                        loop {
                            match udp_socket.recv_from(&mut buf) {
                                Ok((len, addr)) => {
                                    recv_handler.handle(
                                        &mut buf[..len],
                                        RouteKey::new(false, token.0, addr),
                                        &context,
                                    );
                                }
                                Err(e) => {
                                    if e.kind() == io::ErrorKind::WouldBlock {
                                        break;
                                    }
                                    log::error!("{:?}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 阻塞监听
fn main_udp_listen<H>(
    index: usize,
    stop_manager: StopManager,
    recv_handler: H,
    context: Context,
) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let port = context.main_udp_socket[index].local_addr()?.port();
    let context_ = context.clone();
    let worker = stop_manager.add_listener(format!("main_udp_listen-{}", index), move || {
        context_.stop();
        match StdUdpSocket::bind("127.0.0.1:0") {
            Ok(udp) => {
                if let Err(e) = udp.send_to(
                    b"stop",
                    SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
                ) {
                    log::error!("发送停止消息到udp失败:{:?}", e);
                }
            }
            Err(e) => {
                log::error!("发送停止-绑定udp失败:{:?}", e);
            }
        }
    })?;
    thread::Builder::new()
        .name("main_udp读事件处理线程".into())
        .spawn(move || {
            if let Err(e) = main_udp_listen0(index, recv_handler, context) {
                log::error!("{:?}", e);
            }
            worker.stop_all();
        })?;
    Ok(())
}

pub fn main_udp_listen0<H>(index: usize, mut recv_handler: H, context: Context) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let mut buf = [0; BUFFER_SIZE];
    let udp_socket = &context.main_udp_socket[index];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                if &buf[..len] == b"stop" {
                    if context.is_stop() {
                        return Ok(());
                    }
                }
                recv_handler.handle(&mut buf[..len], RouteKey::new(false, index, addr), &context);
            }
            Err(e) => {
                log::error!("main_udp_listen0={:?}", e);
            }
        }
    }
}
