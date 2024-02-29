use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
#[cfg(any(unix))]
use std::os::fd::FromRawFd;
#[cfg(any(unix))]
use std::os::fd::IntoRawFd;
#[cfg(windows)]
use std::os::windows::io::FromRawSocket;
#[cfg(windows)]
use std::os::windows::io::IntoRawSocket;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::{io, thread};

use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token, Waker};

use crate::channel::context::Context;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::notify::{AcceptNotify, WritableNotify};
use crate::channel::sender::{AcceptSocketSender, PacketSender};
use crate::channel::{RouteKey, BUFFER_SIZE};
use crate::util::StopManager;

const SERVER: Token = Token(0);
const NOTIFY: Token = Token(1);

/// 监听tcp端口，等待客户端连接
pub fn tcp_listen<H>(
    tcp_server: TcpListener,
    stop_manager: StopManager,
    recv_handler: H,
    context: Context,
) -> io::Result<AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>>
where
    H: RecvChannelHandler,
{
    let (tcp_sender, tcp_receiver) = sync_channel(64);
    let poll = Poll::new()?;
    let waker = AcceptNotify::new(Waker::new(poll.registry(), NOTIFY)?);
    let accept = AcceptSocketSender::new(waker.clone(), tcp_sender);
    let worker = {
        let waker = waker.clone();
        stop_manager.add_listener("tcp_listen".into(), move || {
            if let Err(e) = waker.stop() {
                log::error!("{:?}", e);
            }
        })?
    };

    thread::Builder::new()
        .name("tcp读事件处理线程".into())
        .spawn(move || {
            if let Err(e) = tcp_listen0(
                poll,
                tcp_server,
                &stop_manager,
                waker,
                tcp_receiver,
                recv_handler,
                context,
            ) {
                log::error!("{:?}", e);
            }
            worker.stop_all();
        })?;
    Ok(accept)
}

fn tcp_listen0<H>(
    mut poll: Poll,
    mut tcp_server: TcpListener,
    stop_manager: &StopManager,
    accept_notify: AcceptNotify,
    accept_tcp_receiver: Receiver<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
    mut recv_handler: H,
    context: Context,
) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let (tcp_sender, tcp_receiver) = sync_channel(64);
    let write_waker = init_writable_handler(tcp_receiver, stop_manager.clone(), context.clone())?;
    poll.registry()
        .register(&mut tcp_server, SERVER, Interest::READABLE)?;
    let mut events = Events::with_capacity(1024);

    let mut read_map: HashMap<Token, (RouteKey, TcpStream, Box<[u8; BUFFER_SIZE]>, usize)> =
        HashMap::with_capacity(32);
    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            match event.token() {
                SERVER => loop {
                    match tcp_server.accept() {
                        Ok((stream, addr)) => {
                            accept_handle(
                                stream,
                                addr,
                                None,
                                &write_waker,
                                &mut read_map,
                                &tcp_sender,
                                poll.registry(),
                            )?;
                        }
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                break;
                            }
                            return Err(e);
                        }
                    }
                },
                NOTIFY => {
                    if accept_notify.is_stop() {
                        return Ok(());
                    }
                    if accept_notify.is_add_socket() {
                        while let Ok((stream, addr, init_buf)) = accept_tcp_receiver.try_recv() {
                            accept_handle(
                                stream,
                                addr,
                                init_buf,
                                &write_waker,
                                &mut read_map,
                                &tcp_sender,
                                poll.registry(),
                            )?;
                        }
                    }
                }
                token => {
                    if event.is_readable() {
                        if let Err(e) =
                            readable_handle(&token, &mut read_map, &mut recv_handler, &context)
                        {
                            closed_handle_r(&token, &mut read_map);
                            log::warn!("{:?}", e);
                            if let Err(e) = write_waker.notify(token, false) {
                                log::warn!("{:?}", e);
                            }
                        }
                    } else {
                        closed_handle_r(&token, &mut read_map);
                        if let Err(e) = write_waker.notify(token, false) {
                            log::warn!("{:?}", e);
                        }
                    }
                }
            }
        }
    }
}

/// 处理写事件

fn init_writable_handler(
    receiver: Receiver<(TcpStream, Token, SocketAddr, Option<Vec<u8>>)>,
    stop_manager: StopManager,
    context: Context,
) -> io::Result<WritableNotify> {
    let poll = Poll::new()?;
    let writable_notify = WritableNotify::new(Waker::new(poll.registry(), NOTIFY)?);
    let worker = {
        let writable_notify = writable_notify.clone();
        stop_manager.add_listener("tcp_writable_handler".into(), move || {
            if let Err(e) = writable_notify.stop() {
                log::error!("{:?}", e);
            }
        })?
    };
    {
        let writable_notify = writable_notify.clone();
        thread::Builder::new()
            .name("tcp-writeable-listen".into())
            .spawn(move || {
                if let Err(e) = tcp_writable_listen(receiver, poll, writable_notify, &context) {
                    log::error!("{:?}", e);
                }
                worker.stop_all();
            })?;
    }

    Ok(writable_notify)
}

/// 处理写事件
fn tcp_writable_listen(
    receiver: Receiver<(TcpStream, Token, SocketAddr, Option<Vec<u8>>)>,
    mut poll: Poll,
    writable_notify: WritableNotify,
    context: &Context,
) -> io::Result<()> {
    let mut events = Events::with_capacity(1024);
    let mut write_map: HashMap<
        Token,
        (
            TcpStream,
            SocketAddr,
            Receiver<Vec<u8>>,
            Option<(Vec<u8>, usize)>,
        ),
    > = HashMap::with_capacity(32);
    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            match event.token() {
                NOTIFY => {
                    if writable_notify.is_stop() {
                        //服务停止
                        return Ok(());
                    }
                    if writable_notify.is_need_write() {
                        // 需要写入数据
                        if let Some(tokens) = writable_notify.take_all() {
                            for (token, state) in tokens {
                                if !state {
                                    closed_handle_w(&token, &mut write_map, &context);
                                    continue;
                                }
                                if let Err(e) = writable_handle(&token, &mut write_map) {
                                    closed_handle_w(&token, &mut write_map, &context);
                                    log::warn!("{:?}", e);
                                }
                            }
                        }
                    }
                    if writable_notify.is_add_socket() {
                        //添加tcp连接，并监听写事件
                        while let Ok((mut stream, token, addr, init_buf)) = receiver.try_recv() {
                            if let Err(e) = stream.set_nodelay(true) {
                                log::warn!("set_nodelay err={:?}", e);
                            }
                            if let Err(e) =
                                poll.registry()
                                    .register(&mut stream, token, Interest::WRITABLE)
                            {
                                log::warn!("registry err={:?}", e);
                                continue;
                            }
                            let (sender, receiver) = sync_channel(128);
                            let packet_sender =
                                PacketSender::new(writable_notify.clone(), sender, token);
                            if let Some(init_buf) = init_buf {
                                packet_sender.try_send(&init_buf)?;
                            }

                            context.tcp_map.write().insert(addr, packet_sender);
                            write_map.insert(token, (stream, addr, receiver, None));
                        }
                    }
                }
                token => {
                    if event.is_writable() {
                        if let Err(e) = writable_handle(&token, &mut write_map) {
                            closed_handle_w(&token, &mut write_map, &context);
                            log::warn!("{:?}", e);
                        }
                    } else {
                        closed_handle_w(&token, &mut write_map, &context);
                    }
                }
            }
        }
    }
}

fn accept_handle(
    stream: TcpStream,
    addr: SocketAddr,
    init_buf: Option<Vec<u8>>,
    write_waker: &WritableNotify,
    read_map: &mut HashMap<Token, (RouteKey, TcpStream, Box<[u8; BUFFER_SIZE]>, usize)>,
    tcp_sender: &SyncSender<(TcpStream, Token, SocketAddr, Option<Vec<u8>>)>,
    registry: &Registry,
) -> io::Result<()> {
    #[cfg(windows)]
    let (tcp_stream, index) = unsafe {
        let fd = stream.into_raw_socket();
        (std::net::TcpStream::from_raw_socket(fd), fd as usize)
    };
    #[cfg(any(unix))]
    let (tcp_stream, index) = unsafe {
        let fd = stream.into_raw_fd();
        (std::net::TcpStream::from_raw_fd(fd), fd as usize)
    };
    if index == 0 || index == 1 {
        log::error!("index err={:?}", addr);
        return Ok(());
    }
    let token = Token(index);
    match tcp_stream.try_clone() {
        Ok(tcp_writer) => {
            match tcp_sender.try_send((TcpStream::from_std(tcp_writer), token, addr, init_buf)) {
                Ok(_) => {
                    if let Err(e) = write_waker.add_socket() {
                        log::error!("write_waker,err={:?},addr={:?}", e, addr);
                        return Ok(());
                    }
                }
                Err(e) => {
                    return match e {
                        TrySendError::Full(_) => {
                            log::error!("Full,addr={:?}", addr);
                            Ok(())
                        }
                        TrySendError::Disconnected(_) => {
                            Err(io::Error::new(io::ErrorKind::Other, "write thread exit"))
                        }
                    };
                }
            }
        }
        Err(e) => {
            log::error!("try_clone err={:?},addr={:?}", e, addr);
            return Ok(());
        }
    }
    let mut stream = TcpStream::from_std(tcp_stream);
    if let Err(e) = registry.register(&mut stream, token, Interest::READABLE) {
        log::error!("registry err={:?},addr={:?}", e, addr);
        return Ok(());
    }
    read_map.insert(
        token,
        (
            RouteKey::new(true, index, addr),
            stream,
            Box::new([0; BUFFER_SIZE]),
            0,
        ),
    );
    Ok(())
}

fn readable_handle<H>(
    token: &Token,
    map: &mut HashMap<Token, (RouteKey, TcpStream, Box<[u8; BUFFER_SIZE]>, usize)>,
    recv_handler: &mut H,
    context: &Context,
) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    if let Some((route_key, stream, buf, begin)) = map.get_mut(token) {
        loop {
            let end = if *begin >= 4 {
                4 + (((buf[2] as u16) << 8) | buf[3] as u16) as usize
            } else {
                4
            };
            if end > BUFFER_SIZE {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            match stream.read(&mut buf[*begin..end]) {
                Ok(len) => {
                    if len == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    *begin += len;
                    if end > 4 && *begin == end {
                        recv_handler.handle(&mut buf[4..end], *route_key, context);
                        *begin = 0;
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

fn writable_handle(
    token: &Token,
    map: &mut HashMap<
        Token,
        (
            TcpStream,
            SocketAddr,
            Receiver<Vec<u8>>,
            Option<(Vec<u8>, usize)>,
        ),
    >,
) -> io::Result<()> {
    if let Some((stream, _, receiver, last)) = map.get_mut(token) {
        loop {
            if let Some((buf, begin)) = last {
                match stream.write(&buf[*begin..]) {
                    Ok(len) => {
                        if len == 0 {
                            return Err(io::Error::from(io::ErrorKind::WriteZero));
                        }
                        if len + *begin == buf.len() {
                            *last = None;
                        } else {
                            *begin += len;
                            continue;
                        }
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        return Err(e);
                    }
                }
            }
            match receiver.try_recv() {
                Ok(buf) => *last = Some((buf, 0)),
                Err(e) => match e {
                    TryRecvError::Empty => {
                        break;
                    }
                    TryRecvError::Disconnected => {
                        return Err(io::Error::from(io::ErrorKind::Other));
                    }
                },
            }
        }
    }
    Ok(())
}

fn closed_handle_r(
    token: &Token,
    map: &mut HashMap<Token, (RouteKey, TcpStream, Box<[u8; BUFFER_SIZE]>, usize)>,
) {
    if let Some((_, tcp, _, _)) = map.remove(token) {
        let _ = tcp.shutdown(Shutdown::Both);
    }
}

fn closed_handle_w(
    token: &Token,
    map: &mut HashMap<
        Token,
        (
            TcpStream,
            SocketAddr,
            Receiver<Vec<u8>>,
            Option<(Vec<u8>, usize)>,
        ),
    >,
    context: &Context,
) {
    if let Some((tcp, addr, _, _)) = map.remove(token) {
        context.tcp_map.write().remove(&addr);
        let _ = tcp.shutdown(Shutdown::Both);
    }
}
