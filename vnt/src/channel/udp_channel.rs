use std::sync::mpsc::{sync_channel, Receiver};
use std::{io, thread};

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::channel::context::ChannelContext;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::notify::AcceptNotify;
use crate::channel::sender::AcceptSocketSender;
use crate::channel::{ConnectProtocol, RouteKey, BUFFER_SIZE};
use crate::util::StopManager;

pub fn udp_listen<H>(
    stop_manager: StopManager,
    recv_handler: H,
    context: ChannelContext,
) -> anyhow::Result<AcceptSocketSender<Option<Vec<UdpSocket>>>>
where
    H: RecvChannelHandler,
{
    main_udp_listen(stop_manager.clone(), recv_handler.clone(), context.clone())?;
    sub_udp_listen(stop_manager, recv_handler, context)
}

const NOTIFY: Token = Token(0);

fn sub_udp_listen<H>(
    stop_manager: StopManager,
    recv_handler: H,
    context: ChannelContext,
) -> anyhow::Result<AcceptSocketSender<Option<Vec<UdpSocket>>>>
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
        .name("subUdp".into())
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
    recv_handler: H,
    context: ChannelContext,
    accept_notify: AcceptNotify,
    accept_receiver: Receiver<Option<Vec<UdpSocket>>>,
) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let mut events = Events::with_capacity(1024);
    let mut buf = [0; BUFFER_SIZE];
    let mut extend = [0; BUFFER_SIZE];
    let mut list: Vec<UdpSocket> = Vec::with_capacity(100);
    let main_len = context.main_len();
    loop {
        if let Err(e) = poll.poll(&mut events, None) {
            crate::ignore_io_interrupted(e)?;
            continue;
        }
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
                                    for mut udp_socket in list.drain(..) {
                                        if let Err(e) = udp_socket.deregister(poll.registry()) {
                                            log::error!("{:?}", e);
                                        }
                                    }
                                }
                                Some(socket_list) => {
                                    for mut udp_socket in list.drain(..) {
                                        if let Err(e) = udp_socket.deregister(poll.registry()) {
                                            log::error!("deregister {:?}", e);
                                        }
                                    }
                                    log::info!("切换成对称模式 监听端口数：{}", socket_list.len());
                                    for (index, mut udp_socket) in
                                        socket_list.into_iter().enumerate()
                                    {
                                        poll.registry().register(
                                            &mut udp_socket,
                                            Token(index),
                                            Interest::READABLE,
                                        )?;
                                        list.push(udp_socket);
                                    }
                                }
                            }
                        }
                    }
                }
                Token(index) => {
                    if let Some(udp_socket) = list.get(index) {
                        loop {
                            match udp_socket.recv_from(&mut buf) {
                                Ok((len, addr)) => {
                                    recv_handler.handle(
                                        &mut buf[..len],
                                        &mut extend,
                                        RouteKey::new(ConnectProtocol::UDP, index + main_len, addr),
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

// /// 阻塞
// fn main_udp_listen<H>(
//     stop_manager: StopManager,
//     recv_handler: H,
//     context: Context,
// ) -> io::Result<()>
// where
//     H: RecvChannelHandler,
// {
//     for index in 0..context.main_udp_socket.len() {
//         let stop_manager = stop_manager.clone();
//         let context = context.clone();
//         let recv_handler = recv_handler.clone();
//         thread::Builder::new()
//             .name(format!("mainUdp{}", index))
//             .spawn(move || {
//                 if let Err(e) = main_udp_listen0(stop_manager, index, recv_handler, context) {
//                     log::error!("{:?}", e);
//                 }
//             })?;
//     }
//     Ok(())
// }
//
// pub fn main_udp_listen0<H>(
//     stop_manager: StopManager,
//     index: usize,
//     mut recv_handler: H,
//     context: Context,
// ) -> io::Result<()>
// where
//     H: RecvChannelHandler,
// {
//     use std::time::Duration;
//     let udp_socket = &context.main_udp_socket[index];
//     udp_socket.set_read_timeout(Some(Duration::from_secs(5)))?;
//     udp_socket.set_write_timeout(Some(Duration::from_secs(1)))?;
//     let local_addr = udp_socket.local_addr()?;
//     let worker = stop_manager.add_listener(format!("main_udp_{}", index), move || {
//         if let Ok(udp) = std::net::UdpSocket::bind("0.0.0.0:0") {
//             let _ = udp.send_to(b"stop", format!("127.0.0.1:{}", local_addr.port()));
//         }
//     })?;
//
//     let mut buf = [0; BUFFER_SIZE];
//     loop {
//         match udp_socket.recv_from(&mut buf) {
//             Ok((len, addr)) => {
//                 if &buf[..len] == b"stop" {
//                     if stop_manager.is_stop() {
//                         break;
//                     }
//                 }
//                 recv_handler.handle(&mut buf[..len], RouteKey::new(false, index, addr), &context);
//             }
//             Err(e) => {
//                 if stop_manager.is_stop() {
//                     break;
//                 }
//                 log::error!("index={},{:?},{}", index, udp_socket.local_addr(), e)
//             }
//         }
//     }
//     worker.stop_all();
//     Ok(())
// }

/// 非阻塞
fn main_udp_listen<H>(
    stop_manager: StopManager,
    recv_handler: H,
    context: ChannelContext,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    use std::sync::Arc;
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), NOTIFY)?);
    let _waker = waker.clone();
    let worker = stop_manager.add_listener("main_udp".into(), move || {
        if let Err(e) = waker.wake() {
            log::error!("{:?}", e);
        }
    })?;
    thread::Builder::new()
        .name("mainUdp".into())
        .spawn(move || {
            if let Err(e) = main_udp_listen0(poll, recv_handler, context) {
                log::error!("{:?}", e);
            }
            drop(_waker);
            worker.stop_all();
        })?;
    Ok(())
}

pub fn main_udp_listen0<H>(
    mut poll: Poll,
    recv_handler: H,
    context: ChannelContext,
) -> io::Result<()>
where
    H: RecvChannelHandler,
{
    let mut buf = [0; BUFFER_SIZE];
    let mut udps = Vec::with_capacity(context.main_udp_socket.len());

    for (index, udp) in context.main_udp_socket.iter().enumerate() {
        let udp_socket = udp.try_clone()?;
        udp_socket.set_nonblocking(true)?;
        let mut mio_udp = UdpSocket::from_std(udp_socket);
        poll.registry()
            .register(&mut mio_udp, Token(index + 1), Interest::READABLE)?;
        udps.push(mio_udp);
    }

    let mut events = Events::with_capacity(udps.len());
    let mut extend = [0; BUFFER_SIZE];
    loop {
        if let Err(e) = poll.poll(&mut events, None) {
            crate::ignore_io_interrupted(e)?;
            continue;
        }
        for x in events.iter() {
            let index = match x.token() {
                NOTIFY => return Ok(()),
                // 0的位置留给NOTIFY了，这里要再减回去，因为路由是通过index来找到对应udp的
                Token(index) => index - 1,
            };
            let udp = if let Some(udp) = udps.get(index) {
                udp
            } else {
                log::error!("{:?}", x);
                continue;
            };
            loop {
                match udp.recv_from(&mut buf) {
                    Ok((len, addr)) => {
                        recv_handler.handle(
                            &mut buf[..len],
                            &mut extend,
                            RouteKey::new(ConnectProtocol::UDP, index, addr),
                            &context,
                        );
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        log::error!("main_udp_listen_{}={:?}", index, e);
                    }
                }
            }
        }
    }
}
// /// 用recvmmsg没什么帮助，这里记录下，以下是完整代码
// #[cfg(unix)]
// pub fn main_udp_listen0<H>(index: usize, mut recv_handler: H, context: Context) -> io::Result<()>
//     where
//         H: RecvChannelHandler,
// {
//     use libc::{c_uint, mmsghdr, sockaddr_storage, socklen_t, timespec};
//     use std::os::fd::AsRawFd;
//
//     let udp_socket = context.main_udp_socket[index].try_clone()?;
//     let fd = udp_socket.as_raw_fd();
//     const MAX_MESSAGES: usize = 16;
//     let mut iov: [libc::iovec; MAX_MESSAGES] = unsafe { std::mem::zeroed() };
//     let mut buf: [[u8; BUFFER_SIZE]; MAX_MESSAGES] = [[0; BUFFER_SIZE]; MAX_MESSAGES];
//     let mut msgs: [mmsghdr; MAX_MESSAGES] = unsafe { std::mem::zeroed() };
//     let mut addrs: [sockaddr_storage; MAX_MESSAGES] = unsafe { std::mem::zeroed() };
//     for i in 0..MAX_MESSAGES {
//         iov[i].iov_base = buf[i].as_mut_ptr() as *mut libc::c_void;
//         iov[i].iov_len = BUFFER_SIZE;
//         msgs[i].msg_hdr.msg_iov = &mut iov[i];
//         msgs[i].msg_hdr.msg_iovlen = 1;
//         msgs[i].msg_hdr.msg_name = &mut addrs[i] as *const _ as *mut libc::c_void;
//         msgs[i].msg_hdr.msg_namelen = std::mem::size_of::<sockaddr_storage>() as socklen_t;
//     }
//     let mut time: timespec = unsafe { std::mem::zeroed() };
//     loop {
//         if context.is_stop() {
//             return Ok(());
//         }
//         let res =
//             unsafe { libc::recvmmsg(fd, msgs.as_mut_ptr(), MAX_MESSAGES as c_uint, 0, &mut time) };
//         if res == -1 {
//             log::error!("main_udp_listen_{}={:?}", index, io::Error::last_os_error());
//             continue;
//         }
//
//         let nmsgs = res as usize;
//         for i in 0..nmsgs {
//             let msg = &mut buf[i][0..msgs[i].msg_len as usize];
//             let addr = sockaddr_to_socket_addr(&addrs[i], msgs[i].msg_hdr.msg_namelen);
//             if msg == b"stop" {
//                 if context.is_stop() {
//                     return Ok(());
//                 }
//             }
//             recv_handler.handle(msg, RouteKey::new(false, index, addr), &context);
//         }
//     }
// }
//
// #[cfg(unix)]
// fn sockaddr_to_socket_addr(addr: &libc::sockaddr_storage, _len: libc::socklen_t) -> SocketAddr {
//     match addr.ss_family as libc::c_int {
//         libc::AF_INET => {
//             let addr_in = unsafe { *(addr as *const _ as *const libc::sockaddr_in) };
//             let ip = u32::from_be(addr_in.sin_addr.s_addr);
//             let port = u16::from_be(addr_in.sin_port);
//             SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::from(ip), port))
//         }
//         libc::AF_INET6 => {
//             let addr_in6 = unsafe { *(addr as *const _ as *const libc::sockaddr_in6) };
//             let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
//             let port = u16::from_be(addr_in6.sin6_port);
//             SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))
//         }
//         _ => panic!("Unsupported address family"),
//     }
// }
