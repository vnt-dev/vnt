use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use std::{collections::HashMap, io, net::SocketAddr, thread};

use bytes::{BufMut, BytesMut};
use mio::net::TcpStream;
use mio::{net::TcpListener, Events, Interest, Poll, Registry, Token, Waker};
use parking_lot::Mutex;

use packet::ip::ipv4::packet::IpV4Packet;
use packet::tcp::tcp::TcpPacket;

use crate::ip_proxy::ProxyHandler;
use crate::util::StopManager;

const SERVER_VAL: usize = 0;
const SERVER: Token = Token(SERVER_VAL);
const NOTIFY_VAL: usize = 1;
const NOTIFY: Token = Token(NOTIFY_VAL);

#[derive(Clone)]
pub struct TcpProxy {
    port: u16,
    nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
}

impl TcpProxy {
    pub fn new(stop_manager: StopManager) -> io::Result<Self> {
        let nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(16)));
        let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", 0).parse().unwrap())?;
        let port = tcp_listener.local_addr()?.port();
        {
            let nat_map = nat_map.clone();
            thread::spawn(move || {
                if let Err(e) = tcp_proxy(tcp_listener, nat_map, stop_manager) {
                    log::warn!("tcp_proxy:{:?}", e);
                }
            });
        }
        Ok(Self { port, nat_map })
    }
}

impl ProxyHandler for TcpProxy {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        let dest_ip = ipv4.destination_ip();
        //转发到代理目标地址
        let mut tcp_packet = TcpPacket::new(source, destination, ipv4.payload_mut())?;
        let source_port = tcp_packet.source_port();
        let dest_port = tcp_packet.destination_port();
        tcp_packet.set_destination_port(self.port);
        tcp_packet.update_checksum();
        ipv4.set_destination_ip(destination);
        ipv4.update_checksum();
        let key = SocketAddrV4::new(source, source_port);
        self.nat_map
            .lock()
            .insert(key, SocketAddrV4::new(dest_ip, dest_port));
        Ok(false)
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        let src_ip = ipv4.source_ip();
        let dest_ip = ipv4.destination_ip();
        let dest_addr = {
            let tcp_packet = TcpPacket::new(src_ip, dest_ip, ipv4.payload_mut())?;
            SocketAddrV4::new(dest_ip, tcp_packet.destination_port())
        };
        if let Some(source_addr) = self.nat_map.lock().get(&dest_addr) {
            let source_ip = *source_addr.ip();
            let mut tcp_packet = TcpPacket::new(source_ip, dest_ip, ipv4.payload_mut())?;
            tcp_packet.set_source_port(source_addr.port());
            tcp_packet.update_checksum();
            ipv4.set_source_ip(source_ip);
            ipv4.update_checksum();
        }
        Ok(())
    }
}

fn tcp_proxy(
    mut tcp_listener: TcpListener,
    nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
    stop_manager: StopManager,
) -> io::Result<()> {
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut tcp_listener, SERVER, Interest::READABLE)?;
    let mut events = Events::with_capacity(32);
    let mut tcp_map: HashMap<usize, ProxyValue> = HashMap::with_capacity(16);
    let mut mapping: HashMap<usize, usize> = HashMap::with_capacity(16);
    let stop = Waker::new(poll.registry(), NOTIFY)?;
    let _worker = stop_manager.add_listener("tcp_proxy".into(), move || {
        if let Err(e) = stop.wake() {
            log::warn!("stop tcp_proxy:{:?}", e);
        }
    })?;
    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            match event.token() {
                SERVER => {
                    accept_handle(
                        poll.registry(),
                        &tcp_listener,
                        &nat_map,
                        &mut tcp_map,
                        &mut mapping,
                    );
                }
                NOTIFY => {
                    return Ok(());
                }
                Token(index) => {
                    let (val, src_index) = if let Some(v) = tcp_map.get_mut(&index) {
                        (v, index)
                    } else {
                        if let Some(dest_index) = mapping.get(&index) {
                            if let Some(v) = tcp_map.get_mut(dest_index) {
                                (v, *dest_index)
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    };
                    let (stream1, stream2, buf1, buf2) = val.as_mut(index);
                    if event.is_readable() {
                        if let Err(e) = readable_handle(stream1, stream2, buf1) {
                            log::warn!("tcp proxy {:?}", e);
                            close(src_index, &mut tcp_map, &mut mapping);
                        }
                    } else if event.is_writable() {
                        let read = buf2.len() >= BUF_LEN;
                        if let Err(e) = writable_handle(stream1, buf2) {
                            log::warn!("tcp proxy {:?}", e);
                            close(src_index, &mut tcp_map, &mut mapping);
                        } else if read {
                            if let Err(e) = readable_handle(stream2, stream1, buf2) {
                                log::warn!("tcp proxy {:?}", e);
                                close(src_index, &mut tcp_map, &mut mapping);
                            }
                        }
                    } else {
                        close(src_index, &mut tcp_map, &mut mapping);
                    }
                }
            }
        }
    }
}

fn accept_handle(
    registry: &Registry,
    tcp_listener: &TcpListener,
    nat_map: &Mutex<HashMap<SocketAddrV4, SocketAddrV4>>,
    tcp_map: &mut HashMap<usize, ProxyValue>,
    mapping: &mut HashMap<usize, usize>,
) {
    loop {
        match tcp_listener.accept() {
            Ok((mut src_stream, addr)) => {
                #[cfg(windows)]
                let src_fd = src_stream.as_raw_socket() as usize;
                #[cfg(unix)]
                let src_fd = src_stream.as_raw_fd() as usize;
                if src_fd == SERVER_VAL || src_fd == NOTIFY_VAL {
                    log::error!("fd错误:{:?}", src_fd);
                    continue;
                }
                let addr = match addr {
                    SocketAddr::V4(addr) => addr,
                    SocketAddr::V6(_) => {
                        // 忽略ipv6
                        continue;
                    }
                };
                let _ = src_stream.set_nodelay(false);
                if let Some(dest_addr) = nat_map.lock().get(&addr).cloned() {
                    match tcp_connect(addr.port(), dest_addr.into()) {
                        Ok(mut dest_stream) => {
                            #[cfg(windows)]
                            let dest_fd = dest_stream.as_raw_socket() as usize;
                            #[cfg(unix)]
                            let dest_fd = dest_stream.as_raw_fd() as usize;
                            if dest_fd == SERVER_VAL || dest_fd == NOTIFY_VAL {
                                log::error!("fd错误:{:?}", dest_fd);
                                continue;
                            }
                            if let Err(e) = registry.register(
                                &mut src_stream,
                                Token(src_fd),
                                Interest::READABLE,
                            ) {
                                log::error!("register src_stream:{:?}", e);
                                continue;
                            }
                            if let Err(e) = registry.register(
                                &mut dest_stream,
                                Token(dest_fd),
                                Interest::READABLE,
                            ) {
                                log::error!("register dest_stream:{:?}", e);
                                continue;
                            }
                            tcp_map.insert(
                                src_fd,
                                ProxyValue::new(src_stream, dest_stream, src_fd, dest_fd),
                            );
                            mapping.insert(dest_fd, src_fd);
                        }
                        Err(e) => {
                            log::error!("connect:{:?}", e);
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                log::error!("accept:{:?}", e);
            }
        }
    }
}

fn tcp_connect(src_port: u16, addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if socket
        .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, src_port).into())
        .is_err()
    {
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    }
    socket.set_nonblocking(true)?;
    let _ = socket.set_nodelay(false);
    if let Err(e) = socket.connect(&addr.into()) {
        if e.kind() != io::ErrorKind::WouldBlock {
            return Err(e);
        }
    }
    Ok(TcpStream::from_std(socket.into()))
}

struct ProxyValue {
    src_stream: TcpStream,
    dest_stream: TcpStream,
    src_fd: usize,
    dest_fd: usize,
    src_buf: BytesMut,
    dest_buf: BytesMut,
}

const BUF_LEN: usize = 10 * 4096;

impl ProxyValue {
    fn new(src_stream: TcpStream, dest_stream: TcpStream, src_fd: usize, dest_fd: usize) -> Self {
        Self {
            src_stream,
            dest_stream,
            src_fd,
            dest_fd,
            src_buf: BytesMut::with_capacity(BUF_LEN),
            dest_buf: BytesMut::with_capacity(BUF_LEN),
        }
    }
    fn as_mut(
        &mut self,
        index: usize,
    ) -> (&mut TcpStream, &mut TcpStream, &mut BytesMut, &mut BytesMut) {
        if index == self.src_fd {
            (
                &mut self.src_stream,
                &mut self.dest_stream,
                &mut self.src_buf,
                &mut self.dest_buf,
            )
        } else {
            (
                &mut self.dest_stream,
                &mut self.src_stream,
                &mut self.dest_buf,
                &mut self.src_buf,
            )
        }
    }
}

fn readable_handle(
    stream1: &mut TcpStream,
    stream2: &mut TcpStream,
    mid_buf: &mut BytesMut,
) -> io::Result<()> {
    let mut buf = [0; BUF_LEN];

    loop {
        match stream1.read(&mut buf) {
            Ok(len) => {
                if len == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                let mut buf = &buf[..len];
                if mid_buf.is_empty() {
                    // 直接写入，避免在buf中过渡
                    while !buf.is_empty() {
                        match stream2.write(buf) {
                            Ok(end) => {
                                if end == 0 {
                                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                                }
                                buf = &buf[end..];
                            }
                            Err(e) => {
                                if e.kind() != io::ErrorKind::WouldBlock {
                                    return Err(e);
                                }
                                break;
                            }
                        }
                    }
                    if buf.is_empty() {
                        continue;
                    }
                }
                mid_buf.reserve(buf.len());
                mid_buf.put_slice(buf);
                if mid_buf.len() >= BUF_LEN {
                    // 达到上限不再继续读取
                    return Ok(());
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
    Ok(())
}

fn writable_handle(stream: &mut TcpStream, mid_buf: &mut BytesMut) -> io::Result<()> {
    while !mid_buf.is_empty() {
        match stream.write(&mid_buf) {
            Ok(len) => {
                let _ = mid_buf.split_to(len);
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

fn close(
    index: usize,
    tcp_map: &mut HashMap<usize, ProxyValue>,
    mapping: &mut HashMap<usize, usize>,
) {
    if let Some(val) = tcp_map.remove(&index) {
        let _ = val.src_stream.shutdown(Shutdown::Both);
        let _ = val.dest_stream.shutdown(Shutdown::Both);
        mapping.remove(&val.src_fd);
        mapping.remove(&val.dest_fd);
    }
}
