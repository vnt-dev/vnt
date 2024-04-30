use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use mio::net::TcpStream;

use crate::channel::context::ChannelContext;
use crate::channel::idle::{Idle, IdleType};
use crate::channel::sender::AcceptSocketSender;
use crate::handle::callback::{ConnectInfo, ErrorType};
use crate::handle::handshaker::Handshake;
use crate::handle::{BaseConfigInfo, ConnectStatus, CurrentDeviceInfo};
use crate::util::{address_choose, dns_query_all, Scheduler};
use crate::{ErrorInfo, VntCallback};

pub fn idle_route<Call: VntCallback>(
    scheduler: &Scheduler,
    idle: Idle,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    call: Call,
) {
    let delay = idle_route0(&idle, &context, &current_device_info, &call);
    let rs = scheduler.timeout(delay, move |s| {
        idle_route(s, idle, context, current_device_info, call)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

pub fn idle_gateway<Call: VntCallback>(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    config: BaseConfigInfo,
    tcp_socket_sender: AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
    call: Call,
    mut connect_count: usize,
    handshake: Handshake,
) {
    idle_gateway0(
        &context,
        &current_device_info,
        &config,
        &tcp_socket_sender,
        &call,
        &mut connect_count,
        &handshake,
    );
    let rs = scheduler.timeout(Duration::from_secs(5), move |s| {
        idle_gateway(
            s,
            context,
            current_device_info,
            config,
            tcp_socket_sender,
            call,
            connect_count,
            handshake,
        )
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn idle_gateway0<Call: VntCallback>(
    context: &ChannelContext,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    config: &BaseConfigInfo,
    tcp_socket_sender: &AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
    call: &Call,
    connect_count: &mut usize,
    handshake: &Handshake,
) {
    if let Err(e) = check_gateway_channel(
        context,
        current_device,
        config,
        tcp_socket_sender,
        call,
        connect_count,
        handshake,
    ) {
        let cur = current_device.load();
        call.error(ErrorInfo::new_msg(
            ErrorType::Disconnect,
            format!("connect:{},error:{:?}", cur.connect_server, e),
        ));
    }
}

fn idle_route0<Call: VntCallback>(
    idle: &Idle,
    context: &ChannelContext,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    call: &Call,
) -> Duration {
    let cur = current_device.load();
    match idle.next_idle() {
        IdleType::Timeout(ip, route) => {
            log::info!("route Timeout {:?},{:?}", ip, route);
            context.remove_route(&ip, route.route_key());
            if cur.is_gateway(&ip) {
                //网关路由过期，则需要改变状态
                crate::handle::change_status(current_device, ConnectStatus::Connecting);
                call.error(ErrorInfo::new(ErrorType::Disconnect));
            }
            Duration::from_millis(100)
        }
        IdleType::Sleep(duration) => duration,
        IdleType::None => Duration::from_millis(3000),
    }
}

fn check_gateway_channel<Call: VntCallback>(
    context: &ChannelContext,
    current_device_info: &AtomicCell<CurrentDeviceInfo>,
    config: &BaseConfigInfo,
    tcp_socket_sender: &AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
    call: &Call,
    count: &mut usize,
    handshake: &Handshake,
) -> io::Result<()> {
    let mut current_device = current_device_info.load();
    if current_device.status.offline() {
        *count += 1;
        // 探测服务器地址
        current_device = domain_request0(current_device_info, config);
        //需要重连
        call.connect(ConnectInfo::new(*count, current_device.connect_server));
        log::info!("发送握手请求,{:?}", config);
        if let Err(e) = handshake.send(context, config.server_secret, current_device.connect_server)
        {
            log::warn!("{:?}", e);
            if context.is_main_tcp() {
                let request_packet = handshake.handshake_request_packet(config.server_secret)?;
                //tcp需要重连
                let tcp_stream = std::net::TcpStream::connect_timeout(
                    &current_device.connect_server,
                    Duration::from_secs(5),
                )?;
                tcp_stream.set_nonblocking(true)?;
                if let Err(e) = tcp_socket_sender.try_add_socket((
                    TcpStream::from_std(tcp_stream),
                    current_device.connect_server,
                    Some(request_packet.into_buffer()),
                )) {
                    log::warn!("{:?}", e)
                }
            }
        }
    }
    Ok(())
}

pub fn domain_request0(
    current_device: &AtomicCell<CurrentDeviceInfo>,
    config: &BaseConfigInfo,
) -> CurrentDeviceInfo {
    let mut current_dev = current_device.load();

    // 探测服务端地址变化
    match dns_query_all(&config.server_addr, config.name_servers.clone()) {
        Ok(addrs) => {
            log::info!(
                "domain {} dns {:?} addr {:?}",
                config.server_addr,
                config.name_servers,
                addrs
            );

            match address_choose(addrs) {
                Ok(addr) => {
                    if addr != current_dev.connect_server {
                        let mut tmp = current_dev.clone();
                        tmp.connect_server = addr;
                        let rs = current_device.compare_exchange(current_dev, tmp);
                        log::info!(
                            "服务端地址变化,旧地址:{}，新地址:{},替换结果:{}",
                            current_dev.connect_server,
                            addr,
                            rs.is_ok()
                        );
                        if rs.is_ok() {
                            current_dev.connect_server = addr;
                        }
                    }
                }
                Err(e) => {
                    log::error!("域名地址选择失败:{:?},domain={}", e, config.server_addr);
                }
            }
        }
        Err(e) => {
            log::error!("域名解析失败:{:?},domain={}", e, config.server_addr);
        }
    }
    current_dev
}
