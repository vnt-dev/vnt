use crate::channel::context::Context;
use crate::channel::idle::{Idle, IdleType};
use crate::channel::sender::AcceptSocketSender;
use crate::handle::callback::{ConnectInfo, ErrorType};
use crate::handle::{handshaker, BaseConfigInfo, CurrentDeviceInfo};
use crate::util::Scheduler;
use crate::{ErrorInfo, VntCallback};
use crossbeam_utils::atomic::AtomicCell;
use mio::net::TcpStream;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub fn idle_route<Call: VntCallback>(
    scheduler: &Scheduler,
    idle: Idle,
    context: Context,
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
    context: Context,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    config: BaseConfigInfo,
    tcp_socket_sender: AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
    call: Call,
    mut connect_count: usize,
) {
    idle_gateway0(
        &context,
        &current_device_info,
        &config,
        &tcp_socket_sender,
        &call,
        &mut connect_count,
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
        )
    });
    if !rs {
        log::info!("定时任务停止");
    }
}
fn idle_gateway0<Call: VntCallback>(
    context: &Context,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    config: &BaseConfigInfo,
    tcp_socket_sender: &AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
    call: &Call,
    connect_count: &mut usize,
) {
    if let Err(e) = check_gateway_channel(
        context,
        current_device,
        config,
        tcp_socket_sender,
        call,
        connect_count,
    ) {
        let cur = current_device.load();
        call.error(ErrorInfo::new_msg(
            ErrorType::Disconnect,
            format!("connect:{},error:{:?}", cur.connect_server, e),
        ));
        log::warn!("{:?}", e);
    }
}
fn idle_route0<Call: VntCallback>(
    idle: &Idle,
    context: &Context,
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
                let cur = context.change_status(current_device);
                if cur.status.offline() {
                    call.error(ErrorInfo::new(ErrorType::Disconnect));
                }
            }
            Duration::from_millis(100)
        }
        IdleType::Sleep(duration) => duration,
        IdleType::None => Duration::from_millis(3000),
    }
}

fn check_gateway_channel<Call: VntCallback>(
    context: &Context,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    config: &BaseConfigInfo,
    tcp_socket_sender: &AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
    call: &Call,
    count: &mut usize,
) -> io::Result<()> {
    let current_device = context.change_status(current_device);
    if current_device.status.offline() {
        *count += 1;
        if *count % 4 == 0 {
            context.change_main_index();
        }
        //需要重连
        call.connect(ConnectInfo::new(*count, current_device.connect_server));
        let request_packet = handshaker::handshake_request_packet(config.client_secret)?;
        log::info!("发送握手请求,{:?}", config);
        if let Err(e) = context.send_default(request_packet.buffer(), current_device.connect_server)
        {
            log::warn!("{:?}", e);
            if context.is_main_tcp() {
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
