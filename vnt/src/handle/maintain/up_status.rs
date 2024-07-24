use crate::channel::context::ChannelContext;
use crate::handle::CurrentDeviceInfo;
use crate::proto::message::{ClientStatusInfo, PunchNatType, RouteItem};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{service_packet, NetPacket, Protocol, HEAD_LEN, MAX_TTL};
use crate::util::Scheduler;
use crossbeam_utils::atomic::AtomicCell;
use protobuf::Message;
use std::io;
use std::sync::Arc;
use std::time::Duration;

/// 上报状态给服务器
pub fn up_status(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
) {
    let _ = scheduler.timeout(Duration::from_secs(60), move |x| {
        up_status0(x, context, current_device_info)
    });
}

fn up_status0(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
) {
    if let Err(e) = send_up_status_packet(&context, &current_device_info) {
        log::warn!("{:?}", e)
    }
    let rs = scheduler.timeout(Duration::from_secs(10 * 60), move |x| {
        up_status0(x, context, current_device_info)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn send_up_status_packet(
    context: &ChannelContext,
    current_device_info: &AtomicCell<CurrentDeviceInfo>,
) -> io::Result<()> {
    let device_info = current_device_info.load();
    if device_info.status.offline() {
        return Ok(());
    }
    let routes = context.route_table.route_table_p2p();
    if routes.is_empty() {
        return Ok(());
    }
    let mut message = ClientStatusInfo::new();
    message.source = device_info.virtual_ip.into();
    for (ip, _) in routes {
        let mut item = RouteItem::new();
        item.next_ip = ip.into();
        message.p2p_list.push(item);
    }
    message.up_stream = context.up_traffic_meter.as_ref().map_or(0, |v| v.total());
    message.down_stream = context.down_traffic_meter.as_ref().map_or(0, |v| v.total());
    message.nat_type = protobuf::EnumOrUnknown::new(if context.is_cone() {
        PunchNatType::Cone
    } else {
        PunchNatType::Symmetric
    });
    let buf = message
        .write_to_bytes()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("up_status_packet {:?}", e)))?;
    let mut net_packet =
        NetPacket::new_encrypt(vec![0; HEAD_LEN + buf.len() + ENCRYPTION_RESERVED])?;
    net_packet.set_default_version();
    net_packet.set_gateway_flag(true);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol_into(service_packet::Protocol::ClientStatusInfo);
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_source(device_info.virtual_ip);
    net_packet.set_destination(device_info.virtual_gateway);
    net_packet.set_payload(&buf)?;
    context.send_default(&net_packet, device_info.connect_server)?;
    Ok(())
}
