use std::thread;
use std::time::Duration;

use crate::channel::context::Context;
use crate::channel::sender::AcceptSocketSender;
use crate::nat;
use crate::nat::NatTest;
use crate::util::Scheduler;

/// 10分钟探测一次nat
pub fn retrieve_nat_type(
    scheduler: &Scheduler,
    context: Context,
    nat_test: NatTest,
    udp_socket_sender: AcceptSocketSender<Option<Vec<mio::net::UdpSocket>>>,
) {
    retrieve_nat_type0(context.clone(), nat_test.clone(), udp_socket_sender.clone());
    scheduler.timeout(Duration::from_secs(60 * 10), move |s| {
        retrieve_nat_type(s, context, nat_test, udp_socket_sender)
    });
}

fn retrieve_nat_type0(
    context: Context,
    nat_test: NatTest,
    udp_socket_sender: AcceptSocketSender<Option<Vec<mio::net::UdpSocket>>>,
) {
    thread::spawn(move || {
        if nat_test.can_update() {
            let local_ipv4 = nat::local_ipv4();
            let local_ipv6 = nat::local_ipv6();
            match nat_test.re_test(local_ipv4, local_ipv6) {
                Ok(nat_info) => {
                    log::info!("当前nat信息:{:?}", nat_info);
                    if let Err(e) = context.switch(nat_info.nat_type, &udp_socket_sender) {
                        log::warn!("{:?}", e);
                    }
                }
                Err(e) => {
                    log::warn!("nat re_test {:?}", e);
                }
            };
        }
    });
}
