use igd::{search_gateway, PortMappingProtocol};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::Deref;
use std::sync::Arc;

use parking_lot::Mutex;

#[derive(Clone, Default)]
pub struct UPnP {
    inner: Arc<UpnpInner>,
}

impl Deref for UPnP {
    type Target = UpnpInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Default)]
pub struct UpnpInner {
    list: Mutex<Vec<(PortMappingProtocol, u16)>>,
}

impl UpnpInner {
    pub fn add_tcp_port(&self, port: u16) {
        self.list.lock().push((PortMappingProtocol::TCP, port));
    }
    pub fn add_udp_port(&self, port: u16) {
        self.list.lock().push((PortMappingProtocol::UDP, port));
    }
    pub fn reset(&self, local_ip: Ipv4Addr) {
        let gateway = match search_gateway(Default::default()) {
            Ok(gateway) => gateway,
            Err(e) => {
                log::warn!("search_gateway {:?}", e);
                return;
            }
        };
        let guard = self.list.lock();

        // 不支持upnp的情况会阻塞30秒，之后再改这个库
        for (protocol, port) in guard.iter() {
            let local_addr = SocketAddrV4::new(local_ip, *port);
            log::info!("add upnp protocol={} {}", protocol, local_addr);
            if let Err(e) = gateway.add_port(*protocol, *port, local_addr, 700, "upnp") {
                log::warn!(
                    "add upnp failed protocol={},port={} err:{:?}",
                    protocol,
                    port,
                    e
                );
            }
        }
    }
}

impl Drop for UpnpInner {
    fn drop(&mut self) {
        // let gateway = match search_gateway(Default::default()) {
        //     Ok(gateway) => gateway,
        //     Err(e) => {
        //         log::warn!("search_gateway {:?}", e);
        //         return;
        //     }
        // };
        //
        // let guard = self.list.lock();
        // for (protocol, port) in guard.iter() {
        //     if let Err(e) = gateway.remove_port(*protocol, *port) {
        //         log::warn!(
        //             "remove upnp failed protocol={},port={} err:{:?}",
        //             protocol,
        //             port,
        //             e
        //         );
        //     }
        // }
    }
}
