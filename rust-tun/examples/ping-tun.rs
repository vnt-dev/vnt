//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use futures::{SinkExt, StreamExt};
use packet::{builder::Builder, icmp, ip, Packet};
use tun::{self, Configuration, TunPacket};

#[tokio::main]
async fn main() {
    let mut config = Configuration::default();

    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let dev = tun::create_as_async(&config).unwrap();

    let mut framed = dev.into_framed();

    while let Some(packet) = framed.next().await {
        match packet {
            Ok(pkt) => match ip::Packet::new(pkt.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => match icmp::Packet::new(pkt.payload()) {
                    Ok(icmp) => match icmp.echo() {
                        Ok(icmp) => {
                            let reply = ip::v4::Builder::default()
                                .id(0x42)
                                .unwrap()
                                .ttl(64)
                                .unwrap()
                                .source(pkt.destination())
                                .unwrap()
                                .destination(pkt.source())
                                .unwrap()
                                .icmp()
                                .unwrap()
                                .echo()
                                .unwrap()
                                .reply()
                                .unwrap()
                                .identifier(icmp.identifier())
                                .unwrap()
                                .sequence(icmp.sequence())
                                .unwrap()
                                .payload(icmp.payload())
                                .unwrap()
                                .build()
                                .unwrap();
                            framed.send(TunPacket::new(reply)).await.unwrap();
                        }
                        _ => {}
                    },
                    _ => {}
                },
                Err(err) => println!("Received an invalid packet: {:?}", err),
                _ => {}
            },
            Err(err) => panic!("Error: {:?}", err),
        }
    }
}
