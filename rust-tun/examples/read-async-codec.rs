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

use bytes::BytesMut;
use futures::StreamExt;
use packet::{ip::Packet, Error};
use tokio_util::codec::{Decoder, FramedRead};

pub struct IPPacketCodec;

impl Decoder for IPPacketCodec {
    type Item = Packet<BytesMut>;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let buf = buf.split_to(buf.len());
        Ok(match Packet::no_payload(buf) {
            Ok(pkt) => Some(pkt),
            Err(err) => {
                println!("error {:?}", err);
                None
            }
        })
    }
}

#[tokio::main]
async fn main() {
    let mut config = tun::Configuration::default();

    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let dev = tun::create_as_async(&config).unwrap();

    let mut stream = FramedRead::new(dev, IPPacketCodec);

    while let Some(packet) = stream.next().await {
        match packet {
            Ok(pkt) => println!("pkt: {:#?}", pkt),
            Err(err) => panic!("Error: {:?}", err),
        }
    }
}
