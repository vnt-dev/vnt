use crate::crypto::PacketCrypto;
use crate::protocol::ip_packet_protocol::NetPacket;
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::route_table::{Route, RouteTable};
use bytes::Bytes;
use parking_lot::RwLock;
use rustp2p_core::endpoint::TunnelWriteHalf;
use rustp2p_core::punch::Puncher;
use rustp2p_core::route_table::{Protocol, RouteKey};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct P2pOutbound {
    puncher: Puncher,
    tunnels: Arc<RwLock<HashMap<RouteKey, TunnelWriteHalf>>>,
    route_table: RouteTable,
    packet_crypto: PacketCrypto,
}

impl P2pOutbound {
    pub fn new(puncher: Puncher, route_table: RouteTable, packet_crypto: PacketCrypto) -> Self {
        Self {
            puncher,
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            route_table,
            packet_crypto,
        }
    }

    pub fn register_tunnel(&self, route_key: RouteKey, writer: TunnelWriteHalf) {
        self.tunnels.write().insert(route_key, writer);
    }

    pub fn remove_tunnel(&self, route_key: &RouteKey) {
        self.tunnels.write().remove(route_key);
    }

    fn tunnel(&self, route_key: &RouteKey) -> anyhow::Result<TunnelWriteHalf> {
        self.tunnels
            .read()
            .get(route_key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("tunnel not found for {route_key}"))
    }
    pub fn encrypt_reserve(&self) -> usize {
        self.packet_crypto.encrypt_reserve()
    }
    // pub async fn send_raw(&self, buf: NetPacket<Bytes>) -> anyhow::Result<()> {
    //     let dest_id = Ipv4Addr::from(buf.dest_id());
    //     let route = self.route_table.get_route_by_id(&dest_id)?;
    //     self.manager
    //         .send_to(buf.into_buffer(), &route.route_key())
    //         .await?;
    //     Ok(())
    // }
    // pub async fn send(&self, mut buf: NetPacket<TransmissionBytes>) -> anyhow::Result<()> {
    //     let dest_id = Ipv4Addr::from(buf.dest_id());
    //     let route = self.route_table.get_route_by_id(&dest_id)?;
    //     self.packet_crypto.encrypt_in_place(&mut buf)?;
    //     self.manager
    //         .send_to(buf.into_buffer().into_bytes().freeze(), &route.route_key())
    //         .await?;
    //     Ok(())
    // }
    pub async fn send_raw_to(
        &self,
        buf: NetPacket<Bytes>,
        route_key: &RouteKey,
    ) -> anyhow::Result<()> {
        self.tunnel(route_key)?.send(buf.into_buffer()).await?;
        Ok(())
    }
    pub async fn send_to(
        &self,
        mut buf: NetPacket<TransmissionBytes>,
        route_key: &RouteKey,
    ) -> anyhow::Result<()> {
        self.packet_crypto.encrypt_in_place(&mut buf)?;
        self.tunnel(route_key)?
            .send(buf.into_buffer().into_bytes().freeze())
            .await?;
        Ok(())
    }

    pub fn try_send_to(
        &self,
        mut buf: NetPacket<TransmissionBytes>,
        route_key: &RouteKey,
    ) -> anyhow::Result<()> {
        self.packet_crypto.encrypt_in_place(&mut buf)?;
        self.tunnel(route_key)?
            .try_send(buf.into_buffer().into_bytes().freeze())?;
        Ok(())
    }
    pub async fn send_to_addr(
        &self,
        mut buf: NetPacket<TransmissionBytes>,
        protocol: Protocol,
        address: SocketAddr,
    ) -> anyhow::Result<()> {
        self.packet_crypto.encrypt_in_place(&mut buf)?;
        let bytes = buf.into_buffer().into_bytes().freeze();
        match protocol {
            Protocol::UDP => self.puncher.send_to(&bytes, address)?,
            Protocol::TCP => self.puncher.connect_tcp(address, Some(bytes)).await?,
        }
        Ok(())
    }
    pub fn get_route_by_id(&self, id: &Ipv4Addr) -> Option<Route> {
        self.route_table.get_route_by_id(id).ok()
    }
    pub fn get_p2p_route_by_id(&self, id: &Ipv4Addr) -> Option<Route> {
        self.route_table
            .get_route_by_id(id)
            .ok()
            .filter(|route| route.is_direct())
    }
    pub fn get_direct_route_by_id(&self, id: &Ipv4Addr) -> Option<Route> {
        self.route_table.get_direct_route_by_id(id)
    }
    pub fn exists_route_by_id(&self, id: &Ipv4Addr) -> bool {
        self.route_table.exists(id)
    }

    // pub async fn send_to_id(
    //     &self,
    //     buf: NetPacket<TransmissionBytes>,
    //     id: &Ipv4Addr,
    // ) -> anyhow::Result<bool> {
    //     let Ok(route) = self.route_table.get_route_by_id(id) else {
    //         return Ok(false);
    //     };
    //     self.send_to(buf, &route.route_key()).await?;
    //     Ok(true)
    // }
    // pub fn try_send_to_id(
    //     &self,
    //     buf: NetPacket<TransmissionBytes>,
    //     id: &Ipv4Addr,
    // ) -> anyhow::Result<bool> {
    //     let Ok(route) = self.route_table.get_route_by_id(id) else {
    //         return Ok(false);
    //     };
    //     self.try_send_to(buf, &route.route_key())?;
    //     Ok(true)
    // }
    // pub fn try_send_to(
    //     &self,
    //     buf: NetPacket<TransmissionBytes>,
    //     route_key: &RouteKey,
    // ) -> anyhow::Result<()> {
    //     self.manager
    //         .try_send_to(buf.into_buffer().into_bytes(), route_key)?;
    //     Ok(())
    // }
    pub fn p2p_broadcast(
        &self,
        ips: &[Ipv4Addr],
        max: usize,
        buf: &NetPacket<Bytes>,
    ) -> Vec<Ipv4Addr> {
        let mut list = Vec::with_capacity(ips.len().min(max));

        for id in ips {
            let Some(route) = self.get_p2p_route_by_id(id) else {
                continue;
            };
            if self
                .tunnel(&route.route_key())
                .and_then(|tunnel| Ok(tunnel.try_send(buf.source_buf().clone())?))
                .is_ok()
            {
                list.push(*id);
                if list.len() >= max {
                    break;
                }
            }
        }
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustp2p_core::endpoint::{Config, TunnelIncoming};
    use std::time::Duration;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn registered_writer_supports_send_try_send_and_removal() {
        let mut incoming = TunnelIncoming::bind(Config::udp(0).enable_ipv6(false))
            .await
            .unwrap();
        let target = SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            incoming.local_addr().unwrap().port(),
        );
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"open", target).await.unwrap();

        let tunnel = incoming.next().await.unwrap();
        let route_key = tunnel.route_key();
        let (_reader, writer) = tunnel.split();
        let outbound = P2pOutbound::new(
            incoming.puncher(),
            RouteTable::new(),
            PacketCrypto::new_from_str(None).unwrap(),
        );
        outbound.register_tunnel(route_key, writer);

        outbound
            .tunnel(&route_key)
            .unwrap()
            .send(Bytes::from_static(b"send"))
            .await
            .unwrap();
        let mut buffer = [0; 16];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], b"send");

        outbound
            .tunnel(&route_key)
            .unwrap()
            .try_send(Bytes::from_static(b"try_send"))
            .unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], b"try_send");

        outbound.remove_tunnel(&route_key);
        assert!(outbound.tunnel(&route_key).is_err());
    }
}
