use crate::crypto::PacketCrypto;
use crate::protocol::ip_packet_protocol::NetPacket;
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::route_table::{Route, RouteTable};
use bytes::Bytes;
use rust_p2p_core::route::RouteKey;
use rust_p2p_core::tunnel::SocketManager;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub(crate) struct P2pOutbound {
    manager: SocketManager,
    route_table: RouteTable,
    packet_crypto: PacketCrypto,
}
impl P2pOutbound {
    pub fn new(
        manager: SocketManager,
        route_table: RouteTable,
        packet_crypto: PacketCrypto,
    ) -> Self {
        Self {
            manager,
            route_table,
            packet_crypto,
        }
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
        self.manager.send_to(buf.into_buffer(), route_key).await?;
        Ok(())
    }
    pub async fn send_to(
        &self,
        mut buf: NetPacket<TransmissionBytes>,
        route_key: &RouteKey,
    ) -> anyhow::Result<()> {
        self.packet_crypto.encrypt_in_place(&mut buf)?;
        self.manager
            .send_to(buf.into_buffer().into_bytes().freeze(), route_key)
            .await?;
        Ok(())
    }
    pub fn get_route_by_id(&self, id: &Ipv4Addr) -> Option<Route> {
        self.route_table.get_route_by_id(id).ok()
    }
    pub fn get_p2p_route_by_id(&self, id: &Ipv4Addr) -> Option<Route> {
        self.route_table
            .get_route_by_id(id)
            .ok()
            .filter(|v| v.is_direct())
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
                .manager
                .try_send_to(buf.source_buf().clone(), &route.route_key())
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
