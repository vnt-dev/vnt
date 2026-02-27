use crate::context::config::Config;
use crate::context::{AppState, NetworkAddr, PacketLossInfo, ServerNodeInfo, TrafficInfo};
use crate::protocol::control_message::ClientSimpleInfo;
use crate::tunnel_core::p2p::route_table::Route;
use crate::tunnel_core::server::rpc::ServerRPC;
use rust_p2p_core::nat::NatInfo;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct VntApi {
    app_state: AppState,
    server_rpc: ServerRPC,
}

impl VntApi {
    pub(crate) fn new(app_state: AppState, server_rpc: ServerRPC) -> Self {
        Self {
            app_state,
            server_rpc,
        }
    }
    pub fn server_rpc(&self) -> &ServerRPC {
        &self.server_rpc
    }
    /// 获取启动配置
    pub fn get_config(&self) -> Option<Box<Config>> {
        self.app_state.get_config()
    }
    /// 获取所有客户端ip
    pub fn client_ips(&self) -> Vec<ClientSimpleInfo> {
        self.app_state.client_ips()
    }
    /// 判断目标IP是否直连
    pub fn is_direct(&self, ip: &Ipv4Addr) -> bool {
        self.app_state.route_table.p2p_num(ip) > 0
    }
    /// 查找路由
    pub fn find_route(&self, ip: &Ipv4Addr) -> Option<Route> {
        self.app_state.route_table.get_route_by_id(ip).ok()
    }
    pub fn get_rtt(&self, ip: &Ipv4Addr) -> Option<u32> {
        if let Some(route) = self.find_route(ip) {
            Some(route.rtt())
        } else {
            self.server_node_rtt(ip).map(|v| v * 2)
        }
    }
    /// 获取所有路由
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.app_state.route_table.route_table()
    }
    /// 获取服务器节点
    pub fn server_node_list(&self) -> Vec<ServerNodeInfo> {
        self.app_state.server_info_collection.server_node_list()
    }
    pub fn server_node_rtt(&self, ip: &Ipv4Addr) -> Option<u32> {
        self.app_state.server_info_collection.get_server_rtt(ip)
    }
    /// 获取网络配置
    pub fn network(&self) -> Option<NetworkAddr> {
        self.app_state.get_network()
    }
    /// 获取当前的nat信息
    pub fn nat_info(&self) -> Option<NatInfo> {
        self.app_state.get_nat_info()
    }
    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.app_state.get_peer_info(ip).and_then(|v| v.nat_info)
    }
    /// 获取指定 IP 的聚合丢包信息（所有路由合并）
    pub fn packet_loss_info(&self, ip: &Ipv4Addr) -> Option<PacketLossInfo> {
        self.app_state
            .packet_loss_stats
            .get_aggregated_loss_info(ip)
    }
    /// 获取指定 IP 的所有路由的丢包信息
    pub fn packet_loss_info_by_routes(&self, ip: &Ipv4Addr) -> Vec<PacketLossInfo> {
        self.app_state.packet_loss_stats.get_loss_info_by_ip(ip)
    }
    pub fn all_packet_loss_info(&self) -> Vec<PacketLossInfo> {
        self.app_state.packet_loss_stats.get_all_loss_info()
    }
    pub fn reset_packet_loss(&self, ip: &Ipv4Addr) {
        // 重置该 IP 的所有路由统计
        for info in self.app_state.packet_loss_stats.get_loss_info_by_ip(ip) {
            if let Some(route_key) = info.route_key {
                self.app_state.packet_loss_stats.reset(ip, &route_key);
            }
        }
    }
    pub fn reset_all_packet_loss(&self) {
        self.app_state.packet_loss_stats.reset_all()
    }
    pub fn traffic_info(&self, ip: &Ipv4Addr) -> Option<TrafficInfo> {
        self.app_state.traffic_stats.get_traffic_info(ip)
    }
    pub fn all_traffic_info(&self) -> Vec<TrafficInfo> {
        self.app_state.traffic_stats.get_all_traffic_info()
    }
    pub fn reset_traffic(&self, ip: &Ipv4Addr) {
        self.app_state.traffic_stats.reset(ip)
    }
    pub fn reset_all_traffic(&self) {
        self.app_state.traffic_stats.reset_all()
    }
}
