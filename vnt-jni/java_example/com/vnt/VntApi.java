package com.vnt;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

/**
 * VNT API接口 - 用于查询网络状态和信息
 *
 * 通过VntNetwork.getApi()获取实例
 */
public class VntApi {

    private final long nativeHandle;

    // 包内构造，只能通过VntNetwork创建
    VntApi(long handle) {
        this.nativeHandle = handle;
    }

    /**
     * 获取客户端列表
     * @return 客户端信息列表
     */
    public List<ClientInfo> getClientList() throws VntException {
        try {
            String json = nativeGetClientList(nativeHandle);
            JSONArray array = new JSONArray(json);
            List<ClientInfo> clients = new ArrayList<>();

            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                clients.add(new ClientInfo(
                        obj.getString("ip"),
                        obj.getBoolean("online")
                ));
            }
            return clients;
        } catch (Exception e) {
            throw new VntException("Failed to get client list: " + e.getMessage(), e);
        }
    }

    /**
     * 获取当前网络配置
     * @return 网络信息，未连接返回null
     */
    public NetworkInfo getNetwork() throws VntException {
        try {
            String json = nativeGetNetwork(nativeHandle);
            if ("null".equals(json)) {
                return null;
            }
            JSONObject obj = new JSONObject(json);
            return new NetworkInfo(
                    obj.getString("ip"),
                    obj.getInt("prefix_len"),
                    obj.getString("gateway"),
                    obj.getString("broadcast")
            );
        } catch (Exception e) {
            throw new VntException("Failed to get network info: " + e.getMessage(), e);
        }
    }

    /**
     * 获取本地NAT信息
     * @return NAT信息，未检测到返回null
     */
    public NatInfo getNatInfo() throws VntException {
        try {
            String json = nativeGetNatInfo(nativeHandle);
            if ("null".equals(json)) {
                return null;
            }
            return NatInfo.fromJson(json);
        } catch (Exception e) {
            throw new VntException("Failed to get NAT info: " + e.getMessage(), e);
        }
    }

    /**
     * 获取服务器节点列表
     * @return 服务器信息列表
     */
    public List<ServerInfo> getServerList() throws VntException {
        try {
            String json = nativeGetServerList(nativeHandle);
            JSONArray array = new JSONArray(json);
            List<ServerInfo> servers = new ArrayList<>();

            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                servers.add(new ServerInfo(
                        obj.getInt("server_id"),
                        obj.getString("server_addr"),
                        obj.getBoolean("connected"),
                        obj.isNull("rtt") ? null : obj.getInt("rtt"),
                        obj.getLong("data_version"),
                        obj.isNull("server_version") ? null : obj.getString("server_version")
                ));
            }
            return servers;
        } catch (Exception e) {
            throw new VntException("Failed to get server list: " + e.getMessage(), e);
        }
    }

    /**
     * 获取路由表
     * @return 路由信息列表
     */
    public List<RouteInfo> getRouteTable() throws VntException {
        try {
            String json = nativeGetRouteTable(nativeHandle);
            JSONArray array = new JSONArray(json);
            List<RouteInfo> routes = new ArrayList<>();

            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                String ip = obj.getString("ip");
                JSONArray routesArray = obj.getJSONArray("routes");

                List<RouteDetail> details = new ArrayList<>();
                for (int j = 0; j < routesArray.length(); j++) {
                    JSONObject route = routesArray.getJSONObject(j);
                    details.add(new RouteDetail(
                            route.getString("route_key"),
                            route.getString("protocol"),
                            route.getInt("metric"),
                            route.getInt("rtt")
                    ));
                }
                routes.add(new RouteInfo(ip, details));
            }
            return routes;
        } catch (Exception e) {
            throw new VntException("Failed to get route table: " + e.getMessage(), e);
        }
    }

    /**
     * 检查目标IP是否直连（P2P）
     * @param ip 目标IP地址
     * @return true表示直连，false表示通过服务器中转
     */
    public boolean isDirect(String ip) {
        return nativeIsDirect(nativeHandle, ip);
    }

    /**
     * 获取对端NAT信息
     * @param ip 目标IP地址
     * @return NAT信息，未知返回null
     */
    public NatInfo getPeerNatInfo(String ip) throws VntException {
        try {
            String json = nativeGetPeerNatInfo(nativeHandle, ip);
            if ("null".equals(json)) {
                return null;
            }
            return NatInfo.fromJson(json);
        } catch (Exception e) {
            throw new VntException("Failed to get peer NAT info: " + e.getMessage(), e);
        }
    }

    /**
     * 获取对端丢包信息
     * @param ip 目标IP地址
     * @return 丢包信息，未知返回null
     */
    public PacketLossInfo getPacketLoss(String ip) throws VntException {
        try {
            String json = nativeGetPacketLoss(nativeHandle, ip);
            if ("null".equals(json)) {
                return null;
            }
            JSONObject obj = new JSONObject(json);
            return new PacketLossInfo(
                    obj.getString("ip"),
                    obj.getLong("sent"),
                    obj.getLong("received"),
                    obj.getDouble("loss_rate")
            );
        } catch (Exception e) {
            throw new VntException("Failed to get packet loss: " + e.getMessage(), e);
        }
    }

    /**
     * 获取对端流量统计
     * @param ip 目标IP地址
     * @return 流量信息，未知返回null
     */
    public TrafficInfo getTrafficInfo(String ip) throws VntException {
        try {
            String json = nativeGetTrafficInfo(nativeHandle, ip);
            if ("null".equals(json)) {
                return null;
            }
            JSONObject obj = new JSONObject(json);
            return new TrafficInfo(
                    obj.getString("ip"),
                    obj.getLong("tx_bytes"),
                    obj.getLong("rx_bytes")
            );
        } catch (Exception e) {
            throw new VntException("Failed to get traffic info: " + e.getMessage(), e);
        }
    }

    // ========== Native 方法 ==========

    private static native String nativeGetClientList(long apiHandle);
    private static native String nativeGetNetwork(long apiHandle);
    private static native String nativeGetNatInfo(long apiHandle);
    private static native String nativeGetServerList(long apiHandle);
    private static native String nativeGetRouteTable(long apiHandle);
    private static native boolean nativeIsDirect(long apiHandle, String ip);
    private static native String nativeGetPeerNatInfo(long apiHandle, String ip);
    private static native String nativeGetPacketLoss(long apiHandle, String ip);
    private static native String nativeGetTrafficInfo(long apiHandle, String ip);

    // ========== 数据类 ==========

    public static class ClientInfo {
        private final String ip;
        private final boolean online;

        public ClientInfo(String ip, boolean online) {
            this.ip = ip;
            this.online = online;
        }

        public String getIp() { return ip; }
        public boolean isOnline() { return online; }

        @Override
        public String toString() {
            return "ClientInfo{ip='" + ip + "', online=" + online + "}";
        }
    }

    public static class NetworkInfo {
        private final String ip;
        private final int prefixLen;
        private final String gateway;
        private final String broadcast;

        public NetworkInfo(String ip, int prefixLen, String gateway, String broadcast) {
            this.ip = ip;
            this.prefixLen = prefixLen;
            this.gateway = gateway;
            this.broadcast = broadcast;
        }

        public String getIp() { return ip; }
        public int getPrefixLen() { return prefixLen; }
        public String getGateway() { return gateway; }
        public String getBroadcast() { return broadcast; }

        @Override
        public String toString() {
            return "NetworkInfo{ip='" + ip + "', prefixLen=" + prefixLen +
                    ", gateway='" + gateway + "', broadcast='" + broadcast + "'}";
        }
    }

    public static class NatInfo {
        private final String natType;
        private final List<String> publicIps;
        private final String ipv6;

        private NatInfo(String natType, List<String> publicIps, String ipv6) {
            this.natType = natType;
            this.publicIps = publicIps;
            this.ipv6 = ipv6;
        }

        static NatInfo fromJson(String json) throws Exception {
            JSONObject obj = new JSONObject(json);
            JSONArray ipsArray = obj.getJSONArray("public_ips");
            List<String> publicIps = new ArrayList<>();
            for (int i = 0; i < ipsArray.length(); i++) {
                publicIps.add(ipsArray.getString(i));
            }
            return new NatInfo(
                    obj.getString("nat_type"),
                    publicIps,
                    obj.isNull("ipv6") ? null : obj.getString("ipv6")
            );
        }

        public String getNatType() { return natType; }
        public List<String> getPublicIps() { return publicIps; }
        public String getIpv6() { return ipv6; }

        @Override
        public String toString() {
            return "NatInfo{natType='" + natType + "', publicIps=" + publicIps +
                    ", ipv6='" + ipv6 + "'}";
        }
    }

    public static class ServerInfo {
        private final int serverId;
        private final String serverAddr;
        private final boolean connected;
        private final Integer rtt;
        private final long dataVersion;
        private final String serverVersion;

        public ServerInfo(int serverId, String serverAddr, boolean connected,
                          Integer rtt, long dataVersion, String serverVersion) {
            this.serverId = serverId;
            this.serverAddr = serverAddr;
            this.connected = connected;
            this.rtt = rtt;
            this.dataVersion = dataVersion;
            this.serverVersion = serverVersion;
        }

        public int getServerId() { return serverId; }
        public String getServerAddr() { return serverAddr; }
        public boolean isConnected() { return connected; }
        public Integer getRtt() { return rtt; }
        public long getDataVersion() { return dataVersion; }
        public String getServerVersion() { return serverVersion; }

        @Override
        public String toString() {
            return "ServerInfo{serverId=" + serverId + ", serverAddr='" + serverAddr +
                    "', connected=" + connected + ", rtt=" + rtt + "}";
        }
    }

    public static class RouteInfo {
        private final String ip;
        private final List<RouteDetail> routes;

        public RouteInfo(String ip, List<RouteDetail> routes) {
            this.ip = ip;
            this.routes = routes;
        }

        public String getIp() { return ip; }
        public List<RouteDetail> getRoutes() { return routes; }

        @Override
        public String toString() {
            return "RouteInfo{ip='" + ip + "', routes=" + routes + "}";
        }
    }

    public static class RouteDetail {
        private final String routeKey;
        private final String protocol;
        private final int metric;
        private final int rtt;

        public RouteDetail(String routeKey, String protocol, int metric, int rtt) {
            this.routeKey = routeKey;
            this.protocol = protocol;
            this.metric = metric;
            this.rtt = rtt;
        }

        public String getRouteKey() { return routeKey; }
        public String getProtocol() { return protocol; }
        public int getMetric() { return metric; }
        public int getRtt() { return rtt; }

        @Override
        public String toString() {
            return "RouteDetail{routeKey='" + routeKey + "', protocol='" + protocol +
                    "', metric=" + metric + ", rtt=" + rtt + "}";
        }
    }

    public static class PacketLossInfo {
        private final String ip;
        private final long sent;
        private final long received;
        private final double lossRate;

        public PacketLossInfo(String ip, long sent, long received, double lossRate) {
            this.ip = ip;
            this.sent = sent;
            this.received = received;
            this.lossRate = lossRate;
        }

        public String getIp() { return ip; }
        public long getSent() { return sent; }
        public long getReceived() { return received; }
        public double getLossRate() { return lossRate; }

        @Override
        public String toString() {
            return "PacketLossInfo{ip='" + ip + "', sent=" + sent +
                    ", received=" + received + ", lossRate=" + lossRate + "}";
        }
    }

    public static class TrafficInfo {
        private final String ip;
        private final long txBytes;
        private final long rxBytes;

        public TrafficInfo(String ip, long txBytes, long rxBytes) {
            this.ip = ip;
            this.txBytes = txBytes;
            this.rxBytes = rxBytes;
        }

        public String getIp() { return ip; }
        public long getTxBytes() { return txBytes; }
        public long getRxBytes() { return rxBytes; }

        @Override
        public String toString() {
            return "TrafficInfo{ip='" + ip + "', txBytes=" + txBytes +
                    ", rxBytes=" + rxBytes + "}";
        }
    }
}
