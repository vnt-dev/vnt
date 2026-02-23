package com.vnt;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

/**
 * VNT网络配置
 *
 * 使用Builder模式构建配置
 */
public class VntConfig {

    private final List<String> servers;
    private final String networkCode;
    private final String password;
    private final String deviceId;
    private final String deviceName;
    private final String tunName;
    private final String ip;
    private final String certMode;
    private final boolean noPunch;
    private final boolean compress;
    private final boolean rtx;
    private final boolean fec;
    private final boolean noNat;
    private final boolean noTun;
    private final Integer mtu;
    private final boolean allowMapping;
    private final List<String> portMapping;
    private final List<String> udpStun;
    private final List<String> tcpStun;

    private VntConfig(Builder builder) {
        this.servers = builder.servers;
        this.networkCode = builder.networkCode;
        this.password = builder.password;
        this.deviceId = builder.deviceId;
        this.deviceName = builder.deviceName;
        this.tunName = builder.tunName;
        this.ip = builder.ip;
        this.certMode = builder.certMode;
        this.noPunch = builder.noPunch;
        this.compress = builder.compress;
        this.rtx = builder.rtx;
        this.fec = builder.fec;
        this.noNat = builder.noNat;
        this.noTun = builder.noTun;
        this.mtu = builder.mtu;
        this.allowMapping = builder.allowMapping;
        this.portMapping = builder.portMapping;
        this.udpStun = builder.udpStun;
        this.tcpStun = builder.tcpStun;
    }

    /**
     * 转换为JSON字符串
     */
    String toJson() {
        JSONObject json = new JSONObject();

        // 必填项
        JSONArray serverArray = new JSONArray();
        for (String server : servers) {
            serverArray.put(server);
        }
        json.put("server", serverArray);
        json.put("network_code", networkCode);

        // 可选项
        if (password != null) json.put("password", password);
        if (deviceId != null) json.put("device_id", deviceId);
        if (deviceName != null) json.put("device_name", deviceName);
        if (tunName != null) json.put("tun_name", tunName);
        if (ip != null) json.put("ip", ip);
        if (certMode != null) json.put("cert_mode", certMode);
        if (mtu != null) json.put("mtu", mtu);

        // 布尔值
        json.put("no_punch", noPunch);
        json.put("compress", compress);
        json.put("rtx", rtx);
        json.put("fec", fec);
        json.put("no_nat", noNat);
        json.put("no_tun", noTun);
        json.put("allow_mapping", allowMapping);

        // 数组
        if (!portMapping.isEmpty()) {
            JSONArray mappingArray = new JSONArray();
            for (String mapping : portMapping) {
                mappingArray.put(mapping);
            }
            json.put("port_mapping", mappingArray);
        }

        if (!udpStun.isEmpty()) {
            JSONArray stunArray = new JSONArray();
            for (String stun : udpStun) {
                stunArray.put(stun);
            }
            json.put("udp_stun", stunArray);
        }

        if (!tcpStun.isEmpty()) {
            JSONArray stunArray = new JSONArray();
            for (String stun : tcpStun) {
                stunArray.put(stun);
            }
            json.put("tcp_stun", stunArray);
        }

        return json.toString();
    }

    /**
     * 配置构建器
     */
    public static class Builder {
        private List<String> servers = new ArrayList<>();
        private String networkCode;
        private String password;
        private String deviceId;
        private String deviceName;
        private String tunName;
        private String ip;
        private String certMode;
        private boolean noPunch = false;
        private boolean compress = false;
        private boolean rtx = false;
        private boolean fec = false;
        private boolean noNat = false;
        private boolean noTun = false;
        private Integer mtu;
        private boolean allowMapping = false;
        private List<String> portMapping = new ArrayList<>();
        private List<String> udpStun = new ArrayList<>();
        private List<String> tcpStun = new ArrayList<>();

        /**
         * 添加服务器地址（必填）
         * @param server 服务器地址，格式：tcp://host:port 或 wss://host:port
         */
        public Builder addServer(String server) {
            this.servers.add(server);
            return this;
        }

        /**
         * 设置网络代码（必填）
         * @param networkCode 组网代码
         */
        public Builder setNetworkCode(String networkCode) {
            this.networkCode = networkCode;
            return this;
        }

        /**
         * 设置密码（可选）
         */
        public Builder setPassword(String password) {
            this.password = password;
            return this;
        }

        /**
         * 设置设备ID（可选，默认自动生成）
         */
        public Builder setDeviceId(String deviceId) {
            this.deviceId = deviceId;
            return this;
        }

        /**
         * 设置设备名称（可选）
         */
        public Builder setDeviceName(String deviceName) {
            this.deviceName = deviceName;
            return this;
        }

        /**
         * 设置TUN设备名称（可选）
         */
        public Builder setTunName(String tunName) {
            this.tunName = tunName;
            return this;
        }

        /**
         * 设置固定IP（可选）
         */
        public Builder setIp(String ip) {
            this.ip = ip;
            return this;
        }

        /**
         * 设置证书验证模式（可选）
         * @param certMode "insecure" | "system" | "embedded"
         */
        public Builder setCertMode(String certMode) {
            this.certMode = certMode;
            return this;
        }

        /**
         * 禁用打洞（默认false）
         */
        public Builder setNoPunch(boolean noPunch) {
            this.noPunch = noPunch;
            return this;
        }

        /**
         * 启用压缩（默认false）
         */
        public Builder setCompress(boolean compress) {
            this.compress = compress;
            return this;
        }

        /**
         * 启用QUIC重传（默认false）
         */
        public Builder setRtx(boolean rtx) {
            this.rtx = rtx;
            return this;
        }

        /**
         * 启用FEC冗余传输（默认false）
         */
        public Builder setFec(boolean fec) {
            this.fec = fec;
            return this;
        }

        /**
         * 禁用NAT（默认false）
         */
        public Builder setNoNat(boolean noNat) {
            this.noNat = noNat;
            return this;
        }

        /**
         * 无TUN模式（默认false）
         */
        public Builder setNoTun(boolean noTun) {
            this.noTun = noTun;
            return this;
        }

        /**
         * 设置MTU（可选，默认1380）
         */
        public Builder setMtu(int mtu) {
            this.mtu = mtu;
            return this;
        }

        /**
         * 允许端口映射（默认false）
         */
        public Builder setAllowMapping(boolean allowMapping) {
            this.allowMapping = allowMapping;
            return this;
        }

        /**
         * 添加端口映射规则（可选）
         * @param mapping 格式：tcp:80->192.168.1.100:8080
         */
        public Builder addPortMapping(String mapping) {
            this.portMapping.add(mapping);
            return this;
        }

        /**
         * 添加UDP STUN服务器（可选）
         */
        public Builder addUdpStun(String stun) {
            this.udpStun.add(stun);
            return this;
        }

        /**
         * 添加TCP STUN服务器（可选）
         */
        public Builder addTcpStun(String stun) {
            this.tcpStun.add(stun);
            return this;
        }

        /**
         * 构建配置对象
         */
        public VntConfig build() {
            if (servers.isEmpty()) {
                throw new IllegalArgumentException("At least one server must be specified");
            }
            if (networkCode == null || networkCode.isEmpty()) {
                throw new IllegalArgumentException("Network code must be specified");
            }
            return new VntConfig(this);
        }
    }
}
