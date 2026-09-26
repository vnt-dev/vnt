package com.vnt;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 最新运行期快照：订阅下发的身份字段 + 完整入站路由。
 *
 * 由 {@link RuntimeEvent#getChange()} 取得；宿主据此决定是否重建 VPN
 * 接口，再由 {@link VntNetwork#applyRuntimeChange(int)} 消费。
 */
public final class RuntimeChange {
    private final String networkCode;
    private final String deviceId;
    private final String deviceName;
    private final String ip;
    private final Integer mtu;
    private final List<String> routes;
    private final boolean needsVpnRebuild;
    private final boolean needsInstanceRebuild;

    private RuntimeChange(String networkCode, String deviceId, String deviceName,
                          String ip, Integer mtu, List<String> routes,
                          boolean needsVpnRebuild, boolean needsInstanceRebuild) {
        this.networkCode = networkCode;
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.ip = ip;
        this.mtu = mtu;
        this.routes = Collections.unmodifiableList(routes);
        this.needsVpnRebuild = needsVpnRebuild;
        this.needsInstanceRebuild = needsInstanceRebuild;
    }

    static RuntimeChange fromJson(JSONObject value) throws VntException {
        try {
            JSONObject config = value.getJSONObject("config");
            JSONArray values = value.getJSONArray("routes");
            List<String> routes = new ArrayList<>(values.length());
            for (int i = 0; i < values.length(); i++) {
                routes.add(values.get(i).toString());
            }
            return new RuntimeChange(
                    config.optString("network_code", ""),
                    config.optString("device_id", ""),
                    config.optString("device_name", ""),
                    config.isNull("ip") ? null : config.getString("ip"),
                    config.isNull("mtu") ? null : config.getInt("mtu"),
                    routes,
                    value.optBoolean("needs_vpn_rebuild", false),
                    value.optBoolean("needs_instance_rebuild", false));
        } catch (Exception error) {
            throw new VntException("Invalid runtime change payload", error);
        }
    }

    /** 网络码（订阅托管时由服务端管理）。 */
    public String getNetworkCode() {
        return networkCode;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getDeviceName() {
        return deviceName;
    }

    /**
     * 本机虚拟 IP（CIDR，例如 {@code 10.26.0.2/24}）；无固定 IP
     * （由服务端注册分配）时为 {@code null}。
     */
    public String getIp() {
        return ip;
    }

    /** 快照携带的 MTU；未携带时为 {@code null}。 */
    public Integer getMtu() {
        return mtu;
    }

    /** 完整入站路由（CIDR,下一跳 格式）。 */
    public List<String> getRoutes() {
        return routes;
    }

    /**
     * 网卡相关信息变化（虚拟 IP/MTU/路由/网卡名）：宿主必须用快照参数
     * 重建 VPN 接口，并携带新 fd 调用
     * {@link VntNetwork#applyRuntimeChange(int)}。无设备模式下恒为 false。
     */
    public boolean isVpnRebuild() {
        return needsVpnRebuild;
    }

    /**
     * 快照包含只能重建组网实例生效的字段（密码/出口网卡等）：宿主无需
     * 额外操作，组网实例由 native 内部重建、订阅连接不断；有设备时同样
     * 需要携带新 fd（与 {@link #isVpnRebuild()} 同样处理）。
     */
    public boolean isInstanceRebuild() {
        return needsInstanceRebuild;
    }

    @Override
    public String toString() {
        return "RuntimeChange{networkCode='" + networkCode + "', deviceId='" + deviceId
                + "', deviceName='" + deviceName + "', ip=" + ip + ", mtu=" + mtu
                + ", routes=" + routes + ", needsVpnRebuild=" + needsVpnRebuild
                + ", needsInstanceRebuild=" + needsInstanceRebuild + '}';
    }
}
