package com.vnt;

import org.json.JSONObject;
import org.json.JSONArray;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 当前网络信息（网段）
 *
 * 包含本机在叠加网络中的IP地址、掩码等信息。
 * createNetwork 时底层已在后台连接服务器并注册：网络已配置则立即返回，
 * 否则等待注册结果。注意：如果能创建此对象，说明获取网络一定成功了（失败会抛异常）
 */
public class NetworkResult {

    private final String ip;
    private final int prefixLen;
    private final String gateway;
    private final List<String> routes;

    private NetworkResult(String ip, int prefixLen, String gateway, List<String> routes) {
        this.ip = ip;
        this.prefixLen = prefixLen;
        this.gateway = gateway;
        this.routes = Collections.unmodifiableList(new ArrayList<>(routes));
    }

    /**
     * 从JSON字符串解析网络信息
     * @throws VntException 如果获取失败或解析失败
     */
    static NetworkResult fromJson(String json) throws VntException {
        try {
            JSONObject obj = new JSONObject(json);
            boolean success = obj.getBoolean("success");

            if (success) {
                return fromObject(obj);
            } else {
                // 获取网络失败，抛出异常
                String error = obj.getString("error");
                throw new VntException("Failed to get network: " + error);
            }
        } catch (VntException e) {
            throw e;  // 重新抛出VntException
        } catch (Exception e) {
            throw new VntException("Failed to parse network result: " + e.getMessage(), e);
        }
    }

    static NetworkResult fromObject(JSONObject obj) throws Exception {
        JSONArray values = obj.optJSONArray("routes");
        List<String> routes = new ArrayList<>();
        if (values != null) {
            for (int index = 0; index < values.length(); index++) {
                routes.add(values.getString(index));
            }
        }
        return new NetworkResult(
                obj.getString("ip"),
                obj.getInt("prefix_len"),
                obj.isNull("gateway") ? null : obj.getString("gateway"),
                routes
        );
    }

    /**
     * 获取本机IP地址
     */
    public String getIp() {
        return ip;
    }

    /**
     * 获取前缀长度（掩码位数）
     */
    public int getPrefixLen() {
        return prefixLen;
    }

    /**
     * 获取网关地址
     */
    public String getGateway() {
        return gateway;
    }

    /** 获取规范化后的出口路由。 */
    public List<String> getRoutes() {
        return routes;
    }

    String toJson() throws VntException {
        try {
            return toObject().toString();
        } catch (Exception e) {
            throw new VntException("Failed to serialize network information: " + e.getMessage(), e);
        }
    }

    JSONObject toObject() throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("ip", ip);
        obj.put("prefix_len", prefixLen);
        obj.put("gateway", gateway == null ? JSONObject.NULL : gateway);
        obj.put("routes", new JSONArray(routes));
        return obj;
    }

    /**
     * 转换为CIDR格式字符串（例如：10.0.0.2/24）
     */
    public String toCidr() {
        return ip + "/" + prefixLen;
    }

    @Override
    public String toString() {
        return "NetworkResult{" +
                "ip='" + ip + '\'' +
                ", prefixLen=" + prefixLen +
                ", gateway='" + gateway + '\'' +
                ", routes=" + routes +
                '}';
    }
}
