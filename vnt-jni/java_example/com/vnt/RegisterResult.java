package com.vnt;

import org.json.JSONObject;

/**
 * 注册结果
 *
 * 包含服务器分配的IP地址、掩码等信息
 * 注意：如果能创建此对象，说明注册一定成功了（失败会抛异常）
 */
public class RegisterResult {

    private final String ip;
    private final int prefixLen;
    private final String gateway;
    private final String broadcast;

    private RegisterResult(String ip, int prefixLen, String gateway, String broadcast) {
        this.ip = ip;
        this.prefixLen = prefixLen;
        this.gateway = gateway;
        this.broadcast = broadcast;
    }

    /**
     * 从JSON字符串解析注册结果
     * @throws VntException 如果注册失败或解析失败
     */
    static RegisterResult fromJson(String json) throws VntException {
        try {
            JSONObject obj = new JSONObject(json);
            boolean success = obj.getBoolean("success");

            if (success) {
                return new RegisterResult(
                        obj.getString("ip"),
                        obj.getInt("prefix_len"),
                        obj.getString("gateway"),
                        obj.getString("broadcast")
                );
            } else {
                // 注册失败，抛出异常
                String error = obj.getString("error");
                throw new VntException("Registration failed: " + error);
            }
        } catch (VntException e) {
            throw e;  // 重新抛出VntException
        } catch (Exception e) {
            throw new VntException("Failed to parse register result: " + e.getMessage(), e);
        }
    }

    /**
     * 获取分配的IP地址
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

    /**
     * 获取广播地址
     */
    public String getBroadcast() {
        return broadcast;
    }

    /**
     * 转换为CIDR格式字符串（例如：10.0.0.2/24）
     */
    public String toCidr() {
        return ip + "/" + prefixLen;
    }

    @Override
    public String toString() {
        return "RegisterResult{" +
                "ip='" + ip + '\'' +
                ", prefixLen=" + prefixLen +
                ", gateway='" + gateway + '\'' +
                ", broadcast='" + broadcast + '\'' +
                '}';
    }
}
