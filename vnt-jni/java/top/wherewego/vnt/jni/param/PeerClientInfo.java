package top.wherewego.vnt.jni.param;

import top.wherewego.vnt.jni.IpUtils;

/**
 * 创建网卡所需信息，仅在android上使用
 *
 * @author https://github.com/lbl8603/vnt
 */
public class PeerClientInfo {
    /**
     * 虚拟IP
     */
    public final int virtualIp;
    /**
     * 名称
     */
    public final String name;
    /**
     * 是否在线
     */
    public final boolean online;
    /**
     * 是否开启客户端加密，不同加密状态的不能通信
     */
    public final boolean clientSecret;

    public PeerClientInfo(int virtualIp, String name, boolean online, boolean clientSecret) {
        this.virtualIp = virtualIp;
        this.name = name;
        this.online = online;
        this.clientSecret = clientSecret;
    }

    public int getVirtualIp() {
        return virtualIp;
    }

    public String getName() {
        return name;
    }

    public boolean isOnline() {
        return online;
    }

    public boolean isClientSecret() {
        return clientSecret;
    }

    @Override
    public String toString() {
        return "PeerDeviceInfo{" +
                "virtualIp=" + IpUtils.intToIpAddress(virtualIp) +
                ", name='" + name + '\'' +
                ", online=" + online +
                ", clientSecret=" + clientSecret +
                '}';
    }
}
