package top.wherewego.vnt.jni.param;

import top.wherewego.vnt.jni.IpUtils;

import java.util.Arrays;

/**
 * 创建网卡所需信息，仅在android上使用
 *
 * @author https://github.com/lbl8603/vnt
 */
public class DeviceConfig {
    /**
     * 虚拟IP
     */
    public final int virtualIp;
    /**
     * 掩码
     */
    public final int virtualNetmask;
    /**
     * 网关
     */
    public final int virtualGateway;
    /**
     * 虚拟网段
     */
    public final int virtualNetwork;
    /**
     * 额外路由，来自点对网的路由配置
     */
    public final String[] externalRoute;

    public DeviceConfig(int virtualIp, int virtualNetmask, int virtualGateway, int virtualNetwork, String[] externalRoute) {
        this.virtualIp = virtualIp;
        this.virtualNetmask = virtualNetmask;
        this.virtualGateway = virtualGateway;
        this.virtualNetwork = virtualNetwork;
        this.externalRoute = externalRoute;
    }

    public int getVirtualIp() {
        return virtualIp;
    }

    public int getVirtualNetmask() {
        return virtualNetmask;
    }

    public int getVirtualGateway() {
        return virtualGateway;
    }

    public int getVirtualNetwork() {
        return virtualNetwork;
    }

    public String[] getExternalRoute() {
        return externalRoute;
    }

    @Override
    public String toString() {
        return "DeviceConfig{" +
                "virtualIp=" + IpUtils.intToIpAddress(virtualIp) +
                ", virtualNetmask=" + IpUtils.intToIpAddress(virtualNetmask) +
                ", virtualGateway=" + IpUtils.intToIpAddress(virtualGateway) +
                ", virtualNetwork=" + IpUtils.intToIpAddress(virtualNetwork) +
                ", externalRoute=" + Arrays.toString(externalRoute) +
                '}';
    }
}
