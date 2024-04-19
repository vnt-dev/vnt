package top.wherewego.vnt.jni;

/**
 * 对端设备信息
 *
 * @author https://github.com/lbl8603/vnt
 */
public class PeerRouteInfo {
    private final int virtualIp;
    private final String name;
    private final String status;
    private final Route route;

    public PeerRouteInfo(int virtualIp, String name, String status, Route route) {
        this.virtualIp = virtualIp;
        this.name = name;
        this.status = status;
        this.route = route;
    }

    public int getVirtualIp() {
        return virtualIp;
    }

    public String getName() {
        return name;
    }

    public String getStatus() {
        return status;
    }

    public Route getRoute() {
        return route;
    }

    @Override
    public String toString() {
        return "PeerDeviceInfo{" +
                "virtualIp=" + IpUtils.intToIpAddress(virtualIp) +
                ", name='" + name + '\'' +
                ", status='" + status + '\'' +
                ", route=" + route +
                '}';
    }
}
