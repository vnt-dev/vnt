package top.wherewego.vnt.jni;

/**
 * 路由信息
 *
 * @author https://github.com/lbl8603/vnt
 */
public class Route {
    /**
     * 是否使用tcp
     */
    private final boolean tcp;
    private final String address;
    private final byte metric;
    private final int rt;


    public Route(boolean tcp, String address, byte metric, int rt) {
        this.tcp = tcp;
        this.address = address;
        this.metric = metric;
        this.rt = rt;
    }

    public boolean isTcp() {
        return tcp;
    }

    public String getAddress() {
        return address;
    }

    public byte getMetric() {
        return metric;
    }

    public int getRt() {
        return rt;
    }

    @Override
    public String toString() {
        return "Route{" +
                "tcp=" + tcp +
                ", address='" + address + '\'' +
                ", metric=" + metric +
                ", rt=" + rt +
                '}';
    }
}
