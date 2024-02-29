package top.wherewego.vnt.jni.param;

/**
 * 连接信息
 *
 * @author https://github.com/lbl8603/vnt
 */
public class ConnectInfo {
    private final long count;
    private final String address;

    public ConnectInfo(long count, String address) {
        this.count = count;
        this.address = address;
    }

    public long getCount() {
        return count;
    }

    public String getAddress() {
        return address;
    }

    @Override
    public String toString() {
        return "ConnectInfo{" +
                "count=" + count +
                ", address='" + address + '\'' +
                '}';
    }
}
