package top.wherewego.vnt.jni.param;

/**
 * 网卡信息 仅在 windows/linux/macos上使用
 *
 * @author https://github.com/lbl8603/vnt
 */
public class DeviceInfo {
    /**
     * 虚拟网卡名称
     */
    private final String name;
    /**
     * 虚拟网卡版本
     */
    private final String version;

    public DeviceInfo(String name, String version) {
        this.name = name;
        this.version = version;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    @Override
    public String toString() {
        return "DeviceInfo{" +
                "name='" + name + '\'' +
                ", version='" + version + '\'' +
                '}';
    }
}
