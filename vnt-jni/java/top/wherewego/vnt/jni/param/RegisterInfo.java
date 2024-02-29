package top.wherewego.vnt.jni.param;

/**
 * 注册回调信息
 *
 * @author https://github.com/lbl8603/vnt
 */
public class RegisterInfo {
    /**
     * 虚拟IP
     */
    public final String virtualIp;
    /**
     * 掩码
     */
    public final String virtualNetmask;
    /**
     * 网关
     */
    public final String virtualGateway;

    public RegisterInfo(String virtualIp, String virtualNetmask, String virtualGateway) {
        this.virtualIp = virtualIp;
        this.virtualNetmask = virtualNetmask;
        this.virtualGateway = virtualGateway;
    }

    public String getVirtualIp() {
        return virtualIp;
    }

    public String getVirtualNetmask() {
        return virtualNetmask;
    }

    public String getVirtualGateway() {
        return virtualGateway;
    }

    @Override
    public String toString() {
        return "RegisterInfo{" +
                "virtualIp='" + virtualIp + '\'' +
                ", virtualNetmask='" + virtualNetmask + '\'' +
                ", virtualGateway='" + virtualGateway + '\'' +
                '}';
    }
}
