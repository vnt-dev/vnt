package top.wherewego.vnt.jni;

import java.io.Serializable;
import java.util.Arrays;

/**
 * 启动配置
 *
 * @author https://github.com/lbl8603/vnt
 */
public class Config implements Serializable {
    /**
     * 是否是tap模式，仅支持windows
     */
    private boolean tap;
    /**
     * 组网标识
     */
    private String token;
    /**
     * 设备名称
     */
    private String name;
    /**
     * 客户端间加密的密码
     */
    private String password;
    /**
     * 客户端间加密模式 aes_gcm/aes_cbc/aes_ecb/sm4_cbc
     */
    private String cipherModel;
    /**
     * 打洞模式 ipv4/ipv6/all
     */
    private String punchModel;
    /**
     * mtu 默认自动计算
     */
    private Integer mtu;
    /**
     * 是否开启服务端加密
     */
    private boolean serverEncrypt;
    /**
     * 设备id，请使用唯一值
     */
    private String deviceId;
    /**
     * 服务端地址
     */
    private String server;
    /**
     * dns地址
     */
    private String[] dns;
    /**
     * 端口映射
     */
    private String[] portMapping;
    /**
     * stun服务地址
     */
    private String[] stunServer;
    /**
     * 和服务端使用tcp通信，默认使用udp
     */
    private boolean tcp;
    /**
     * 指定组网IP
     */
    private String ip;
    /**
     * 开启加密指纹校验
     */
    private boolean finger;
    /**
     * 延迟优先，默认p2p优先
     */
    private boolean firstLatency;
    /**
     * 点对网入口 格式 192.168.0.0/26,10.26.0.2
     */
    private String[] inIps;
    /**
     * 点对网出口 格式 192.168.0.0/26
     */
    private String[] outIps;
    /**
     * 端口组，udp会监听一组端口，tcp监听ports[0]端口
     */
    private int[] ports;
    /**
     * 虚拟网卡名称 仅在linux、windows、macos上支持
     */
    private String deviceName;
    /**
     * enum: relay/p2p/all
     */
    private String useChannel;
    /**
     * 模拟丢包率，取0~1之间的数，为null表示不丢包，1表示全部丢包
     */
    private Double packetLossRate;
    /**
     * 模拟延迟 单位毫秒(ms)
     */
    private Integer packetDelay;

    public Config() {
    }

    public boolean isTap() {
        return tap;
    }

    public void setTap(boolean tap) {
        this.tap = tap;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCipherModel() {
        return cipherModel;
    }

    public void setCipherModel(String cipherModel) {
        this.cipherModel = cipherModel;
    }

    public String getPunchModel() {
        return punchModel;
    }

    public void setPunchModel(String punchModel) {
        this.punchModel = punchModel;
    }

    public Integer getMtu() {
        return mtu;
    }

    public void setMtu(Integer mtu) {
        this.mtu = mtu;
    }

    public boolean isServerEncrypt() {
        return serverEncrypt;
    }

    public void setServerEncrypt(boolean serverEncrypt) {
        this.serverEncrypt = serverEncrypt;
    }


    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public String[] getDns() {
        return dns;
    }

    public void setDns(String[] dns) {
        this.dns = dns;
    }
    public String[] getPortMapping() {
        return portMapping;
    }

    public void setPortMapping(String[] portMapping) {
        this.portMapping = portMapping;
    }

    public String[] getStunServer() {
        return stunServer;
    }

    public void setStunServer(String[] stunServer) {
        this.stunServer = stunServer;
    }

    public boolean isTcp() {
        return tcp;
    }

    public void setTcp(boolean tcp) {
        this.tcp = tcp;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public boolean isFinger() {
        return finger;
    }

    public void setFinger(boolean finger) {
        this.finger = finger;
    }

    public boolean isFirstLatency() {
        return firstLatency;
    }

    public void setFirstLatency(boolean firstLatency) {
        this.firstLatency = firstLatency;
    }

    public String[] getInIps() {
        return inIps;
    }

    public void setInIps(String[] inIps) {
        this.inIps = inIps;
    }

    public String[] getOutIps() {
        return outIps;
    }

    public void setOutIps(String[] outIps) {
        this.outIps = outIps;
    }

    public int[] getPorts() {
        return ports;
    }

    public void setPorts(int[] ports) {
        this.ports = ports;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    public String getUseChannel() {
        return useChannel;
    }

    public void setUseChannel(String useChannel) {
        this.useChannel = useChannel;
    }

    public Double getPacketLossRate() {
        return packetLossRate;
    }

    public void setPacketLossRate(Double packetLossRate) {
        this.packetLossRate = packetLossRate;
    }

    public Integer getPacketDelay() {
        return packetDelay;
    }

    public void setPacketDelay(Integer packetDelay) {
        this.packetDelay = packetDelay;
    }

    @Override
    public String toString() {
        return "Config{" +
                "tap=" + tap +
                ", token='" + token + '\'' +
                ", name='" + name + '\'' +
                ", password='" + password + '\'' +
                ", cipherModel='" + cipherModel + '\'' +
                ", punchModel='" + punchModel + '\'' +
                ", mtu=" + mtu +
                ", serverEncrypt=" + serverEncrypt +
                ", deviceId='" + deviceId + '\'' +
                ", server='" + server + '\'' +
                ", dns=" + Arrays.toString(dns) +
                ", portMapping=" + Arrays.toString(portMapping) +
                ", stunServer=" + Arrays.toString(stunServer) +
                ", tcp=" + tcp +
                ", ip='" + ip + '\'' +
                ", finger=" + finger +
                ", firstLatency=" + firstLatency +
                ", inIps=" + Arrays.toString(inIps) +
                ", outIps=" + Arrays.toString(outIps) +
                ", ports=" + Arrays.toString(ports) +
                ", deviceName='" + deviceName + '\'' +
                ", useChannel='" + useChannel + '\'' +
                ", packetLossRate=" + packetLossRate +
                ", packetDelay=" + packetDelay +
                '}';
    }
}
