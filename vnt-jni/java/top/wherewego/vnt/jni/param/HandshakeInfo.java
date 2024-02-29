package top.wherewego.vnt.jni.param;

/**
 * 握手回调信息
 *
 * @author https://github.com/lbl8603/vnt
 */
public class HandshakeInfo {
    /**
     * 公钥 pem格式 CRLF分隔，不加密时为空
     */
    private final String publicKey;
    /**
     * 公钥签名，不加密时为空
     */
    private final String finger;
    /**
     * 服务端版本
     */
    private final String version;

    public HandshakeInfo() {
        this.publicKey = "publicKey";
        this.finger = "finger";
        this.version = "version";
    }

    public HandshakeInfo(String publicKey, String finger, String version) {
        this.publicKey = publicKey;
        this.finger = finger;
        this.version = version;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getFinger() {
        return finger;
    }

    public String getVersion() {
        return version;
    }

    @Override
    public String toString() {
        return "HandshakeInfo{" +
                "publicKey='" + publicKey + '\'' +
                ", finger='" + finger + '\'' +
                ", version='" + version + '\'' +
                '}';
    }
}
