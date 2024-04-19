package top.wherewego.vnt.jni;

import top.wherewego.vnt.jni.param.*;

/**
 * 回调
 *
 * @author https://github.com/lbl8603/vnt
 */
public interface CallBack {
    /**
     * 连接成功的回调
     */
    void success();

    /**
     * 创建虚拟网卡成功的回调方法
     * 仅在 windows/linux/macos上使用
     *
     * @param info 网卡信息
     */
    void createTun(DeviceInfo info);

    /**
     * 连接服务端
     *
     * @param info 将要连接的服务端信息
     */
    void connect(ConnectInfo info);

    /**
     * 和服务端握手
     *
     * @param info 握手信息
     * @return 是否确认握手
     */
    boolean handshake(HandshakeInfo info);

    /**
     * 注册成功回调
     *
     * @param info 注册信息
     * @return 是否确认注册信息
     */
    boolean register(RegisterInfo info);

    /**
     * 创建网卡回调
     * 仅在android上使用
     *
     * @param info 创建配置
     * @return 网卡fd
     */

    int generateTun(DeviceConfig info);

    /**
     * 对端用户列表
     *
     * @param infoArray
     */
    void peerClientList(PeerClientInfo[] infoArray);


    /**
     * 异常回调
     *
     * @param info 错误信息
     */
    void error(ErrorInfo info);

    /**
     * 服务停止
     */
    void stop();

}
