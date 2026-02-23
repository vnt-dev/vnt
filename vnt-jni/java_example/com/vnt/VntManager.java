package com.vnt;

/**
 * VNT网络管理器 - 主入口类
 *
 * 使用示例:
 * 1. 初始化: VntManager.init()
 * 2. 创建网络: VntNetwork network = VntManager.createNetwork(config)
 * 3. 注册: RegisterResult result = network.register()
 * 4. (Android端用result的IP/掩码创建VPN接口，获取tunFd)
 * 5. 启动TUN: network.startTun(tunFd)
 * 6. 获取API: VntApi api = network.getApi()
 * 7. 关闭: network.stop()
 */
public class VntManager {

    static {
        // 加载JNI库
        System.loadLibrary("vnt_jni");
    }

    /**
     * 初始化VNT模块（全局初始化，只需调用一次）
     * @return true表示成功，false表示失败
     */
    public static boolean init() {
        return nativeInit();
    }

    /**
     * 销毁VNT模块（全局清理）
     */
    public static void destroy() {
        nativeDestroy();
    }

    /**
     * 创建网络实例
     * @param config 网络配置对象
     * @return VntNetwork实例，失败返回null
     */
    public static VntNetwork createNetwork(VntConfig config) {
        String configJson = config.toJson();
        long handle = nativeCreateNetwork(configJson);
        if (handle < 0) {
            return null;
        }
        return new VntNetwork(handle);
    }

    // ========== Native 方法 ==========

    private static native boolean nativeInit();
    private static native void nativeDestroy();
    private static native long nativeCreateNetwork(String configJson);
}
