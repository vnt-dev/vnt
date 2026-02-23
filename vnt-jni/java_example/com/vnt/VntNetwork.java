package com.vnt;

/**
 * VNT网络实例
 *
 * 代表一个VNT网络连接，持有native资源
 */
public class VntNetwork {

    private long nativeHandle;
    private boolean closed = false;

    // 包内构造，只能通过VntManager创建
    VntNetwork(long handle) {
        this.nativeHandle = handle;
    }

    /**
     * 注册网络（连接服务器）
     * @return 注册结果，包含分配的IP、掩码等信息
     * @throws VntException 注册失败时抛出异常
     */
    public RegisterResult register() throws VntException {
        checkClosed();
        String resultJson = nativeRegister(nativeHandle);
        return RegisterResult.fromJson(resultJson);
    }

    /**
     * 启动TUN设备
     * @param tunFd TUN设备文件描述符（Android VpnService.Builder.establish()返回的fd）
     *              传入-1表示让VNT自动创建（仅非Android平台支持）
     * @throws VntException 启动失败时抛出异常
     */
    public void startTun(int tunFd) throws VntException {
        checkClosed();
        if (!nativeStartTun(nativeHandle, tunFd)) {
            throw new VntException("Failed to start TUN device");
        }
    }

    /**
     * 设置网络IP（仅非Android平台使用）
     * @param ip IP地址
     * @param prefixLen 前缀长度
     * @throws VntException 设置失败时抛出异常
     */
    public void setNetworkIp(String ip, int prefixLen) throws VntException {
        checkClosed();
        if (!nativeSetNetworkIp(nativeHandle, ip, prefixLen)) {
            throw new VntException("Failed to set network IP");
        }
    }

    /**
     * 获取VNT API实例
     * @return VntApi实例
     * @throws VntException 获取失败时抛出异常
     */
    public VntApi getApi() throws VntException {
        checkClosed();
        long apiHandle = nativeGetApi(nativeHandle);
        if (apiHandle < 0) {
            throw new VntException("Failed to get VntApi");
        }
        return new VntApi(apiHandle);
    }

    /**
     * 检查是否为无TUN模式
     * @return true表示无TUN模式
     */
    public boolean isNoTun() {
        checkClosed();
        return nativeIsNoTun(nativeHandle);
    }

    /**
     * 停止并关闭网络
     */
    public void stop() {
        if (closed) {
            return;
        }
        nativeStop(nativeHandle);
        closed = true;
    }

    /**
     * 获取native句柄（供内部使用）
     */
    long getNativeHandle() {
        return nativeHandle;
    }

    /**
     * 检查是否已关闭
     */
    private void checkClosed() {
        if (closed) {
            throw new IllegalStateException("VntNetwork has been closed");
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            stop();
        } finally {
            super.finalize();
        }
    }

    // ========== Native 方法 ==========

    private static native String nativeRegister(long handle);
    private static native boolean nativeStartTun(long handle, int tunFd);
    private static native boolean nativeSetNetworkIp(long handle, String ip, int prefixLen);
    private static native long nativeGetApi(long handle);
    private static native boolean nativeIsNoTun(long handle);
    private static native boolean nativeStop(long handle);
}
