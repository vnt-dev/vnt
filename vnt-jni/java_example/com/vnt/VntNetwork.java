package com.vnt;

import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

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
     * 获取当前网络（网段信息）。
     * createNetwork 时底层已在后台连接服务器并注册：网络已配置则立即返回，
     * 否则等待注册结果返回网段信息。
     * @return 网络信息，包含本机IP、掩码等
     * @throws VntException 获取失败时抛出异常
     */
    public NetworkResult getNetwork() throws VntException {
        checkClosed();
        String resultJson = nativeGetNetwork(nativeHandle);
        return NetworkResult.fromJson(resultJson);
    }

    /**
     * 获取实例最近日志（每个实例保留最后 50 条，按时间正序）。
     * createNetwork 时底层已在后台连接服务器并注册，运行期错误会写入实例日志。
     * @return 日志条目列表
     * @throws VntException 获取失败时抛出异常
     */
    public List<LogEntry> getLogs() throws VntException {
        checkClosed();
        String resultJson = nativeGetLogs(nativeHandle);
        try {
            JSONArray array = new JSONArray(resultJson);
            List<LogEntry> logs = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) {
                logs.add(LogEntry.fromJson(array.getJSONObject(i)));
            }
            return logs;
        } catch (Exception e) {
            throw new VntException("Failed to parse logs: " + e.getMessage(), e);
        }
    }

    /**
     * 启动TUN设备。
     * Android 传入 VpnService.Builder.establish() 返回的 fd；传 -1 表示由
     * VNT 自动创建（仅非 Android 平台支持）。
     * @param tunFd TUN设备文件描述符
     * @throws VntException 启动失败时抛出异常
     */
    public void startTun(int tunFd) throws VntException {
        checkClosed();
        if (!nativeStartTun(nativeHandle, tunFd)) {
            throw new VntException("Failed to start TUN device");
        }
    }

    /**
     * 阻塞等待下一次运行期事件：组网实例停止或新的完整快照。
     * 对应 PC 端 cli/web 主循环的 nextEvent：收到 instance_stopped 时应
     * 结束变更循环，收到 changed 时快照由 {@link #applyRuntimeChange(int)}
     * 消费。
     */
    public RuntimeEvent nextEvent() throws VntException {
        checkClosed();
        return RuntimeEvent.fromJson(nativeNextEvent(nativeHandle));
    }

    /**
     * 应用 nextEvent 返回的最新快照（不携带 TUN fd）：纯策略/服务器类变更
     * 原地生效。快照的 {@link RuntimeChange#isVpnRebuild()} /
     * {@link RuntimeChange#isInstanceRebuild()} 为 true 说明需要新接口，
     * 应改用 {@link #applyRuntimeChange(int)} 携带新建接口的 fd。
     *
     * @return 应用结果：applied / need_fd、rebuild（忽略了需要新接口的标志）
     * @throws VntException 应用失败时抛出异常
     */
    public ChangeApplyResult applyRuntimeChange() throws VntException {
        checkClosed();
        String resultJson = nativeApplyRuntimeChange(nativeHandle);
        return ChangeApplyResult.fromJson(resultJson);
    }

    /**
     * 应用 nextEvent 返回的最新快照，携带宿主新建的 TUN fd：快照的
     * {@link RuntimeChange#isVpnRebuild()} /
     * {@link RuntimeChange#isInstanceRebuild()} 为 true 时使用。携带 fd
     * 且有虚拟网卡时整体重建 fd 型设备（虚拟地址/MTU 以快照为准）；组网
     * 实例由 native 内部重建，订阅连接保持不断。
     *
     * @param tunFd 宿主新建的 TUN fd
     * @return 应用结果：applied / need_fd / rebuild
     * @throws VntException 应用失败时抛出异常
     */
    public ChangeApplyResult applyRuntimeChange(int tunFd) throws VntException {
        checkClosed();
        String resultJson = nativeApplyRuntimeChangeFd(nativeHandle, tunFd);
        return ChangeApplyResult.fromJson(resultJson);
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

    private static native String nativeGetNetwork(long handle);
    private static native String nativeGetLogs(long handle);
    private static native boolean nativeStartTun(long handle, int tunFd);
    private static native String nativeNextEvent(long handle);
    private static native String nativeApplyRuntimeChange(long handle);
    private static native String nativeApplyRuntimeChangeFd(long handle, int tunFd);
    private static native long nativeGetApi(long handle);
    private static native boolean nativeIsNoTun(long handle);
    private static native boolean nativeStop(long handle);
}
