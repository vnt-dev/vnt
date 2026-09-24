import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import com.vnt.*;

import java.util.Collections;
import java.util.List;

/**
 * Android VPN服务示例
 *
 * 演示如何正确使用VNT JNI接口（新版运行期变更流程），用法与 PC 端
 * cli/web 一致，由 native 侧的 RuntimeChangeManager 驱动：
 * createNetwork（创建管理器并启动首个组网实例）→ 建立 VPN 接口 →
 * startTun → nextEvent/applyRuntimeChange 变更循环 → stop。
 * 外部（UI）只通过 {@link #getApi()} 持有查询接口。
 *
 * 订阅连接与组网实例分离：rebuild 时 native 侧只重建组网实例，订阅
 * 连接不断。安卓设备模式下，VPN 接口的地址/MTU/路由在 establish 时确定，
 * 网卡相关变更需要宿主整体重建：nextEvent 的 changed 事件直接携带
 * needsVpnRebuild/needsInstanceRebuild 标志，宿主按标志决定是原地应用
 * 还是先建立新接口再携带 fd 应用。
 */
public class AndroidVpnExample extends VpnService {

    private static final int DEFAULT_MTU = 1380;

    private VntConfig networkConfig;
    /** 组网 worker 线程持有实例；外部通过 {@link #getApi()} 读取查询接口 */
    private volatile VntApi api;
    private volatile boolean running;
    private Thread networkThread;

    /** 当前 VPN 接口使用的 CIDR；快照未携带固定 IP 时沿用（worker 线程内使用） */
    private String establishedCidr;

    /*
     * Subscription setup flow:
     * 1. VntManager.fetchSubscriptionConfig(subscription) and show the returned config in UI.
     * 2. Persist the user's field overrides plus subscription in app-private storage.
     * 3. Create VntConfig with subscription and persist one subscription_instance_id
     *    for the whole VPN task lifecycle.
     * 4. createNetwork blocks until the server pushes the managed identity; local
     *    settings are layered on top automatically.
     */

    @Override
    public int onStartCommand(android.content.Intent intent, int flags, int startId) {
        startVpn();
        return START_STICKY;
    }

    private synchronized void startVpn() {
        if (running) {
            return;
        }
        if (!VntManager.init()) {
            throw new IllegalStateException("Failed to initialize VNT");
        }

        // 本地设置；订阅托管身份（network_code/device_id/ip/设备名）由服务端下发
        networkConfig = new VntConfig.Builder()
                .addServer("tcp://101.35.230.139:6660")
                .setNetworkCode("your_network_code")
                .setPassword("123456")
                .setDeviceName("AndroidDevice")
                .setCompress(true)
                .setMtu(DEFAULT_MTU)
                .build();

        running = true;
        networkThread = new Thread(this::runNetworkLoop, "vnt-network");
        networkThread.start();
    }

    /**
     * 组网主流程（worker 线程）：createNetwork → 取网段信息 → 建立 VPN
     * 接口 → startTun → 变更循环。与 PC 端 cli/web 的流程一致：订阅连接
     * 与组网实例分离，运行期变更（含重建组网实例）都由管理器内部完成，
     * 宿主不需要重新建网。
     */
    private void runNetworkLoop() {
        VntNetwork network = null;
        try {
            // 1. 创建网络实例（订阅模式在此等待服务端下发身份快照）
            network = VntManager.createNetwork(networkConfig);
            if (network == null) {
                throw new VntException("Failed to create network");
            }

            // 2. 等待注册完成，取分配的网段信息
            NetworkResult registered = network.getNetwork();
            establishedCidr = registered.toCidr();

            // 3. 建立 VPN 接口（子网路由先指向 tun）并把 fd 交给 VNT；
            //    完整入站路由由变更循环按快照补齐
            int tunFd = establishVpnInterface(establishedCidr, DEFAULT_MTU, Collections.emptyList());
            network.startTun(tunFd);
            api = network.getApi();
            System.out.println("VNT started: " + establishedCidr);

            // 4. 变更循环：与 cli/web 一致，由 nextEvent 驱动
            runChangeLoop(network);
        } catch (Exception error) {
            error.printStackTrace();
        } finally {
            if (network != null) {
                network.stop();
            }
            api = null;
            // 变更循环结束（实例停止或异常）后允许再次启动
            running = false;
        }
    }

    /**
     * 变更循环：等待运行期事件 → 按快照自带标志应用。与 PC 端 cli/web 的
     * 主循环（nextEvent → applyChange）一致。
     *
     * nextEvent 的 changed 事件携带两个处理标志：
     * - isVpnRebuild：网卡相关信息变化（虚拟 IP/MTU/路由/网卡名），必须
     *   用快照参数重建 VPN 接口并携带新 fd 应用；
     * - isInstanceRebuild：密码/出口网卡等只能重建实例生效的字段，组网
     *   实例由 native 内部重建、订阅连接不断，有设备时同样需要新 fd。
     *
     * 两个标志都为 false 时是纯策略/服务器类变更，原地应用、无需新接口。
     * 实例停止时结束循环（对应 cli 的 InstanceStopped 分支）。
     */
    private void runChangeLoop(VntNetwork network) throws Exception {
        while (running) {
            RuntimeEvent event = network.nextEvent();
            if (event.isInstanceStopped()) {
                System.out.println("组网实例已停止");
                break;
            }
            RuntimeChange change = event.getChange();
            System.out.println("Runtime change received: " + change);

            // 按快照标志决定调用方式：需要新接口时先建立再携带 fd 应用
            ChangeApplyResult result;
            if (change.isVpnRebuild() || change.isInstanceRebuild()) {
                // 快照未携带固定 IP（服务端动态分配）时保持当前接口地址
                String cidr = change.getIp() != null ? change.getIp() : establishedCidr;
                int mtu = change.getMtu() != null ? change.getMtu() : DEFAULT_MTU;
                int tunFd = establishVpnInterface(cidr, mtu, change.getRoutes());
                establishedCidr = cidr;
                result = network.applyRuntimeChange(tunFd);
            } else {
                result = network.applyRuntimeChange();
            }
            if (!result.isApplied()) {
                // 按标志提供 fd 后必定 applied；其余结果仅作防御，结束循环
                System.out.println("Runtime change not applied: " + result);
                break;
            }
            System.out.println("Runtime change applied: " + result);
            // 实例可能被内部重建，刷新对外查询接口（对应 cli 的 ipc.publish）
            refreshApi(network);
        }
    }

    /** 实例可能被内部重建，重新取查询接口（对应 cli 的 ipc.publish）。 */
    private void refreshApi(VntNetwork network) throws VntException {
        api = network.getApi();
    }

    /** 当前实例的查询 API；组网线程在实例重建时自动切换，可能为 null。 */
    public VntApi getApi() {
        return api;
    }

    /** 按参数建立 VPN 接口并返回 detached fd。 */
    private int establishVpnInterface(String cidr, int mtu, List<String> routes) throws Exception {
        String[] cidrParts = cidr.split("/", 2);
        String ip = cidrParts[0];
        int prefixLen = cidrParts.length == 2 ? Integer.parseInt(cidrParts[1]) : 24;

        VpnService.Builder builder = new Builder();
        builder.setMtu(mtu);
        builder.addAddress(ip, prefixLen);
        // Android 的 addAddress 不会自动生成路由，必须显式把虚拟网段指向 tun；
        // 不要加 0.0.0.0/0，否则会劫持整机流量，普通上网请求也会进入 tun。
        builder.addRoute(networkAddress(ip, prefixLen), prefixLen);
        for (String route : routes) {
            String cidrPart = route.split(",", 2)[0];
            String[] parts = cidrPart.split("/", 2);
            if (parts.length == 2) {
                try {
                    builder.addRoute(parts[0], Integer.parseInt(parts[1]));
                } catch (RuntimeException ignored) {
                    // Rust validates routes; malformed host data is skipped defensively.
                }
            }
        }
        builder.setSession("VNT VPN");
        ParcelFileDescriptor vpn = builder.establish();
        if (vpn == null) {
            throw new VntException("VpnService.Builder.establish returned null");
        }
        return vpn.detachFd();
    }

    /** 由 ip/prefixLen 计算所在网段的网络地址，例如 10.26.0.5/24 -> 10.26.0.0。 */
    private static String networkAddress(String ip, int prefixLen) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        }
        long value = 0;
        for (String octet : octets) {
            int part = Integer.parseInt(octet);
            if (part < 0 || part > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
            }
            value = (value << 8) | part;
        }
        long mask = prefixLen <= 0 ? 0L : (0xFFFFFFFFL << (32 - prefixLen)) & 0xFFFFFFFFL;
        value &= mask;
        return ((value >> 24) & 0xFF) + "." + ((value >> 16) & 0xFF) + "."
                + ((value >> 8) & 0xFF) + "." + (value & 0xFF);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        running = false;
        // 注意：worker 若阻塞在 nextEvent，会在下一次事件到达时退出
        // （守护线程，不阻塞进程退出）；nativeStop 已清理 native 资源。
        VntManager.destroy();
    }

    /**
     * 查询客户端列表（可在UI线程定期调用）
     */
    public void queryClients() {
        VntApi api = getApi();
        if (api == null) {
            return;
        }

        try {
            for (VntApi.ClientInfo client : api.getClientList()) {
                System.out.println("Client: " + client);

                // 检查是否直连
                boolean direct = api.isDirect(client.getIp());
                System.out.println("  Direct: " + direct);

                // 获取丢包信息
                VntApi.PacketLossInfo loss = api.getPacketLoss(client.getIp());
                if (loss != null) {
                    System.out.println("  Packet loss: " + loss);
                }

                // 获取流量信息
                VntApi.TrafficInfo traffic = api.getTrafficInfo(client.getIp());
                if (traffic != null) {
                    System.out.println("  Traffic: " + traffic);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
