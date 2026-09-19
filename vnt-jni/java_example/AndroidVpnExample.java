import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import com.vnt.*;
import org.json.JSONArray;

/**
 * Android VPN服务示例
 *
 * 演示如何正确使用VNT JNI接口：
 * 1. 创建网络
 * 2. 注册获取IP/掩码
 * 3. 用获取的参数建立Android VPN接口
 * 4. 传入tunFd启动VNT
 */
public class AndroidVpnExample extends VpnService {

    private VntNetwork network;

    /*
     * Subscription setup flow:
     * 1. VntManager.fetchSubscriptionConfig(subscription) and show the returned config in UI.
     * 2. Persist the user's field overrides plus subscription in app-private storage.
     * 3. Create VntConfig with subscription/subscription_revision and persist one
     *    subscription_instance_id for the whole VPN task lifecycle.
     * 4. A Java-owned listener blocks on Rust TUN rebuild events. It rebuilds
     *    one VPN and transfers its detached fd back to the existing network.
     */

    @Override
    public int onStartCommand(android.content.Intent intent, int flags, int startId) {
        try {
            startVpn();
            return START_STICKY;
        } catch (Exception e) {
            e.printStackTrace();
            stopSelf();
            return START_NOT_STICKY;
        }
    }

    private void startVpn() throws Exception {
        // 1. 初始化VNT（全局初始化，只需一次）
        if (!VntManager.init()) {
            throw new VntException("Failed to initialize VNT");
        }

        // 2. 构建配置
        VntConfig config = new VntConfig.Builder()
                .addServer("tcp://101.35.230.139:6660")
                .setNetworkCode("your_network_code")
                .setPassword("123456")
                .setDeviceName("AndroidDevice")
                .setCompress(true)
                .setMtu(1380)
                .build();

        // 3. 创建网络实例
        network = VntManager.createNetwork(config);
        if (network == null) {
            throw new VntException("Failed to create network");
        }

        // 4. 注册网络（连接服务器，获取分配的IP和掩码）
        RegisterResult result = network.register();
        System.out.println("Registration successful: " + result);

        // 5. 使用注册返回的IP和掩码，建立Android VPN接口
        ParcelFileDescriptor initialVpn = establishVpn(result.getIp(), result.getPrefixLen(), 1380, null);
        if (initialVpn == null) {
            throw new VntException("Failed to establish VPN interface");
        }

        int tunFd = initialVpn.detachFd();
        System.out.println("VPN interface established, fd: " + tunFd);

        // 6. 将tunFd传给VNT，启动数据转发
        network.startTun(tunFd);
        System.out.println("VNT started successfully!");
        network.listenTunRebuild(this::replaceVpnForRequest);

        // 7. 获取API用于查询状态
        VntApi api = network.getApi();

        // 8. 查询网络信息
        VntApi.NetworkInfo networkInfo = api.getNetwork();
        System.out.println("Network info: " + networkInfo);

        // 9. 查询NAT信息
        VntApi.NatInfo natInfo = api.getNatInfo();
        System.out.println("NAT info: " + natInfo);
    }

    private ParcelFileDescriptor establishVpn(String ip, int prefixLen, int mtu, JSONArray routes) {
        return establishVpn(ip, prefixLen, mtu, routes, null);
    }

    private ParcelFileDescriptor establishVpn(String ip, int prefixLen, int mtu, JSONArray routes, String sessionName) {
        VpnService.Builder builder = new Builder();
        builder.setMtu(mtu);
        builder.addAddress(ip, prefixLen);
        builder.addRoute("0.0.0.0", 0);
        if (routes != null) {
            for (int index = 0; index < routes.length(); index++) {
                String route = routes.optString(index, "");
                String cidr = route.split(",", 2)[0];
                String[] parts = cidr.split("/", 2);
                if (parts.length == 2) {
                    try {
                        builder.addRoute(parts[0], Integer.parseInt(parts[1]));
                    } catch (RuntimeException ignored) {
                        // Rust validates routes; malformed host data is skipped defensively.
                    }
                }
            }
        }
        builder.setSession(sessionName == null || sessionName.isEmpty() ? "VNT VPN" : sessionName);
        return builder.establish();
    }

    /** Runs on the Java-owned pull listener thread, never from Rust into Java. */
    private void replaceVpnForRequest(TunRebuildRequest request) throws Exception {
        ParcelFileDescriptor replacement;
        try {
            replacement = establishVpn(
                    request.getIp(), request.getPrefixLen(), request.getMtu(), request.getRoutes(), request.getSessionName());
        } catch (Exception error) {
            network.rejectTunRebuild(request.getRequestId(), error.toString());
            return;
        }
        if (replacement == null) {
            network.rejectTunRebuild(request.getRequestId(), "VpnService.Builder.establish returned null");
            return;
        }
        int fd = replacement.detachFd();
        try {
            network.replaceTun(request.getRequestId(), fd);
        } catch (Exception error) {
            // Rust owns a detached fd even on failure and closes it itself.
            throw error;
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        // 清理资源
        if (network != null) {
            network.stop();
            network = null;
        }
        VntManager.destroy();
    }

    /**
     * 查询客户端列表（可在UI线程定期调用）
     */
    public void queryClients() {
        if (network == null) {
            return;
        }

        try {
            VntApi api = network.getApi();
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
