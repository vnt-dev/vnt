import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import com.vnt.*;

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
    private ParcelFileDescriptor vpnInterface;

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
        VpnService.Builder builder = new Builder();
        builder.setMtu(1380);
        builder.addAddress(result.getIp(), result.getPrefixLen());
        builder.addRoute("0.0.0.0", 0); // 全局路由
        builder.setSession("VNT VPN");

        // 建立VPN接口，获取文件描述符
        vpnInterface = builder.establish();
        if (vpnInterface == null) {
            throw new VntException("Failed to establish VPN interface");
        }

        int tunFd = vpnInterface.getFd();
        System.out.println("VPN interface established, fd: " + tunFd);

        // 6. 将tunFd传给VNT，启动数据转发
        network.startTun(tunFd);
        System.out.println("VNT started successfully!");

        // 7. 获取API用于查询状态
        VntApi api = network.getApi();

        // 8. 查询网络信息
        VntApi.NetworkInfo networkInfo = api.getNetwork();
        System.out.println("Network info: " + networkInfo);

        // 9. 查询NAT信息
        VntApi.NatInfo natInfo = api.getNatInfo();
        System.out.println("NAT info: " + natInfo);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        // 清理资源
        if (network != null) {
            network.stop();
            network = null;
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            vpnInterface = null;
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
