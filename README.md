# VNT

一个简单、高效、能快速组建虚拟局域网的工具

# 快速开始

### 简单说明
1. vnt2_cli 是一个纯命令行组网工具，可以从命令行参数或配置文件快速启动组网
2. vnt2_ctrl 和vnt2_cli搭配使用，vnt2_cli后台运行时，可以用vnt2_ctrl来获取组网状态
3. vnt2_web 是一个集成web服务的组网工具，带web页面，可以在页面上操作组网

## 使用vnt2_cli组网

使用方式和vnt1.0一样，只是增减了一些功能，具体参数请查看 -h
```
# 启动程序 服务端可以使用101.35.230.139:6660
./vnt2_cli -k 123456 -s 101.35.230.139:6660
```

```
# 查看组网信息
./vnt2_ctrl info
```
 
## 使用vnt2_web组网

1. 启动程序

    ```
    # 启动程序
    ./vnt2_web
    ```
2. 浏览器打开 http://127.0.0.1:19099
3. 在页面上添加组网配置，再启动组网


# VNT2.0新特性

1. 提升安全性，支持tcp-tls、quic、wss协议连接服务器，和服务端强制使用tls加密，并支持证书绑定，防止伪造服务端攻击
2. 提升流量稳定性，支持使用quic代理流量，支持FEC冗余传输
3. 简化操作，去除了大量vnt1.0的重复和无用的配置参数
4. vnt-link、vnt合二为一
5. 支持有tun模式、无tun模式、端口映射
6. 全功能的情况下，减少程序体积
7. 性能提升，支持linux-offload
8. 更规范的api接入，可以轻松自定义客户端
9. 支持同时连接多个服务端，可以容灾和负载均衡

# 说明

vnt2.0整体重构了一遍，和1.0不兼容，同时也可能引入新的bug，欢迎反馈

其他平台后续再推出

### 相关库
1. tun虚拟网卡(https://github.com/tun-rs/tun-rs)
2. 路由设置(https://github.com/tun-rs/route_manager)
3. 用户态协议栈(用于quic代理和无tun模式出口)(https://github.com/rustp2p/tcp_ip)
4. 打洞通道处理(https://github.com/rustp2p/rustp2p/tree/master/rustp2p-core)




