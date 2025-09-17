# VNT

🚀An efficient VPN

🚀一个简单、高效、能快速组建虚拟局域网的工具

### vnt-cli参数详解 [参数说明](https://github.com/vnt-dev/vnt/blob/main/vnt-cli/README.md)

### 快速开始：

1. 指定一个token，在多台设备上运行该程序，例如：
    ```shell
      # linux上
      root@DESKTOP-0BCHNIO:/opt# ./vnt-cli -k 123456
      # 在另一台linux上使用nohup后台运行
      root@izj6cemne76ykdzkataftfz vnt# nohup ./vnt-cli -k 123456 &
      # windows上
      D:\vnt\bin_v1>vnt-cli.exe -k 123456
    ```
2. 可以执行info命令查看当前设备的虚拟ip
   ```shell
    root@DESKTOP-0BCHNIO:/opt# ./vnt-cli --info
    Name: Ubuntu 18.04 (bionic) [64-bit]
    Virtual ip: 10.26.0.2
    Virtual gateway: 10.26.0.1
    Virtual netmask: 255.255.255.0
    Connection status: Connected
    NAT type: Cone
    Relay server: 43.139.56.10:29871
    Public ips: 120.228.76.75
    Local ip: 172.25.165.58
    ```
3. 也可以执行list命令查看其他设备的虚拟ip
   ```shell
    root@DESKTOP-0BCHNIO:/opt# ./vnt-cli --list
    Name                                                       Virtual Ip      P2P/Relay      Rt      Status
    Windows 10.0.22621 (Windows 11 Professional) [64-bit]      10.26.0.3       p2p            2       Online
    CentOS 7.9.2009 (Core) [64-bit]                            10.26.0.4       p2p            35      Online
    ```
4. 最后可以用虚拟ip实现设备间相互访问

      <img width="506" alt="ssh" src="https://raw.githubusercontent.com/vnt-dev/vnt/main/documents/img/ssh.jpg">
5. 帮助，使用-h命令查看

### 使用须知

- token的作用是标识一个虚拟局域网，当使用公共服务器时，建议使用一个唯一值当token(比如uuid)，否则有可能连接到其他人创建的虚拟局域网中
- 默认使用公共服务器做注册和中继，目前的配置是2核4G 4Mbps，有需要再扩展~
- vnt-cli需要使用命令行运行
- Mac和Linux下需要加可执行权限(例如:chmod +x ./vnt-cli)
- 可以自己搭中继服务器([server](https://github.com/vnt-dev/vnts))

### 直接使用

[**下载release文件**](https://github.com/vnt-dev/vnt/releases)

[**帮助文档**](https://rustvnt.com)

### 自行编译

<details> <summary>点击展开</summary>

前提条件:安装rust编译环境([install rust](https://www.rust-lang.org/zh-CN/tools/install))

```
到项目根目录下执行 cargo build -p vnt-cli

也可按需编译，将得到更小的二进制文件，使用--no-default-features排除默认features

cargo build -p vnt-cli --no-default-features
```

features说明

| feature           | 说明                             | 是否默认 |
|-------------------|--------------------------------|------|
| openssl           | 使用openssl中的加密算法                | 否    |
| openssl-vendored  | 从源码编译openssl                   | 否    |
| ring-cipher       | 使用ring中的加密算法                   | 否    |
| aes_cbc           | 支持aes_cbc加密                    | 是    |
| aes_ecb           | 支持aes_ecb加密                    | 是    |
| aes_gcm           | 支持aes_gcm加密                    | 是    |
| sm4_cbc           | 支持sm4_cbc加密                    | 是    |
| chacha20_poly1305 | 支持chacha20和chacha20_poly1305加密 | 是    |
| server_encrypt    | 支持服务端加密                        | 是    |
| ip_proxy          | 内置ip代理                         | 是    |
| port_mapping      | 端口映射                           | 是    |
| log               | 日志                             | 是    |
| command           | list、route等命令                  | 是    |
| file_config       | yaml配置文件                       | 是    |
| lz4               | lz4压缩                          | 是    |
| zstd              | zstd压缩                         | 否    |
| upnp              | upnp协议                         | 否    |
| ws                | ws协议                           | 是    |
| wss               | wss协议                          | 是    |

</details>

### 支持平台

- Mac
- Linux
- Windows
    - 默认使用tun网卡 依赖wintun.dll([win-tun](https://www.wintun.net/))(将dll放到同目录下，建议使用版本0.14.1)
    - 可选择使用tap网卡 依赖tap-windows([win-tap](https://build.openvpn.net/downloads/releases/))(建议使用版本9.24.7)
- Android

### GUI

支持安卓和Windows [下载](https://github.com/vnt-dev/VntApp/releases/)

### 特性

- IP层数据转发
- NAT穿透
    - 点对点穿透
    - 服务端中继转发
    - 客户端中继转发
- IP代理(点对点、点对网)
- p2p组播/广播
- 客户端数据加密(`aes-gcm`、`chacha20-poly1305`等多种加密算法)
- 服务端数据加密(`rsa` + `aes-gcm`)
- 多通道UDP应对QOS
- 支持TCP、UDP、WebSocket等多种协议
- 支持数据压缩

### 更多玩法

1. 和远程桌面(如mstsc)搭配，超低延迟的体验
2. 安装samba服务，共享磁盘
3. 点对网,访问内网其他机器、IP代理(结合启动参数'-i'和'-o')

### Todo

- ~~桌面UI(已支持)~~
- 使用FEC、ARQ等方式提升弱网环境的稳定性

### 常见问题

<details> <summary>展开</summary>

#### 问题1: 设置网络地址失败

##### 可能原因:

vnt默认使用10.26.0.0/24网段，和本地网络适配器的ip冲突

##### 解决方法:

1. 方法一：找到冲突的IP，将其改成别的
2. 方法二：自建服务器，指定其他不会冲突的网段
3. 方法三：增加参数-d <device-id> ，设置不同的id会让服务端分配不同的IP，从而绕开有冲突的IP

#### 问题2: windows系统上wintun.dll加载失败

##### 可能原因：

没有下载wintun.dll 或者使用的wintun.dll有问题

##### 解决方法：

1. 下载最新版的wintun.dll [下载链接](https://www.wintun.net/builds/wintun-0.14.1.zip)
2. 解压后找到对应架构的目录,通常是amd64
3. 将对应的wintun.dll放到和vnt-cli同目录下（或者放到C盘Windows目录下）
4. 再次启动vnt-cli

#### 问题3: 丢包严重，或是不能正常组网通信

##### 可能原因：

某些宽带下(比如广电宽带)UDP丢包严重

##### 解决方法：

1. 使用TCP模式中继转发（vnt-cli增加--tcp参数）
2. 如果p2p后效果很差，可以选择禁用p2p（vnt-cli增加--use-channel relay 参数）

#### 问题4：重启后虚拟IP发生变化，或指定了IP不能启动

##### 可能原因：

设备重启后程序自动获取的id值改变，导致注册时重新分配了新的IP，或是IP冲突

##### 解决方法：

1. 命令行启动增加-d参数（使用配置文件启动则在配置文件中增加device_id参数），要保证每个设备的值都不一样，取值可以任意64位以内字符串

</details>

### 交流群

对VNT有任何问题均可以加群联系作者

QQ群1: 1034868233(满人)

QQ群2: 950473757

QQ群3: 1060550456

### 赞助

如果VNT对你有帮助，欢迎打赏作者

 <img width="300" alt="" src="https://github.com/vnt-dev/vnt/assets/49143209/0d3a7311-43fc-4ed7-9507-863b5d69b6b2">

### 其他

可使用社区小伙伴搭建的中继服务器

1. -s vnt.8443.eu.org:29871
2. -s vnt.wherewego.top:29872

### 参与贡献

<a href="https://github.com/vnt-dev/vnt/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=vnt-dev/vnt" />
</a>
