# Vnt

A virtual network tool (VPN)

将不同网络下的多个设备虚拟到一个局域网下

### vnt-cli参数详解 [参数说明](https://github.com/lbl8603/vnt/blob/main/vnt-cli/README.md)

### 快速使用：

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

      <img width="506" alt="ssh" src="https://raw.githubusercontent.com/lbl8603/vnt/dev/documents/img/ssh.jpg">
5. 帮助，使用-h命令查看

### 更多玩法

1. 和远程桌面(如mstsc)搭配，超低延迟的体验
2. 安装samba服务，共享磁盘
3. 搭配公网服务器nginx反向代理，在公网访问内网文件或服务
4. 点对网,访问内网其他机器、IP代理(结合启动参数'-i'和'-o')

### 使用须知

- token的作用是标识一个虚拟局域网，当使用公共服务器时，建议使用一个唯一值当token(比如uuid)，否则有可能连接到其他人创建的虚拟局域网中
- 默认使用公共服务器做注册和中继，目前的配置是2核4G 4Mbps，有需要再扩展~
- 需要root/管理员权限
- vnt-cli需要使用命令行运行
- Mac和Linux下需要加可执行权限(例如:chmod +x ./vnt-cli)
- 可以自己搭注册和中继服务器([server](https://github.com/lbl8603/vnts))
- vnt使用stun服务器探测网络NAT类型，默认使用谷歌和腾讯的stun服务器，也可自己搭建(-e参数指定)

### 编译

前提条件:安装rust编译环境([install rust](https://www.rust-lang.org/zh-CN/tools/install))

```
到项目根目录下执行 cargo build -p vnt-cli

也可按需编译，将得到更小的二进制文件，使用--no-default-features排除默认features

cargo build -p vnt-cli --no-default-features
```

features说明

| feature          | 说明                   | 是否默认 |
|------------------|----------------------|------|
| openssl          | 使用openssl中的aes_ecb算法 | 否    |
| openssl-vendored | 从源码编译openssl         | 否    |
| ring-cipher      | 使用ring中的aes_gcm算法    | 否    |
| aes_cbc          | 支持aes_cbc加密          | 是    |
| aes_ecb          | 支持aes_ecb加密          | 是    |
| aes_gcm          | 支持aes_gcm加密          | 是    |
| sm4_cbc          | 支持sm4_cbc加密          | 是    |
| server_encrypt   | 支持服务端加密              | 是    |
| ip_proxy         | 内置ip代理               | 是    |

如果编译时去除了内置的ip代理(或使用--no-proxy关闭了代理)，则可以使用网卡NAT转发来实现点对网，
一般来说使用网卡NAT转发会比内置的ip代理性能更好
<details> <summary>NAT配置可参考如下示例,点击展开</summary>

### 在出口一端做如下配置
注意原有的-i(入口)和-o(出口)的参数不能少

### windows
参考 https://learn.microsoft.com/zh-cn/virtualization/hyper-v-on-windows/user-guide/setup-nat-network
```shell
#设置nat,名字可以自己取，网段是vnt的网段
New-NetNat -Name vntnat -InternalIPInterfaceAddressPrefix 10.26.0.0/24
#查看设置
Get-NetNat
```
### linux
```shell
# 开启ip转发
sudo sysctl -w net.ipv4.ip_forward=1
# 开启nat转发  表示来源10.26.0.0/24的数据通过nat映射后再从vnt-tun以外的其他网卡发出去
sudo iptables -t nat -A POSTROUTING ! -o vnt-tun -s 10.26.0.0/24 -j MASQUERADE
# 或者这样  表示来源10.26.0.0/24的数据通过nat映射后再从eth0网卡发出去
sudo iptables -t nat -A POSTROUTING  -o eth0 -s 10.26.0.0/24 -j MASQUERADE
# 查看设置
iptables -vnL -t nat
```

### Arch Linux

[![Packaging status](https://repology.org/badge/vertical-allrepos/vnt.svg)](https://repology.org/project/vnt/versions)

- 通过 AUR 安装 [vnt-git](https://aur.archlinux.org/packages/vnt-git)

```bash
yay -Syu vnt
```

- 通过 `systemd` 设置开机自启及配置

```bash
sudo systemctl enable --now vnt-cli@
sudo systemctl status vnt-cli@
```

- 启用内置 `IPv4` 转发规则

```bash
sudo sysctl --system
```

- 通过内置防火墙文件配置防火墙转发规则

```bash
sudo cat /etc/vnt/iptables-vnt.rules >> /etc/iptables/iptables.rules
sudo iptables-restore iptables.rules
```

### macos
```shell
# 开启ip转发
sudo sysctl -w net.ipv4.ip_forward=1
# 配置NAT转发规则
# 在/etc/pf.conf文件中添加以下规则,en0是出口网卡，10.26.0.0/24是来源网段
nat on en0 from 10.26.0.0/24 to any -> (en0)
# 加载规则
sudo pfctl -f /etc/pf.conf -e
```
</details>

### 支持平台

- Mac
- Linux
    - Arch Linux `yay -Syu vnt`
- Windows
    - 默认使用tun网卡 依赖wintun.dll([win-tun](https://www.wintun.net/))(将dll放到同目录下，建议使用版本0.14.1)
    - 使用tap网卡 依赖tap-windows([win-tap](https://build.openvpn.net/downloads/releases/))(建议使用版本9.24.7)
- Android
    - [VntApp](https://github.com/lbl8603/VntApp)

### 特性

- IP层数据转发
    - tun虚拟网卡
    - tap虚拟网卡
- NAT穿透
    - 点对点穿透
    - 服务端中继转发
    - 客户端中继转发
- IP代理
- p2p组播/广播
- 客户端数据加密
- 服务端数据加密

### 结构

<details> <summary>展开</summary>

<pre>
    
   0                                            15                                              31
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |e |s |unused| 版本(4)  |      协议(8)        |     上层协议(8)        |初始ttl(4)|生存时间(4)  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                        源ip地址(32)                                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                        目的ip地址(32)                                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                          数据体(n)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                                                             |
  |                                          指纹(96)                                           |
  |                                                                                             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  注：
  1. e为是否加密标志，s为服务端通信包标志，unused占两位未使用；
  2. 开启加密时，数据体为加密后的密文(加密方式取决于密码长度和加密模式)，
     且会存在指纹，指纹使用sha256生成，用于对数据包完整性和真实性的校验
</pre>


</details>

### Todo

- 桌面UI(测试中)
- 支持Ipv6(1.2.2已支持客户端之间的ipv6，待支持客户端和服务端之间的ipv6通信)

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
2. 如果p2p后效果很差，可以选择禁用p2p（vnt-cli增加--relay参数）

</details>

### 交流群

QQ: 1034868233

### 其他

可使用社区小伙伴搭建的中继服务器

1. -s vnt.8443.eu.org:29871

### 参与贡献

<a href="https://github.com/lbl8603/vnt/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=lbl8603/vnt" />
</a>
