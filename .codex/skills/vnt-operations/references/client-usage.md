# VNT 客户端程序与配置

## 源码依据与版本核对

当前客户端源码位于 `D:\rust\vnt`。关键来源：

- `README.md`：用户入口和安全说明。
- `Cargo.toml`：程序名称与 feature。
- `src/args_config.rs`：CLI 参数、TOML 字段、默认值和覆盖规则。
- `src/main_cli.rs`、`src/main_ctrl.rs`、`src/main_web.rs`：三个程序的运行行为。
- `.github/workflows/rust.yml`：发行包的实际内容。

发行 zip 包含同一目标平台的 `vnt2_cli`、`vnt2_ctrl`、`vnt2_web`（Windows 带 `.exe`）。桌面安装包是独立的 Tauri 客户端。命令示例在 Windows 上为程序名补 `.exe`；Unix 首次解压后执行 `chmod +x vnt2_*`。

在给出最终命令前优先运行：

```text
vnt2_cli --version
vnt2_cli --help
vnt2_web --help
vnt2_ctrl --help
```

`vnt2_cli --conf-example` 会在当前工作目录写入 `example_config.toml`，仅在用户允许创建该文件时运行。

## 选择程序

| 程序 | 用途 | 关键行为 |
| --- | --- | --- |
| VNT 桌面客户端 | Windows 普通用户 | 图形界面；可按需启用进程内 Web 访问。 |
| `vnt2_web` | 浏览器管理、NAS、无桌面主机、多实例 | 默认监听 `127.0.0.1:19099`；配置存于工作目录的 `vnt_config/`；通过 Bearer token 保护 API。 |
| `vnt2_cli` | 单实例、服务化、脚本化 | 直接传 CLI 参数或用 `--conf` 读取 TOML；TUN/TAP 通常需要管理员/root。 |
| `vnt2_ctrl` | 查询后台 `vnt2_cli` | 支持 `info`、`ips`、`clients`/`list`、`route`，用 `--port` 连接非默认控制端口。 |

最小客户端示例：

```text
vnt2_cli --network-code my-network --server quic://vpn.example.com:29872 --password "shared-network-password"
```

兼容参数 `-k` 也可设置网络编号；新命令优先写清晰的 `--network-code`。同一虚拟网络中的客户端必须使用相同的服务端、网络编号和网络密码。

Web 管理示例：

```text
vnt2_web --addr 127.0.0.1:19099 --token "at-least-16-characters"
```

也可通过 `VNT_WEB_TOKEN` 提供 token。未指定时程序生成随机 token，并在日志中输出带 `?token=` 的访问链接。只有明确需要远程访问时才监听非回环地址；远程访问应配合防火墙或 HTTPS 反向代理。

控制后台 CLI：

```text
vnt2_ctrl info
vnt2_ctrl clients
vnt2_ctrl route
vnt2_ctrl --port 11234 info
```

`ctrl_port = 0` 会禁用控制服务。

## CLI 与配置文件合并

`vnt2_cli --conf path/to/client.toml` 可与 CLI 参数同时使用：

- `Option` 类型参数由显式 CLI 值覆盖文件值。
- 可重复的列表参数在 CLI 非空时覆盖文件列表，否则使用文件列表。
- 布尔开关通常为 CLI `true` 与文件值做启用合并；CLI 不提供通用的“反向关闭文件中 true”能力。
- `network_code` 必填；`server` 在正常组网中也应设置。
- 已删除 `no_tun`；必须迁移到 `device_mode = "no"`、`"tun"` 或 `"tap"`。

不要仅凭本文猜测边界值；使用当前二进制的 `--help` 和源码中的 `FileConfig`/`Args` 核对。

## 推荐 TOML 基线

```toml
config_name = "office-node"
network_code = "my-network"
server = ["quic://vpn.example.com:29872"]

# 同一虚拟网络必须一致；开启后节点间使用端到端加密。
password = "replace-with-a-strong-shared-password"

device_mode = "tun"
device_name = "office-node"

# 自签名服务端建议使用启动日志给出的 SHA-256 指纹。
cert_mode = "finger:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

no_punch = false
no_broadcast = false
rtx = false
compress = false
fec = false
auto_sync_subnet = false
no_nat = false
allow_mapping = false
allow_ikev2 = false
```

不要把示例秘密原样投入生产。`config_name` 是 Web 配置格式支持的展示名；CLI 的 `FileConfig` 会忽略未知字段失败与否应按当前版本验证，给纯 CLI 配置时可省略它。

## 参数速查

### 服务端与直连

- `server = ["quic://host:29872", "tcp://host:29872", "wss://host:29872"]` 可配置多个服务端以容灾。
- `dynamic://domain` 从 DNS TXT 解析；`dynamic://https://...` 接口返回按换行分隔的服务端地址。
- `peer_address` 可重复，接受 `ip:port`、`tcp://ip:port`、`udp://ip:port`。无协议时同时尝试 TCP/UDP，端口必须是对端 `tunnel_port`。
- `no_punch = true` 关闭自动打洞，但显式 `peer_address` 仍可直连。
- `turn = ["目标IP或CIDR,中转虚拟IP"]`。中转填写网关虚拟 IP 时强制服务器中继；命中目标不参与 P2P 打洞。
- `punch_model = ["目标IP或CIDR,IPv4Udp,IPv4Tcp"]` 限制打洞方式。模式为 `IPv4Tcp`、`IPv4Udp`、`IPv6Tcp`、`IPv6Udp`；双方使用允许集合的交集。

### 设备与安全

- `device_mode = "tun"`：三层虚拟网卡，默认模式。
- `device_mode = "tap"`：二层 Ethernet；Windows 需管理员权限并预装 TAP-Windows `tap0901`。
- `device_mode = "no"`：不创建网卡，只提供流量出口和端口映射，通常不需管理员权限。
- Windows TUN 使用随程序提取的 `wintun.dll`；Linux/macOS 使用系统 TUN/TAP 能力。
- `device_id` 同一服务端和网络内不得冲突；缺省时使用机器标识。`device_name` 缺省取 hostname。
- `tunnel_port` 固定 P2P 端口；同机多实例不能使用同一显式端口。
- `outbound_interface` 绑定服务端通信、打洞及转发流量使用的出口网卡。
- `cert_mode = "skip"` 跳过服务端证书验证（默认但不推荐公网生产）；`standard` 使用系统根证书；`finger:<64位hex>` 绑定 SHA-256 指纹。
- `password` 是节点间端到端加密密码，不是 Web token，也不是服务端管理密码。
- `allow_ikev2 = true` 信任服务端注入的 IKEv2 明文 IPv4 流量；仅在确实要与 IKEv2 客户端互通时开启。

### 网络转发与质量

- `input = ["源网段CIDR,目标虚拟IP"]` 将指定网段流量导向出口节点。
- `output = ["真实CIDR"]` 声明本机允许转发的真实网段。
- `subnet_mapping = ["映射CIDR,真实CIDR"]` 做等掩码映射；真实范围必须被 `output` 覆盖。
- `auto_sync_subnet = true` 自动应用在线节点上报的出口子网。
- `no_nat = true` 关闭内置子网 NAT，此时必须另行配置系统转发/NAT。
- `port_mapping = ["tcp://0.0.0.0:81-10.26.0.2-192.168.1.10:80"]` 表示本地监听、目标虚拟节点和最终目标。
- 作为远端端口映射出口的节点必须设置 `allow_mapping = true`。
- `no_broadcast = true` 关闭本机发出的 IPv4 广播和组播转发；ARP、其他二层广播及单播不受影响。
- `rtx` 启用 QUIC 优化通道；`compress` 启用 LZ4；`fec` 用额外带宽换取丢包恢复。根据链路实测启用，不要默认全部开启。
- `mtu` 只在明确诊断到 MTU/分片问题时调整。

## 多实例和验证

Web 端允许多个配置实例，但会拒绝以下冲突：

- 相同服务端范围、相同 `network_code` 且相同 `device_id`；双方都未指定 `device_id` 也可能因机器标识相同而冲突。
- 两个实例显式设置相同 `tunnel_port`。

验证顺序：确认程序版本；确认服务器、网络编号和密码一致；确认实例进入 `Running`；查看分配的虚拟 IP 和节点列表；最后用虚拟 IP `ping` 或真实业务流量验证。ICMP 失败也可能只是主机防火墙阻止 ping。
