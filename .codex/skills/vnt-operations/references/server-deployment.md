# VNTS 自建服务端部署

## 源码依据

本机服务端源码在 `D:\rust\vnts`，与客户端项目分开。关键来源：

- `README.md`：功能和前端构建说明。
- `src/main.rs`：启动参数、配置加载、服务组合。
- `src/utils/config.rs`：配置字段、默认值和校验。
- `src/http/web_server.rs`：管理端和热更新行为。
- `.github/workflows/rust.yml`：发行二进制命名与目标架构。

部署前核对当前版本：

```text
vnts2 --version
vnts2 --help
vnts2 --conf-example
```

`--conf-example` 只打印示例；无参数首次启动会在当前工作目录创建 `config.toml`、TLS 证书及运行目录。生产环境应先准备配置再启动服务。

## 获取二进制

优先使用与目标架构匹配的 GitHub Release 单文件二进制，命名形如 `vnts2-x86_64-unknown-linux-musl-v2.0.3`。下载后校验发布页提供的完整性信息并设置执行权限。

从源码构建时，先构建会被嵌入二进制的 Web 前端，再构建 Rust：

```text
cd D:\rust\vnts\frontend
pnpm install --frozen-lockfile
pnpm build
cd D:\rust\vnts
cargo build --release
```

本机原生输出为 `target/release/vnts2`（Windows 为 `.exe`）。面向 Linux 部署时不要把 Windows 构建产物复制到服务器；使用 Linux 构建机、CI 的目标产物或配置正确的交叉编译目标。

## 生产目录布局

使用以下固定布局：

```text
/opt/vnts/vnts2                 只读程序
/var/lib/vnts/config.toml       配置
/var/lib/vnts/network_control.db
/var/lib/vnts/cert.pem
/var/lib/vnts/key.pem
/var/lib/vnts/ikev2-*.pem       可选
/var/lib/vnts/logs/
```

程序的数据库、默认 TLS 证书和日志都相对于工作目录；因此 systemd 的 `WorkingDirectory` 必须固定为 `/var/lib/vnts`。管理 API 会修改 `config.toml` 中的白名单和 IKEv2 配置，因此该文件需由服务用户写入。

创建专用账号和目录的典型命令：

```text
sudo useradd --system --home /var/lib/vnts --shell /usr/sbin/nologin vnts
sudo install -d -o vnts -g vnts -m 0750 /var/lib/vnts
sudo install -d -o root -g root -m 0755 /opt/vnts
sudo install -o root -g root -m 0755 ./vnts2 /opt/vnts/vnts2
sudo install -o vnts -g vnts -m 0640 ./config.toml /var/lib/vnts/config.toml
```

在执行前根据目标发行版确认 `nologin` 路径。升级时不要覆盖数据库或配置目录。

## 配置基线

```toml
# TCP-TLS 与 WSS 相同地址时由同一监听器自动识别协议。
tcp_bind = "0.0.0.0:29872"
quic_bind = "0.0.0.0:29872"
ws_bind = "0.0.0.0:29872"

network = "10.26.0.0/24"
white_list = ["my-network"]
lease_duration = 86400
persistence = true

# 管理端优先只监听本机，由 HTTPS 反向代理或 SSH 隧道访问。
web_bind = "127.0.0.1:29871"
username = "replace-admin"
password = "replace-with-a-long-random-password"

# 留空时在 WorkingDirectory 自动生成自签名证书。
# cert = "/var/lib/vnts/cert.pem"
# key = "/var/lib/vnts/key.pem"

peer_servers = []

[custom_nets]
# special-network = "10.27.0.0/24"
```

配置含义：

- `tcp_bind`、`quic_bind`、`ws_bind` 省略某项即不启用对应传输；三项均缺失会启动失败。
- `network` 是默认虚拟网段。`custom_nets` 可为指定网络编号设置独立网段。
- `white_list = []` 允许任意网络编号；非空时只允许列表中的编号。网络编号不能为空、不能有首尾空白且最多 32 字节。
- `lease_duration` 单位秒。
- `persistence = true` 使用工作目录中的 `network_control.db` 保存网络、设备及互联服务端状态。
- `web_bind` 省略即禁用管理端。绝不在公网保留默认 `admin/admin`。
- `cert` 和 `key` 必须一起设置；省略时生成 `cert.pem`/`key.pem`。服务启动日志输出 `Fingerprint: <64位hex>`，客户端可配置 `cert_mode = "finger:<hex>"`。

服务端互联的所有节点必须使用相同的非默认 `server_token`：

```toml
server_quic_bind = "0.0.0.0:29873"
peer_servers = ["server-b.example.com:29873"]
server_token = "replace-with-a-long-shared-secret"
```

若配置了 peer 或启用了 Web 管理，内部 peer manager 也会建立；不要依赖源码默认的 `default_token` 进行生产互联。

## systemd

写入 `/etc/systemd/system/vnts.service`：

```ini
[Unit]
Description=VNT self-hosted server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vnts
Group=vnts
WorkingDirectory=/var/lib/vnts
ExecStart=/opt/vnts/vnts2 --conf /var/lib/vnts/config.toml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/vnts

[Install]
WantedBy=multi-user.target
```

加载并检查：

```text
sudo systemctl daemon-reload
sudo systemctl enable --now vnts
sudo systemctl status vnts --no-pager
sudo journalctl -u vnts -n 100 --no-pager
```

未启用 IKEv2 时不要授予额外 capability。启用标准 UDP 500/4500 时，为非 root 服务在 `[Service]` 增加：

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

然后 `daemon-reload` 并重启。若发行版或安全策略仍拒绝绑定，先读 journal 和审计日志，不要直接改成 root 长期运行。

## 防火墙与暴露面

按实际启用项开放：

| 端口 | 协议 | 用途 |
| --- | --- | --- |
| 29872 | TCP | VNT TCP-TLS / WSS |
| 29872 | UDP | VNT QUIC |
| 29871 | TCP | Web 管理；优先不向公网开放 |
| 自定义，例 29873 | UDP | 服务端互联 QUIC |
| 500 | UDP | 可选 IKEv2 IKE |
| 4500 | UDP | 可选 IKEv2 NAT-T/ESP 数据面 |

只开放配置中真实绑定的端口。公网管理建议让 `web_bind` 监听回环地址，经 HTTPS 反向代理、VPN 或 SSH 隧道访问；如果直接监听私网地址，也应按管理源 IP 限制防火墙。

## IKEv2（可选）

优先在 Web 管理端“系统设置”配置，再在网络详情中创建设备。配置基线：

```toml
[ikev2]
enabled = true
ike_bind = "0.0.0.0:500"
natt_bind = "0.0.0.0:4500"
remote_id = "vpn.example.com"
public_ip = "203.0.113.10"
dns = ["1.1.1.1"]
# cert/key 同时省略时自动创建本地 CA 和匹配 remote_id 的服务证书。
```

`remote_id` 只接受域名或 IPv4 地址，不能有首尾空白；两个监听地址不能相同。IKEv2 设备使用独立用户名/密码。普通 VNT 客户端只有设置 `allow_ikev2 = true` 才接受该流量；该路径不受 VNT 节点间密码的端到端加密保护。

## 验证

1. `systemctl is-active vnts` 必须为 active。
2. 日志应显示版本、证书指纹、启用的监听器和 `HTTP Server running`（若启用管理端）。
3. 用 `ss -lntup` 对照配置检查端口，不要仅凭进程状态判断。
4. 从管理入口登录并读取网络列表。
5. 客户端使用 `quic://公网名或IP:29872` 连接，网络编号必须满足白名单。
6. 读取客户端实例状态、分配 IP、节点列表和路由，再进行虚拟 IP/业务连通性测试。

## 备份、升级与回滚

备份至少包含 `/var/lib/vnts/config.toml`、`network_control.db`、TLS 证书/私钥和所有 `ikev2-*.pem`。私钥备份必须加密并限制访问。日志通常不作为恢复必需项。

升级流程：记录当前版本和二进制校验值；备份数据；安装为临时新文件；停止服务；原子替换 `/opt/vnts/vnts2`；启动并执行上述验证。保留上一版二进制，失败时停止服务、恢复旧二进制；仅当新版本修改了数据格式且验证失败时，按发布说明决定是否恢复数据库备份，不要在运行中覆盖 SQLite 文件。
