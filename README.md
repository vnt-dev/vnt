# VNT

一个简单、高效、能快速组建虚拟局域网的工具

# 快速开始

### 简单说明
1. vnt2_cli 是一个纯命令行组网工具，可以从命令行参数或配置文件快速启动组网
2. vnt2_ctrl 和vnt2_cli搭配使用，vnt2_cli后台运行时，可以用vnt2_ctrl来获取组网状态
3. vnt2_web 是一个集成web服务的组网工具，带web页面，可以在页面上操作组网
4. `vnt-desktop` 是基于 Tauri 2 的 PC 客户端，内置组网服务、桌面工作台和系统托盘

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
2. 从启动日志复制带 `?token=...` 的 Web 访问地址；也可以通过 `--token` 或 `VNT_WEB_TOKEN` 指定固定令牌
3. 在页面上添加组网配置，再启动组网

## 前端构建

web 前端源码位于 `vnt-web/ui/`(Vite + Vue 3 + Pinia + Tailwind CSS v4),构建产物输出到 `vnt-web/static/`,由 RustEmbed 嵌入二进制。

项目使用根级 pnpm workspace 统一管理 Web 与桌面前端依赖：

```
pnpm install
pnpm build:web
```

开发调试使用 `pnpm dev:web`，Vite dev server 会将 `/api` 代理到 `127.0.0.1:19099`。启动 `vnt2_web` 时应指定令牌，并在浏览器登录页输入相同令牌。

## PC 客户端

桌面客户端源码位于 `vnt-desktop/`（Tauri 2 + Vue 3）。桌面工作台通过 Tauri IPC 直接调用进程内 `vnt-core`；需要浏览器访问时，可在“Web 访问”中按需启用同进程 HTTP 服务，无需单独运行 `vnt2_web`。Tauri 与 Web 端统一使用 `vnt-web/ui/src/` 下的同一套响应式前端代码。

```
pnpm install
pnpm dev:desktop
```

构建安装包使用 `pnpm build:desktop`。更多说明见 `vnt-desktop/README.md`。

# VNT2.0新特性

1. 提升安全性，支持tcp-tls、quic、wss协议连接服务器，和服务端强制使用tls加密，并支持证书绑定，防止伪造服务端攻击
2. 提升流量稳定性，支持使用quic代理流量，支持FEC冗余传输
3. 简化操作，去除了大量vnt1.0的重复和无用的配置参数
4. vnt-link、vnt合二为一
5. 支持无网卡、TUN（三层）和 TAP（二层）模式及端口映射；三种模式的 IPv4 流量可互通
6. 全功能的情况下，减少程序体积
7. 性能提升，支持linux-offload
8. 更规范的api接入，可以轻松自定义客户端
9. 支持同时连接多个服务端，可以容灾和负载均衡

## 虚拟网卡模式

配置文件使用 `device_mode = "no|tun|tap"`，默认值为 `tun`；命令行可用 `--device-mode` 覆盖。旧的 `no_tun` 配置已移除，程序会提示迁移而不会静默按 TUN 启动。

- `no`：不创建虚拟网卡，只提供流量出口和端口映射。
- `tun`：创建三层网卡，网卡收发 IPv4 包。
- `tap`：创建二层网卡，完整透传 Ethernet 帧，并与 TUN/NO 节点转换 IPv4、兼容 ARP。

Linux 和 macOS 使用系统提供的 TUN/TAP 能力。Windows 的 TUN 模式使用随程序提供的 `wintun.dll`；TAP 模式需要管理员权限并预先安装 `tap-windows`（硬件 ID `tap0901`）。Android VpnService 仅支持 TUN。

# 说明

vnt2.0整体重构了一遍，和1.0不兼容，同时也可能引入新的bug，欢迎反馈

其他平台后续再推出

### 相关库
1. tun虚拟网卡(https://github.com/tun-rs/tun-rs)
2. 路由设置(https://github.com/tun-rs/route_manager)
3. 用户态协议栈(用于quic代理和无tun模式出口)(https://github.com/rustp2p/tcp_ip)
4. 打洞通道处理(https://github.com/rustp2p/rustp2p/tree/master/rustp2p-core)




