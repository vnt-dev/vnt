# VNT Desktop

基于 Tauri 2 + Vue 3 的 VNT PC 客户端。桌面端直接内置 `vnt-web` 的服务能力，不需要另行启动 `vnt2_web`。

桌面端与 Web 端共用 `vnt-web/ui/src/` 下的同一套 Vue 应用、路由、状态、组件和样式。`vnt-desktop/src/main.js` 只负责注册 Tauri IPC 桥接，不维护第二套界面代码。

## 功能

- 桌面工作台：总览、实例、在线设备、路由和配置管理
- 多实例启动、停止、重启及启动日志
- 表单 / TOML 双模式配置编辑
- 原生窗口、系统托盘、单实例运行
- 关闭主窗口时隐藏到托盘，托盘菜单可彻底退出
- 深浅主题与 `Ctrl/Cmd + 1~5` 页面快捷键
- 响应式布局：桌面侧栏、移动端顶部栏和抽屉导航
- 桌面工作台通过 Tauri IPC 直接调用进程内 `vnt-core`，不监听本地 API 端口
- 可选 Web 访问：启停、端口、本机/局域网监听范围、访问令牌、打开浏览器
- Web API 强制使用 Bearer 令牌鉴权，令牌可在桌面端重新生成
- 关于页提供 GitHub 开源地址与更新检查；桌面端可通过 Tauri Updater 下载并安装更新

桌面数据存放在系统应用数据目录的 `com.vnt.desktop` 下，包括 `vnt_config`、自启动记录、`web_access.toml`、日志及 Windows 下的 `wintun.dll`。

## 开发

要求：Rust、Node.js、pnpm，以及 Tauri 2 对应的系统依赖。

依赖由仓库根目录的 pnpm workspace 统一管理：

```powershell
pnpm install
pnpm dev:desktop
```

只验证前端：

```powershell
pnpm build:desktop-ui
```

验证 Rust 桌面模块：

```powershell
cargo check -p vnt-desktop
```

## 打包

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY=Get-Content -Raw -LiteralPath "$HOME\.tauri\vnt-desktop.key"
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
pnpm build:desktop
```

Windows 使用虚拟网卡模式时，可能需要以管理员身份运行；TAP（二层）模式还需要预先安装 `tap-windows`（`tap0901`）驱动，内置的 `wintun.dll` 只用于 TUN（三层）模式。

### 发布桌面更新

Tauri Updater 会从以下 GitHub Release 资源检查更新：

```text
https://github.com/vnt-dev/vnt/releases/latest/download/latest.json
```

更新包必须使用与 `tauri.conf.json` 内公钥匹配的私钥签名。当前密钥默认保存在 `~/.tauri/vnt-desktop.key`，请妥善备份并在 CI 中将私钥内容配置为 `TAURI_SIGNING_PRIVATE_KEY`；私钥不得提交到仓库。发布时需将 Tauri 生成的安装包、`.sig` 文件以及对应的 `latest.json` 一并上传到 GitHub Release。

仓库的 Release 流水线会在推送版本标签后自动构建 Windows 桌面安装包及 updater 元数据。请在 GitHub Actions Secrets 中配置 `TAURI_SIGNING_PRIVATE_KEY`；如果私钥设置了密码，同时配置 `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`。流水线还会将桌面安装包和各平台 VNT 工具包的直接下载链接写入 Release Notes。

## 应用图标

图标母版保存在 `vnt-desktop/assets/vnt-icon-master.png`。需要重新生成各平台图标时，在仓库根目录执行：

```powershell
pnpm --filter vnt-desktop tauri icon assets/vnt-icon-master.png --ios-color '#4F46E5'
```
