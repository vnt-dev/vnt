# VNT 客户端 Web API

## 连接与鉴权

本接口由独立 `vnt2_web` 或桌面端启用的 Web 访问提供。独立程序默认地址是 `http://127.0.0.1:19099`。

若用户未提供访问数据，询问完整访问链接（通常包含 `?token=...`），或分别询问 API 根地址和 token。完整链接的查询参数只用于提取 token，API 请求必须改为：

```text
Authorization: Bearer <token>
```

不要继续把 token 放在请求 URL 中。先请求：

```text
GET /api/version
GET /api/runtime
```

`runtime` 当前可能返回 `standalone_web` 或 `desktop_web`。所有业务响应采用：

```json
{"code": 0, "msg": "success", "data": {}}
```

HTTP 2xx 不等于业务成功；只有 `code == 0` 才成功。`401` 表示 Web token 不正确或已变化，只重新获取/重试一次。

通用辅助脚本示例（从 stdin 输入带 token 的完整链接）：

```text
python scripts/vnt_api.py client --access-url-stdin GET /api/version
python scripts/vnt_api.py client --access-url-stdin GET /api/instances
```

脚本路径相对于本 skill 目录。若调用环境不方便重复输入，可将链接放入临时进程环境变量并用 `--access-url-env`；不要写入仓库文件。

## 接口目录

| 方法 | 路径 | 用途 | 输入 |
| --- | --- | --- | --- |
| GET | `/api/version` | 程序版本 | 无 |
| GET | `/api/runtime` | 运行形态 | 无 |
| GET | `/api/instances` | 所有实例 | 无 |
| GET | `/api/start/status?file_name=...` | 启动状态和日志 | 配置文件名 |
| GET | `/api/info?file_name=...` | 实例综合状态 | 配置文件名 |
| GET | `/api/peers?file_name=...` | 节点列表 | 配置文件名 |
| GET | `/api/routes?file_name=...` | 路由列表 | 配置文件名 |
| POST | `/api/start` | 启动实例 | `{"file_name":"x.toml"}` |
| POST | `/api/stop` | 停止实例/中止启动 | `{"file_name":"x.toml"}` |
| POST | `/api/restart` | 停止后重新启动 | `{"file_name":"x.toml"}` |
| DELETE | `/api/instance?file_name=...` | 移除已停止实例卡片 | 配置文件名 |
| GET | `/api/config/list` | 配置摘要列表 | 无 |
| GET | `/api/config?file_name=...` | 读取 TOML 原文 | 配置文件名 |
| POST | `/api/config` | 新建或覆盖配置 | `{"file_name":"x.toml","config":"..."}` |
| DELETE | `/api/config?file_name=...` | 删除未占用的配置文件 | 配置文件名 |

查询参数必须进行 URL 编码。文件名不能为空，不能包含 `..`、`/` 或 `\\`。保存配置时无扩展名会补 `.toml`，其他扩展名会被拒绝；省略或传空 `file_name` 时服务端生成时间戳文件名。

## 典型工作流

### 查看状态

1. `GET /api/instances`，取得准确 `file_name` 和 `status`。
2. 针对实例读取 `/api/info`、`/api/peers` 或 `/api/routes`。
3. 不要把展示名 `config_name` 当作 `file_name`。

实例摘要：

```json
{
  "file_name": "office.toml",
  "config_name": "Office",
  "status": "Running"
}
```

状态值由当前版本序列化，主要关注 `Starting`、`Running`、`Stopped`。

### 保存配置

先读取当前配置并保留用户未要求改变的字段。请求体中的 `config` 是 TOML 字符串，不是嵌套 JSON 对象：

```json
{
  "file_name": "office.toml",
  "config": "config_name = \"Office\"\nnetwork_code = \"team-a\"\nserver = [\"quic://vpn.example.com:29872\"]\ndevice_mode = \"tun\"\n"
}
```

服务端会解析 TOML 并拒绝旧的 `no_tun = true`。写入成功后再 `GET /api/config` 比对。覆盖正在运行实例的配置不会自动重启；由用户决定是否调用 restart。

脚本示例：

```text
python scripts/vnt_api.py client --access-url-stdin POST /api/config --json-file office-request.json
```

`office-request.json` 只能是用户允许的临时文件，且不得放入秘密 token。若无需落盘，可使用 `--json`。

### 启动与轮询

调用：

```json
{"file_name":"office.toml"}
```

发送到 `/api/start` 后，每 0.5–2 秒请求 `/api/start/status?file_name=office.toml`，但避免无限轮询。响应 data：

```json
{
  "status": "Starting",
  "logs": ["..."]
}
```

到 `Running` 即成功；到 `Stopped` 即失败或已停止，报告相关日志。设置合理总超时；服务端不可达时启动任务可能持续重试，用户要求取消时调用 `/api/stop`。

### 停止、重启和清理

- `POST /api/stop` 会中止尚在注册重试中的启动任务，并停止运行实例。
- `POST /api/restart` 最多等待约 5 秒停止，再尝试启动；之后仍需轮询状态。
- `DELETE /api/instance` 只移除 `Stopped` 实例的内存条目，不删除 TOML。
- `DELETE /api/config` 删除 TOML，若配置仍被实例占用会失败。

先停止、确认 `Stopped`、必要时移除实例条目，最后才删除配置文件。删除不是“修复卡片”的首选；启动失败残留应优先用 `/api/instance` 清理。

## 返回数据要点

`/api/info` 包含虚拟 IP、前缀、网关、设备 ID、服务器状态、NAT、公网地址、在线/离线/直连数量，以及 FEC、压缩、加密、RTX 和配置是否变化等信息。

`/api/peers` 返回各虚拟节点的设备信息、在线状态、连接路径和流量信息。`/api/routes` 按目标虚拟 IP 返回一个或多个路由，每条路由包含地址、协议、metric、RTT 和丢包率。以实际响应为准，不要依赖未使用字段的固定顺序。

## 错误处理

- HTTP `401`：token 无效；重新询问/刷新一次。
- `code != 0`：展示已脱敏的 `msg`，不要继续执行依赖该步骤的写操作。
- `Config file not found`：重新读取配置列表，确认 `file_name`。
- `实例不存在`：重新读取实例列表，不要假设配置也不存在。
- `此配置已被使用，不能删除`：先停止并确认状态，不要强制绕过。
- 网络超时：先做一次只读健康探测；不要循环重放 POST/DELETE。
