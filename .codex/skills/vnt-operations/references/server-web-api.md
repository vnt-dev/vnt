# VNTS 管理 Web API

## 登录与会话

VNTS 管理 API 与客户端 `vnt2_web` API 完全独立。若用户未提供，询问：

- 管理端根地址，例如 `https://admin.example.com` 或 `http://127.0.0.1:29871`；
- `config.toml` 中的管理用户名和密码。

登录：

```http
POST /api/login
Content-Type: application/json

{"username":"...","password":"..."}
```

成功响应的 `data.token` 是 JWT，有效期 24 小时；服务器重启会生成新的签名密钥，因此旧 JWT 也会失效。后续请求发送：

```text
Authorization: Bearer <JWT>
```

成功响应约定：

```json
{"code": 200, "msg": "success", "data": {}}
```

只有 `code == 200` 才是业务成功。HTTP `401` 后允许重新登录一次；再次失败则停止。不要把 VNTS 用户密码、JWT、IKEv2 设备密码或 CA 私钥写入仓库、命令输出总结或日志。

辅助脚本从 stdin 读取密码并自动登录：

```text
python scripts/vnt_api.py server --base-url http://127.0.0.1:29871 --username admin --password-stdin GET /api/networks
```

也可使用 `--token-stdin` 传已有 JWT。脚本路径相对于本 skill 目录。

## 枚举与公共字段

- `network_type`：`Public` 或 `Private`。
- `ip_type`：`Dynamic`、`Static` 或 `Fixed`。
- `client_type`：`VNT` 或 `IKEV2`。
- 设备状态主要为 `Online`、`Remote` 或当前版本增加的其他字符串。

路径段和查询参数必须 URL 编码。任何修改后都重新 GET 对应资源确认结果。

## 网络

### 列表

```text
GET /api/network_codes
GET /api/networks
```

网络对象包括 `network_code`、`gateway`、`netmask`、`net`、`lease_duration`、`source`、`network_type`、`all_count` 和 `online_count`。

### 创建

```http
POST /api/networks

{
  "network_code": "team-a",
  "gateway": "10.26.10.1",
  "netmask": 24,
  "lease_duration": 86400,
  "network_type": "Private"
}
```

`netmask` 最大为 30。`lease_duration` 和 `network_type` 可省略，后者默认 `Public`。

### 更新与删除

```text
PUT    /api/networks/{network_code}
DELETE /api/networks/{network_code}
```

更新请求：

```json
{
  "gateway": "10.26.10.1",
  "netmask": 24,
  "lease_duration": 86400,
  "network_type": "Private"
}
```

删除前读取网络及其设备，向用户明确将删除的网络编号。不要根据展示顺序选择目标。

## 设备

### 列表

```text
GET /api/devices?code={network_code}
```

设备对象包括设备 ID/名称/版本、客户端类型、配置和当前 IP、IP 类型、状态、时间、延迟、所在服务器、上报子网及收发字节。

### 创建

```http
POST /api/devices

{
  "network_code": "team-a",
  "device_id": "node-01",
  "ip": "10.26.10.2",
  "ip_type": "Fixed",
  "client_type": "VNT"
}
```

`ip_type` 省略时默认 `Dynamic`。创建 IKEv2 设备时使用 `"client_type":"IKEV2"` 并提供强随机 `ikev2_password`；该密码属于敏感信息。

### 更新与删除

```text
PUT    /api/devices/{device_id}
DELETE /api/devices?code={network_code}&device_id={device_id}
```

更新请求：

```json
{
  "network_code": "team-a",
  "ip": "10.26.10.2",
  "ip_type": "Fixed",
  "ikev2_password": null
}
```

设备 ID 只在路径中，网络编号仍在请求体。删除前同时确认网络编号和设备 ID。

### IKEv2 接入信息

```text
GET /api/networks/{network_code}/devices/{device_id}/ikev2-access
```

响应包括服务配置、网络网段、用户名和密码。密码只用于当前任务，不要在最终回复原样重复；若必须交付给用户，使用用户指定的安全通道。

## 网络编号白名单

```text
GET /api/settings/network-whitelist
PUT /api/settings/network-whitelist
```

更新体：

```json
{"network_codes":["team-a","team-b"]}
```

服务端会校验、去重、排序并持久化到当前 `config.toml`，随后立即替换运行时白名单。空数组表示不限制网络编号。更新前保留当前列表，避免因遗漏意外拒绝现有网络。

## 服务端互联

```text
GET    /api/peer_servers
POST   /api/peer_servers
DELETE /api/peer_servers/{server_addr}
```

添加体：

```json
{"server_addr":"server-b.example.com:29873"}
```

列表将 outbound/inbound 分开，条目包含地址、延迟、连接状态和方向。互联需要在配置中启用 peer manager，并在各服务器使用相同 `server_token`。删除地址路径必须 URL 编码。

## IKEv2 服务设置

```text
GET /api/settings/ikev2
PUT /api/settings/ikev2
```

更新体必须给出完整设置而非局部 patch：

```json
{
  "enabled": true,
  "ike_bind": "0.0.0.0:500",
  "natt_bind": "0.0.0.0:4500",
  "remote_id": "vpn.example.com",
  "public_ip": "203.0.113.10",
  "dns": ["1.1.1.1"],
  "cert": null,
  "key": null
}
```

先 GET、仅修改用户要求的字段、再 PUT 完整对象。`cert`/`key` 必须同时设置或同时为空；为空时可生成受管 CA 和服务证书。响应包含 `configured`、`enabled`、`runtime_active`、证书状态、CA 是否可下载及 `runtime_error`。保存会启动、停止或热加载服务，失败时服务端尝试回滚配置和受管证书；仍需读回并检查 `runtime_active/runtime_error`。

下载 CA：

```text
GET /api/ikev2/ca-certificate?format=der
GET /api/ikev2/ca-certificate?format=pem
```

使用辅助脚本的 `--output` 保存二进制/文本证书，不要尝试按 JSON 解析：

```text
python scripts/vnt_api.py server --base-url http://127.0.0.1:29871 --token-stdin GET "/api/ikev2/ca-certificate?format=der" --output vnt-ikev2-ca.cer
```

## 失败处理

- `401`：重新登录一次；服务端可能刚重启或 JWT 已过期。
- `code != 200`：报告脱敏的 `msg`，停止依赖该步骤的后续写操作。
- 网络/设备不存在：重新读取列表并核对 URL 编码，不自动创建替代对象。
- 写配置失败或 IKEv2 回滚失败：立即读取设置、检查 journal 和 `runtime_error`；不要连续重放 PUT。
- 超时：用一个 GET 健康检查区分管理端不可达与写操作响应丢失，然后读回资源判定是否已生效，避免盲目重试非幂等 POST。
