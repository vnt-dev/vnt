import { parseTOML } from "toml-eslint-parser";

export const emptyFormData = () => ({
  config_name: "",
  subscription: "",
  network_code: "",
  server: [""],
  peer_address: [],
  turn: [],
  punch_model: [],
  ip: "",
  mtu: null,
  dns: [],
  dns_explicit: false,
  rtx: false,
  fec: false,
  compress: false,
  no_punch: false,
  no_broadcast: false,
  allow_ikev2: false,
  allow_wireguard: false,
  input: [],
  subnet_mapping: [],
  output: [],
  auto_sync_subnet: false,
  no_nat: false,
  device_mode: "tun",
  device_mode_explicit: false,
  port_mapping: [],
  allow_mapping: false,
  device_name: "",
  device_id: "",
  tun_name: "",
  outbound_interface: "",
  password: "",
  cert_mode: "skip",
  fingerprint: "",
  udp_stun: [],
  tcp_stun: [],
  tunnel_addr: [],
  event_script: "",
});

const formOnlyFields = new Set(["dns_explicit", "device_mode_explicit", "fingerprint"]);

const parseSource = (source) => {
  const { body } = parseTOML(source).body[0];
  const fields = new Map();
  for (const node of body) {
    if (node.type === "TOMLKeyValue" && node.key.keys.length === 1) {
      const [key] = node.key.keys;
      fields.set(key.name ?? key.value, node);
    }
  }
  return { fields, firstTable: body.find((node) => node.type === "TOMLTable") };
};

const readField = (key, node, fallback) => {
  if (Array.isArray(fallback)) {
    if (node.type === "TOMLArray" && node.elements.every((element) => element.kind === "string")) {
      return node.elements.map((element) => element.value);
    }
  } else {
    const kind = fallback === null ? "integer" : typeof fallback;
    if (node.type === "TOMLValue" && node.kind === kind) return node.value;
  }
  throw new Error(`${key} 的值不适合表单编辑，请使用 TOML 模式`);
};

const readForm = (fields) => {
  const data = emptyFormData();
  for (const [key, fallback] of Object.entries(data)) {
    const field = fields.get(key);
    if (field && !formOnlyFields.has(key)) data[key] = readField(key, field.value, fallback);
  }
  if (fields.get("no_tun")?.value.value === true) {
    throw new Error('配置项 no_tun 已移除，请改用 device_mode = "no|tun|tap"');
  }
  data.dns_explicit = fields.has("dns");
  data.device_mode_explicit = fields.has("device_mode");
  if (!["no", "tun", "tap"].includes(data.device_mode)) {
    throw new Error('device_mode 必须是 "no"、"tun" 或 "tap"');
  }
  const certMode = data.cert_mode.trim().toLowerCase();
  if (certMode.startsWith("finger:")) {
    data.cert_mode = "finger";
    data.fingerprint = certMode.slice(7);
  } else {
    data.cert_mode = certMode;
  }
  const legacyPort = fields.get("tunnel_port");
  if (data.tunnel_addr.length === 0 && legacyPort) {
    data.tunnel_addr = [`0.0.0.0:${readField("tunnel_port", legacyPort.value, null)}`];
  }
  return data;
};

export const parseTomlToForm = (source) => readForm(parseSource(source).fields);

const formValue = (key, form) => {
  const value = form[key];
  if (key === "dns" && !form.dns_explicit && !value.some((item) => item.trim())) return undefined;
  if (key === "device_mode" && !form.device_mode_explicit) return undefined;
  if (key === "cert_mode" && value === "finger") return `finger:${form.fingerprint}`;
  if (Array.isArray(value)) {
    const items = value.filter((item) => item.trim());
    return key === "dns" ? items.map((item) => item.trim()) : items;
  }
  return value === "" || value === null ? undefined : value;
};

// JSON basic strings are also TOML basic strings, except literal DEL must be escaped.
const formatValue = (value) => {
  if (Array.isArray(value)) return `[${value.map(formatValue).join(", ")}]`;
  return typeof value === "string" ? JSON.stringify(value).replaceAll("\x7f", "\\u007f") : String(value);
};

export const formToToml = (form, source = "") => {
  const { fields, firstTable } = parseSource(source);
  const before = readForm(fields);
  const edits = [];
  const added = [];
  for (const key of Object.keys(before)) {
    if (formOnlyFields.has(key)) continue;
    const previous = formValue(key, before);
    const next = formValue(key, form);
    if (JSON.stringify(previous) === JSON.stringify(next)) continue;
    const field = fields.get(key);
    if (next === undefined) {
      if (field) edits.push([...field.range, ""]);
    } else if (field) {
      edits.push([...field.value.range, formatValue(next)]);
    } else {
      added.push(`${key} = ${formatValue(next)}`);
    }
    if (key === "tunnel_addr" && fields.has("tunnel_port")) {
      edits.push([...fields.get("tunnel_port").range, ""]);
    }
  }
  if (added.length) {
    const newline = source.includes("\r\n") ? "\r\n" : "\n";
    const at = firstTable
      ? source.lastIndexOf("\n", firstTable.range[0] - 1) + 1
      : source.length;
    const separator = at > 0 && source[at - 1] !== "\n" ? newline : "";
    edits.push([at, at, separator + added.join(newline) + newline]);
  }

  // Keep the original text for unchanged values, comments, and fields not exposed by the form.
  let result = source;
  for (const [start, end, text] of edits.sort((a, b) => b[0] - a[0] || b[1] - a[1])) {
    result = result.slice(0, start) + text + result.slice(end);
  }
  if (edits.length) parseTOML(result);
  return result;
};

// 新建配置的 TOML 模板(从旧代码逐字迁移)
export const NEW_CONFIG_TEMPLATE = `# config_name = "配置名称"
# --- 网络配置 ---
# 网络编号，相同网络编号的会组在同一个虚拟网
network_code = "your_network_code"

# 服务器地址列表；固定 IP 时在后台连接，也可删除此项完全无服务器运行
# dynamic 协议默认使用 DNS TXT 解析，也可使用 dynamic://http(s)://接口地址获取换行分隔的服务器地址列表
server = ["quic://1.2.3.4:29872"]

# 可直连节点地址列表；支持 dynamic:// DNS TXT 或 HTTP(S) 地址列表
# peer_address = ["1.2.3.4:29873", "tcp://192.168.1.10:29873", "dynamic://peers.example.com"]

# P2P 隧道监听地址；IPv4 与 IPv6 最多各一个且端口必须相同
# tunnel_addr = ["192.168.1.10:29873", "[2001:db8::10]:29873"]

# 指定目标虚拟 IP 或网段的优先中转虚拟 IP；填写网关 IP 时强制走服务器中继
# 命中目标不参与 P2P 打洞
# turn = ["10.26.0.0/24,10.26.0.2", "10.26.1.9,10.26.0.3"]

# 按目标虚拟 IP 或网段限制 P2P 打洞方式；可选 IPv4Tcp、IPv4Udp、IPv6Tcp、IPv6Udp
# punch_model = ["10.26.0.2,IPv4Udp", "10.26.1.0/24,IPv4Tcp,IPv4Udp"]

# ===简单使用以下参数可以不动===

# 固定虚拟 IP/CIDR（纯 IP 默认 /24；无服务器或多服务器时需要设置）
# ip = "10.10.0.2/24"

# 是否启用quic优化传输 (默认 false,设置为true时开启)
# 开启后传输过程几乎不会丢包，但是延迟会有波动
# rtx = false

# 是否启用 FEC 前向纠错，损失一定带宽来提升网络稳定性(默认 false,设置为true时开启)
# 开启后可以减少丢包率，损失带宽但是延迟比较稳定，带宽充足时可以使用此功能
# fec = false

# 是否关闭 P2P 打洞 (默认 false,设置为true时关闭)
# no_punch = false

# 是否关闭 IPv4 广播和组播转发 (默认 false，即开启)
# no_broadcast = false

# 是否允许与 IKEv2 客户端通信，并信任服务端注入的 IKEv2 明文 IPv4 包
# allow_ikev2 = false

# 是否允许与 WireGuard 客户端通信，并信任服务端注入的 WireGuard 明文 IPv4 包
# allow_wireguard = false

# 是否启用 LZ4 压缩 (默认 false,设置为true时开启)
# compress = false

# 入栈监听网段 (逗号分隔的 CIDR 和目标 IP)，用于点对网，将指定网段的流量发送到目标节点
# input = ["192.168.0.0/24,10.26.0.2", "192.168.1.0/24,10.26.0.3"]

# 出栈允许网段，用于点对网，允许指定网段的转发
# output = ["0.0.0.0/0"]

# 出栈网段映射，两侧掩码必须相同；本机 output 需允许真实网段
# subnet_mapping = ["192.168.2.0/24,192.168.1.0/24", "192.168.2.2/32,192.168.1.3/32"]

# 是否自动获取并应用其他在线节点的出口子网
# auto_sync_subnet = false

# 是否关闭内置子网NAT，关闭(设为true)后需要配置网卡转发，否则无法使用点对网。通常关闭内置子网NAT，使用系统的网卡转发，点对网性能会更好
# no_nat = false

# 虚拟网卡模式：no（无网卡）、tun（三层网卡，默认）、tap（二层网卡）
# Windows 的 tap 模式需要预先安装 tap-windows (tap0901) 驱动
device_mode = "tun"

# 端口映射，格式为：协议://本地监听地址-目标虚拟IP-目标映射地址
# 端口映射用于在本地监听指定端口，并将收到的网络流量经由指定虚拟节点转发到目标地址，从而实现跨网络或内网服务访问
# 例如 port_mapping = ["tcp://0.0.0.0:81-10.0.0.2-10.0.0.2:80"]
# tcp://0.0.0.0:81-10.0.0.2-10.0.0.2:80 则表示将本地tcp的81端口的数据转发到10.0.0.2:80
# tcp://0.0.0.0:81-10.0.0.2-192.168.1.10:80 则表示将本地tcp的81端口的数据经过10.0.0.2转到192.168.1.10:80
# tcp://0.0.0.0:81-10.0.0.2-anyonehost:80 则表示将本地tcp的81端口的数据经过10.0.0.2转到anyonehost:80
# port_mapping = []

# 是否允许作为端口映射出口，开启(设置为true)后其他设备才可使用本设备的ip为"目标虚拟IP"
# 开启后虚拟网络其他设备可以使用此设备当跳板访问其他网络
# allow_mapping = false

# MTU 设置
# mtu = 1400

# 网卡 DNS：非空列表写入虚拟网卡接口，空列表或省略则使用系统 DNS。
# 第 1 条主用，其余备用；建议填 VNT 对端（路由器）隧道 IP。
# dns = ["10.26.0.3", "223.5.5.5"]

# --- 设备配置 ---

# 设备名称 (可选，默认读取本机 hostname)
# device_name = "my-device"

# 设备 ID (可选，不填自动生成，不同设备ID不能相同)
# device_id = "device-id-xxxx"

# 虚拟网卡名称
# tun_name = "vnt-tun"

# 绑定对外通信 Socket 的出口网卡名称（例如 Ethernet、Wi-Fi、eth0）
# outbound_interface = "Ethernet"

# 事件脚本路径/命令 (可选，留空不触发)；网卡创建成功、掉线、重连成功、IP 变化时以命令行参数调用
# 例如创建网卡成功时脚本会收到: <脚本> netcard-created --ip ... --prefix-length ... --gateway ... --broadcast ... --server ...
# event_script = "C:\\\\scripts\\\\vnt-event.bat"

# --- 安全配置 ---

# 加密密码 (可选)
# password = "123456"

# 证书校验方式：
#   skip     跳过验证（默认）
#   standard 使用系统证书验证
#   finger   使用证书指纹验证，服务端启动时日志会输出指纹，
#            例如 finger:3bdd8675606837cdf95d5e13445606315762315a78555f9da652940a25feaec1
# cert_mode = "skip"

# --- 其他配置 ---
# 自定义stun地址，分别用于udp打洞和tcp打洞，需要单独配置，不设置则用默认stun
# udp_stun = ["stun.chat.bilibili.com"]
# tcp_stun = ["stun.nextcloud.com:443"]`;
