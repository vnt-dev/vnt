// 从旧 index.html 原样迁移的 TOML <-> 表单双向解析逻辑

export const emptyFormData = () => ({
  config_name: "",
  network_code: "",
  server: [""],
  peer_address: [],
  turn: [],
  ip: "",
  mtu: null,
  rtx: false,
  fec: false,
  compress: false,
  no_punch: false,
  no_broadcast: false,
  input: [],
  output: [],
  no_nat: false,
  device_mode: "tun",
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
  tunnel_port: null,
});

// 从TOML解析到表单
export const parseTomlToForm = (toml) => {
  const data = emptyFormData();

  const lines = toml.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    if (trimmed.includes("config_name")) {
      const match = trimmed.match(/config_name\s*=\s*"([^"]*)"/);
      if (match) data.config_name = match[1];
    } else if (trimmed.includes("network_code")) {
      const match = trimmed.match(/network_code\s*=\s*"([^"]*)"/);
      if (match) data.network_code = match[1];
    } else if (trimmed.startsWith("server")) {
      const match = trimmed.match(/server\s*=\s*\[(.*)\]/);
      if (match) {
        const items = match[1].match(/"([^"]*)"/g);
        if (items) data.server = items.map((s) => s.replace(/"/g, ""));
      }
    } else if (trimmed.startsWith("peer_address")) {
      const match = trimmed.match(/peer_address\s*=\s*\[(.*)\]/);
      if (match) {
        const items = match[1].match(/"([^"]*)"/g);
        if (items) data.peer_address = items.map((s) => s.replace(/"/g, ""));
      }
    } else if (trimmed.match(/^turn\s*=/)) {
      const match = trimmed.match(/turn\s*=\s*\[(.*)\]/);
      if (match) {
        const items = match[1].match(/"([^"]*)"/g);
        if (items) data.turn = items.map((s) => s.replace(/"/g, ""));
      }
    } else if (trimmed.includes("ip =")) {
      const match = trimmed.match(/ip\s*=\s*"([^"]*)"/);
      if (match) data.ip = match[1];
    } else if (trimmed.includes("mtu =")) {
      const match = trimmed.match(/mtu\s*=\s*(\d+)/);
      if (match) data.mtu = parseInt(match[1]);
    } else if (trimmed.match(/^rtx\s*=/)) {
      data.rtx = trimmed.includes("true");
    } else if (trimmed.match(/^fec\s*=/)) {
      data.fec = trimmed.includes("true");
    } else if (trimmed.match(/^compress\s*=/)) {
      data.compress = trimmed.includes("true");
    } else if (trimmed.match(/^no_punch\s*=/)) {
      data.no_punch = trimmed.includes("true");
    } else if (trimmed.match(/^no_broadcast\s*=/)) {
      data.no_broadcast = trimmed.includes("true");
    } else if (trimmed.startsWith("input")) {
      const match = trimmed.match(/input\s*=\s*\[(.*)\]/);
      if (match) {
        const items = match[1].match(/"([^"]*)"/g);
        if (items) data.input = items.map((s) => s.replace(/"/g, ""));
      }
    } else if (trimmed.startsWith("output")) {
      const match = trimmed.match(/output\s*=\s*\[(.*)\]/);
      if (match) {
        const items = match[1].match(/"([^"]*)"/g);
        if (items) data.output = items.map((s) => s.replace(/"/g, ""));
      }
    } else if (trimmed.match(/^no_nat\s*=/)) {
      data.no_nat = trimmed.includes("true");
    } else if (trimmed.match(/^no_tun\s*=/)) {
      throw new Error('配置项 no_tun 已移除，请改用 device_mode = "no|tun|tap"');
    } else if (trimmed.match(/^device_mode\s*=/)) {
      const match = trimmed.match(/device_mode\s*=\s*"([^"]*)"/);
      if (!match || !["no", "tun", "tap"].includes(match[1])) {
        throw new Error('device_mode 必须是 "no"、"tun" 或 "tap"');
      }
      data.device_mode = match[1];
    } else if (trimmed.startsWith("port_mapping")) {
      const match = trimmed.match(/port_mapping\s*=\s*\[(.*)\]/);
      if (match) {
        const items = match[1].match(/"([^"]*)"/g);
        if (items) data.port_mapping = items.map((s) => s.replace(/"/g, ""));
      }
    } else if (trimmed.match(/^allow_mapping\s*=/)) {
      data.allow_mapping = trimmed.includes("true");
    } else if (trimmed.includes("device_name")) {
      const match = trimmed.match(/device_name\s*=\s*"([^"]*)"/);
      if (match) data.device_name = match[1];
    } else if (trimmed.includes("device_id")) {
      const match = trimmed.match(/device_id\s*=\s*"([^"]*)"/);
      if (match) data.device_id = match[1];
    } else if (trimmed.includes("tun_name")) {
      const match = trimmed.match(/tun_name\s*=\s*"([^"]*)"/);
      if (match) data.tun_name = match[1];
    } else if (trimmed.includes("outbound_interface")) {
      const match = trimmed.match(/outbound_interface\s*=\s*"([^"]*)"/);
      if (match) data.outbound_interface = match[1];
    } else if (trimmed.includes("password =")) {
      const match = trimmed.match(/password\s*=\s*"([^"]*)"/);
      if (match) data.password = match[1];
    } else if (trimmed.includes("cert_mode")) {
      const match = trimmed.match(/cert_mode\s*=\s*"([^"]*)"/);
      if (match) {
        const value = match[1];
        if (value.startsWith("finger:")) {
          data.cert_mode = "finger";
          data.fingerprint = value.substring(7); // 去掉 "finger:" 前缀
        } else {
          data.cert_mode = value;
        }
      }
    } else if (trimmed.startsWith("udp_stun")) {
      const match = trimmed.match(/udp_stun\s*=\s*\[(.*)\]/);
      if (match) {
        const items = match[1].match(/"([^"]*)"/g);
        if (items) data.udp_stun = items.map((s) => s.replace(/"/g, ""));
      }
    } else if (trimmed.startsWith("tcp_stun")) {
      const match = trimmed.match(/tcp_stun\s*=\s*\[(.*)\]/);
      if (match) {
        const items = match[1].match(/"([^"]*)"/g);
        if (items) data.tcp_stun = items.map((s) => s.replace(/"/g, ""));
      }
    }
  }

  return data;
};

// 从表单生成TOML
export const formToToml = (formData) => {
  let toml = "";

  if (formData.config_name) {
    toml += `# 配置名称\nconfig_name = "${formData.config_name}"\n`;
  }

  toml += "\n# --- 网络配置 ---\n";
  toml += "# 网络编号，相同网络编号的会组在同一个虚拟网 (必填)\n";
  toml += `network_code = "${formData.network_code}"\n\n`;

  const servers = formData.server.filter((s) => s.trim());
  if (servers.length > 0) {
    toml += "# 服务器地址列表(支持 quic / tcp / wss / dynamic) (必填)\n";
    toml += "# dynamic 协议使用dns txt解析记录值\n";
    toml += `server = [${servers.map((s) => `"${s}"`).join(", ")}]\n`;
  }

  const peerAddresses = formData.peer_address.filter((s) => s.trim());
  if (peerAddresses.length > 0) {
    toml += "\n# 可直连节点地址；无协议时同时尝试 TCP 和 UDP\n";
    toml += "# 端口应为对端配置的 tunnel_port\n";
    toml += `peer_address = [${peerAddresses.map((s) => `"${s}"`).join(", ")}]\n`;
  }

  const turnRules = formData.turn.filter((s) => s.trim());
  if (turnRules.length > 0) {
    toml += "\n# 指定目标虚拟 IP 或网段的优先中转虚拟 IP；填写网关 IP 时强制走服务器中继\n";
    toml += "# 命中目标不参与 P2P 打洞\n";
    toml += `turn = [${turnRules.map((s) => `"${s}"`).join(", ")}]\n`;
  }

  if (formData.ip) {
    toml += "\n# 自定义虚拟 IP (可选)\n";
    toml += `ip = "${formData.ip}"\n`;
  }

  if (formData.rtx) {
    toml += "\n# 是否启用quic优化传输 (默认 false)\n";
    toml += "# 开启后传输过程几乎不会丢包，但是延迟可能会有波动\n";
    toml += "rtx = true\n";
  }

  if (formData.fec) {
    toml += "\n# 是否启用 FEC 前向纠错 (默认 false)\n";
    toml += "# 开启后可以减少丢包率，损失带宽但是延迟比较稳定，带宽充足时可以使用此功能\n";
    toml += "fec = true\n";
  }

  if (formData.no_punch) {
    toml += "\n# 是否关闭 P2P 打洞 (默认 false)\n";
    toml += "no_punch = true\n";
  }

  if (formData.no_broadcast) {
    toml += "\n# 是否关闭 IPv4 广播和组播转发 (默认 false，即开启)\n";
    toml += "no_broadcast = true\n";
  }

  if (formData.compress) {
    toml += "\n# 是否启用 LZ4 压缩 (默认 false)\n";
    toml += "compress = true\n";
  }

  const inputs = formData.input.filter((s) => s.trim());
  if (inputs.length > 0) {
    toml += "\n# 入栈监听网段 (逗号分隔的 CIDR 和目标 IP)，用于点对网，将指定网段的流量发送到目标节点\n";
    toml += "# 例如192.168.0.0/24,10.26.0.2 表示将192.168.0.0/24网段的数据转发到10.26.0.2\n";
    toml += `input = [${inputs.map((s) => `"${s}"`).join(", ")}]\n`;
  }

  const outputs = formData.output.filter((s) => s.trim());
  if (outputs.length > 0) {
    toml += "\n# 出栈允许网段，用于点对网，允许指定网段的转发\n";
    toml += `output = [${outputs.map((s) => `"${s}"`).join(", ")}]\n`;
  }

  if (formData.no_nat) {
    toml += "\n# 是否关闭内置子网NAT，关闭后需要配置网卡转发，否则无法使用点对网\n";
    toml += "# 通常关闭内置子网NAT，使用系统的网卡转发，点对网性能会更好\n";
    toml += "no_nat = true\n";
  }

  toml += "\n# 虚拟网卡模式：no（无网卡）、tun（三层网卡）、tap（二层网卡）\n";
  toml += `device_mode = "${formData.device_mode || "tun"}"\n`;

  const portMappings = formData.port_mapping.filter((s) => s.trim());
  if (portMappings.length > 0) {
    toml += "\n# 端口映射，格式为：协议://本地监听地址-目标虚拟IP-目标映射地址\n";
    toml += "# 端口映射用于在本地监听指定端口，并将收到的网络流量经由指定虚拟节点转发到目标地址\n";
    toml += "# 例如: tcp://0.0.0.0:81-10.0.0.2-10.0.0.2:80 表示将本地tcp的81端口的数据转发到10.0.0.2:80\n";
    toml += "# 例如: tcp://0.0.0.0:81-10.0.0.2-192.168.1.10:80 则表示将本地tcp的81端口的数据经过10.0.0.2转到192.168.1.10:80\n";
    toml += "# 例如: tcp://0.0.0.0:81-10.0.0.2-anyonehost:80 则表示将本地tcp的81端口的数据经过10.0.0.2转到anyonehost:80\n";
    toml += `port_mapping = [${portMappings.map((s) => `"${s}"`).join(", ")}]\n`;
  }

  if (formData.allow_mapping) {
    toml += '\n# 是否允许作为端口映射出口，开启后其他设备才可使用本设备的ip为"目标虚拟IP"\n';
    toml += "# 开启后虚拟网络其他设备可以使用此设备当跳板访问其他网络\n";
    toml += "allow_mapping = true\n";
  }

  if (formData.mtu) {
    toml += "\n# MTU 设置\n";
    toml += `mtu = ${formData.mtu}\n`;
  }

  toml += "\n# --- 设备配置 ---\n";
  if (formData.device_name) {
    toml += "\n# 设备名称 (可选，默认读取本机 hostname)\n";
    toml += `device_name = "${formData.device_name}"\n`;
  }
  if (formData.device_id) {
    toml += "\n# 设备 ID (可选，不填自动生成，不同设备ID不能相同)\n";
    toml += `device_id = "${formData.device_id}"\n`;
  }
  if (formData.tun_name) {
    toml += "\n# 虚拟网卡名称\n";
    toml += `tun_name = "${formData.tun_name}"\n`;
  }
  if (formData.outbound_interface) {
    toml += "\n# 绑定对外通信 Socket 的出口网卡名称（用于服务端通信、P2P 打洞及转发流量）\n";
    toml += `outbound_interface = "${formData.outbound_interface}"\n`;
  }

  toml += "\n# --- 安全配置 ---\n";
  if (formData.password) {
    toml += "\n# 组网加密密码 (可选)\n";
    toml += `password = "${formData.password}"\n`;
  }
  if (formData.cert_mode && formData.cert_mode !== "skip") {
    toml += "\n# 证书校验方式：\n";
    toml += "#   skip     跳过验证（默认）\n";
    toml += "#   standard 使用系统证书验证\n";
    toml += "#   finger   使用证书指纹验证，服务端启动时日志会输出指纹\n";
    if (formData.cert_mode === "finger" && formData.fingerprint) {
      toml += `cert_mode = "finger:${formData.fingerprint}"\n`;
    } else {
      toml += `cert_mode = "${formData.cert_mode}"\n`;
    }
  }

  const udpStuns = formData.udp_stun.filter((s) => s.trim());
  if (udpStuns.length > 0) {
    toml += "\n# 自定义UDP STUN地址，不设置则用默认stun\n";
    toml += `udp_stun = [${udpStuns.map((s) => `"${s}"`).join(", ")}]\n`;
  }

  const tcpStuns = formData.tcp_stun.filter((s) => s.trim());
  if (tcpStuns.length > 0) {
    toml += "\n# 自定义TCP STUN地址，不设置则用默认stun\n";
    toml += `tcp_stun = [${tcpStuns.map((s) => `"${s}"`).join(", ")}]\n`;
  }

  return toml;
};

// 新建配置的 TOML 模板(从旧代码逐字迁移)
export const NEW_CONFIG_TEMPLATE = `# config_name = "配置名称"
# --- 网络配置 ---
# 网络编号，相同网络编号的会组在同一个虚拟网 (必填)
network_code = "your_network_code"

# 服务器地址列表(支持 quic / tcp / wss / dynamic) (必填)
# dynamic 协议使用dns txt解析记录值
server = ["quic://1.2.3.4:29872"]

# 可直连节点地址列表 (可选)
# peer_address = ["1.2.3.4:29873", "tcp://192.168.1.10:29873"]

# 指定目标虚拟 IP 或网段的优先中转虚拟 IP；填写网关 IP 时强制走服务器中继
# 命中目标不参与 P2P 打洞
# turn = ["10.26.0.0/24,10.26.0.2", "10.26.1.9,10.26.0.3"]

# ===简单使用以下参数可以不动===

# 自定义虚拟 IP (可选)
# ip = "10.10.0.2"

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

# 是否启用 LZ4 压缩 (默认 false,设置为true时开启)
# compress = false

# 入栈监听网段 (逗号分隔的 CIDR 和目标 IP)，用于点对网，将指定网段的流量发送到目标节点
# input = ["192.168.0.0/24,10.26.0.2", "192.168.1.0/24,10.26.0.3"]

# 出栈允许网段，用于点对网，允许指定网段的转发
# output = ["0.0.0.0/0"]

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

# --- 设备配置 ---

# 设备名称 (可选，默认读取本机 hostname)
# device_name = "my-device"

# 设备 ID (可选，不填自动生成，不同设备ID不能相同)
# device_id = "device-id-xxxx"

# 虚拟网卡名称
# tun_name = "vnt-tun"

# 绑定对外通信 Socket 的出口网卡名称（例如 Ethernet、Wi-Fi、eth0）
# outbound_interface = "Ethernet"

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
