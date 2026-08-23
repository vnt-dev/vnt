export const NETWORK_QR_TYPE = "vnt-network";
export const NETWORK_QR_VERSION = 1;

export const buildNetworkQrPayload = (form) => {
  const networkCode = String(form.network_code || "").trim();
  const servers = (form.server || []).map((server) => String(server).trim()).filter(Boolean);
  const mtu = Number(form.mtu || 1380);

  if (!networkCode) throw new Error("组网编号不能为空");
  if (servers.length === 0) throw new Error("服务器地址不能为空");
  if (!Number.isInteger(mtu) || mtu < 576 || mtu > 9000) {
    throw new Error("MTU 必须在 576-9000 之间");
  }

  return {
    type: NETWORK_QR_TYPE,
    version: NETWORK_QR_VERSION,
    network_code: networkCode,
    server: servers,
    mtu,
    password: String(form.password || ""),
  };
};
