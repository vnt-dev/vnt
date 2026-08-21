// 格式化时间
export const formatTime = (timestamp) => {
  if (!timestamp) return "-";
  const date = new Date(timestamp * 1000);
  const pad = (n) => (n < 10 ? "0" + n : n);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
};

// 格式化字节数
export const formatBytes = (bytes) => {
  if (bytes === 0 || bytes === undefined || bytes === null) return "0B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let value = bytes;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return i === 0 ? value + units[i] : value.toFixed(2) + units[i];
};

// 格式化速度(字节/秒)
export const formatSpeed = (bytesPerSecond) => {
  if (
    bytesPerSecond === 0 ||
    bytesPerSecond === undefined ||
    bytesPerSecond === null
  )
    return "0B/s";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let i = 0;
  let value = bytesPerSecond;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return i === 0 ? value + units[i] : value.toFixed(2) + units[i];
};

// 将数值取整到适合的刻度
export const niceNumber = (val) => {
  const units = [
    1024, // 1KB
    10 * 1024, // 10KB
    100 * 1024, // 100KB
    1024 * 1024, // 1MB
    10 * 1024 * 1024, // 10MB
    100 * 1024 * 1024, // 100MB
    1024 * 1024 * 1024, // 1GB
  ];
  for (const u of units) {
    if (val <= u) return u;
  }
  return Math.ceil(val / (1024 * 1024 * 1024)) * 1024 * 1024 * 1024;
};
