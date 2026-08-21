// fetch 封装:统一解包 ApiResponse{code,msg,data},code!==0 抛出带 msg 的错误
const request = async (url, options) => {
  const res = await fetch(url, options);
  const json = await res.json();
  if (json.code !== 0) {
    throw new Error(json.msg || "请求失败");
  }
  return json.data;
};

const jsonHeaders = { "Content-Type": "application/json" };

// GET /api/info?file_name=
export const getInstanceInfo = (fileName) =>
  request(`/api/info?file_name=${encodeURIComponent(fileName)}`);

// GET /api/peers?file_name=
export const getPeers = (fileName) =>
  request(`/api/peers?file_name=${encodeURIComponent(fileName)}`);

// GET /api/routes?file_name=
export const getRoutes = (fileName) =>
  request(`/api/routes?file_name=${encodeURIComponent(fileName)}`);

// GET /api/start/status?file_name=
export const getStartStatus = (fileName) =>
  request(`/api/start/status?file_name=${encodeURIComponent(fileName)}`);

// GET /api/instances
export const getInstances = () => request("/api/instances");

// DELETE /api/instance?file_name=
export const deleteInstance = (fileName) =>
  request(`/api/instance?file_name=${encodeURIComponent(fileName)}`, {
    method: "DELETE",
  });

const postAction = (path, fileName) =>
  request(path, {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify({ file_name: fileName }),
  });

// POST /api/start
export const startVntApi = (fileName) => postAction("/api/start", fileName);

// POST /api/stop
export const stopVntApi = (fileName) => postAction("/api/stop", fileName);

// POST /api/restart
export const restartVntApi = (fileName) => postAction("/api/restart", fileName);

// GET /api/config/list
export const getConfigList = () => request("/api/config/list");

// GET /api/config?file_name= -> TOML 原文字符串
export const getConfig = (fileName) =>
  request(`/api/config?file_name=${encodeURIComponent(fileName)}`);

// POST /api/config, JSON {file_name?, config}
export const saveConfig = (fileName, config) =>
  request("/api/config", {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify({ file_name: fileName || null, config }),
  });

// DELETE /api/config?file_name=
export const deleteConfig = (fileName) =>
  request(`/api/config?file_name=${encodeURIComponent(fileName)}`, {
    method: "DELETE",
  });
