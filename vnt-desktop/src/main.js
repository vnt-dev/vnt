import { invoke } from "@tauri-apps/api/core";

globalThis.__VNT_DESKTOP__ = true;
globalThis.__VNT_IPC_REQUEST__ = ({ method, path, body }) =>
  invoke("api_request", { method, path, body });
globalThis.__VNT_WEB_ACCESS__ = {
  status: () => invoke("web_access_status"),
  update: (config) => invoke("update_web_access", { config }),
  generateToken: () => invoke("generate_web_token"),
  openUrl: (url) => invoke("open_web_url", { url }),
};

// Tauri 与 Web 端共用同一个 Vue 应用，这里只负责平台初始化。
await import("@shared/main.js");
