import { invoke } from "@tauri-apps/api/core";
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";

let pendingUpdate = null;

globalThis.__VNT_DESKTOP__ = true;
globalThis.__VNT_IPC_REQUEST__ = ({ method, path, body }) =>
  invoke("api_request", { method, path, body });
globalThis.__VNT_WEB_ACCESS__ = {
  status: () => invoke("web_access_status"),
  update: (config) => invoke("update_web_access", { config }),
  generateToken: () => invoke("generate_web_token"),
  openUrl: (url) => invoke("open_web_url", { url }),
};
globalThis.__VNT_UPDATER__ = {
  check: async () => {
    pendingUpdate = await check();
    if (!pendingUpdate) return null;
    return {
      currentVersion: pendingUpdate.currentVersion,
      version: pendingUpdate.version,
      date: pendingUpdate.date || "",
      body: pendingUpdate.body || "",
    };
  },
  downloadAndInstall: async (onProgress) => {
    if (!pendingUpdate) throw new Error("请先检查更新");
    let downloaded = 0;
    let contentLength = 0;
    await pendingUpdate.downloadAndInstall((event) => {
      if (event.event === "Started") {
        contentLength = event.data.contentLength || 0;
      } else if (event.event === "Progress") {
        downloaded += event.data.chunkLength;
      }
      onProgress?.({ event: event.event, downloaded, contentLength });
    });
    await relaunch();
  },
};

// Tauri 与 Web 端共用同一个 Vue 应用，这里只负责平台初始化。
await import("@shared/main.js");
