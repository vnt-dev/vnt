import { invoke } from "@tauri-apps/api/core";
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";

let pendingUpdate = null;

globalThis.__VNT_DESKTOP__ = true;
globalThis.__VNT_API_REQUEST__ = ({ method, path, body }) =>
  invoke("api_request", { method, path, body });
globalThis.__VNT_SETTINGS__ = {
  status: () => invoke("kernel_status"),
  saveAndRestart: (config) => invoke("save_and_restart_kernel", { config }),
  installService: () => invoke("install_kernel_service"),
  uninstallService: () => invoke("uninstall_kernel_service"),
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
    await pendingUpdate.download((event) => {
      if (event.event === "Started") {
        contentLength = event.data.contentLength || 0;
      } else if (event.event === "Progress") {
        downloaded += event.data.chunkLength;
      }
      onProgress?.({ event: event.event, downloaded, contentLength });
    });

    const servicePrepared = await invoke("prepare_app_update");
    try {
      // Windows 更新器会在启动安装程序后直接退出；新版本启动时会用新 sidecar
      // 刷新服务注册并恢复运行。其他平台安装完成后继续走 relaunch。
      await pendingUpdate.install();
      if (servicePrepared) await invoke("restore_service_after_update");
      await relaunch();
    } catch (error) {
      if (servicePrepared) {
        try {
          await invoke("restore_service_after_update");
        } catch (restoreError) {
          throw new Error(`${error?.message || error}；同时恢复 VNT Web 服务失败：${restoreError}`);
        }
      }
      throw error;
    }
  },
};

// Tauri 与 Web 端共用同一个 Vue 应用，这里只负责平台初始化。
await import("@shared/main.js");
