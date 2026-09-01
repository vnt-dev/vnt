<script setup>
import { computed, onMounted, ref } from "vue";
import { useAppStore } from "../stores/app";
import { getRuntime, getVersion } from "../api";
import { isDesktop } from "../auth";
import vntIcon from "../assets/vnt-icon.png";

const PROJECT_URL = "https://github.com/vnt-dev/vnt";
const RELEASES_URL = `${PROJECT_URL}/releases`;
const RELEASES_API = "https://api.github.com/repos/vnt-dev/vnt/releases?per_page=20";

const app = useAppStore();
const runtime = ref(isDesktop ? "desktop" : "");
const checking = ref(false);
const installing = ref(false);
const updateInfo = ref(null);
const resultKind = ref("");
const message = ref("");
const downloaded = ref(0);
const contentLength = ref(0);

const currentVersion = computed(() => app.version || "2.0.6");
const progress = computed(() => {
  if (!contentLength.value) return 0;
  return Math.min(100, Math.round((downloaded.value / contentLength.value) * 100));
});

const versionParts = (value) => {
  const match = String(value || "").trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:[+-].*)?$/);
  return match ? match.slice(1).map(Number) : null;
};

const compareVersions = (left, right) => {
  const a = versionParts(left);
  const b = versionParts(right);
  if (!a || !b) return 0;
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] > b[index] ? 1 : -1;
  }
  return 0;
};

const openUrl = async (url) => {
  if (globalThis.__VNT_SETTINGS__?.openUrl) {
    await globalThis.__VNT_SETTINGS__.openUrl(url);
  } else {
    window.open(url, "_blank", "noopener,noreferrer");
  }
};

const checkGithubRelease = async () => {
  const response = await fetch(RELEASES_API, {
    headers: { Accept: "application/vnd.github+json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`GitHub 返回 ${response.status}`);
  const releases = (await response.json()).filter(
    (release) => !release.draft && !release.prerelease && versionParts(release.tag_name),
  );
  releases.sort((a, b) => compareVersions(b.tag_name, a.tag_name));
  const latest = releases[0];
  if (!latest) throw new Error("没有找到可用的发布版本");
  return {
    version: latest.tag_name.replace(/^v/, ""),
    body: latest.body || "",
    url: latest.html_url || RELEASES_URL,
  };
};

const checkUpdate = async () => {
  checking.value = true;
  resultKind.value = "";
  message.value = "";
  updateInfo.value = null;
  try {
    if (isDesktop) {
      let update;
      try {
        update = await globalThis.__VNT_UPDATER__?.check();
      } catch {
        const latest = await checkGithubRelease();
        if (compareVersions(latest.version, currentVersion.value) <= 0) {
          resultKind.value = "latest";
          message.value = "当前已是最新版本";
          return;
        }
        updateInfo.value = { ...latest, manualOnly: true };
        resultKind.value = "update";
        message.value = `发现新版本 v${latest.version}，该版本暂未提供自动更新包。`;
        return;
      }
      if (!update) {
        resultKind.value = "latest";
        message.value = "当前已是最新版本";
        return;
      }
      updateInfo.value = { ...update, url: RELEASES_URL };
      resultKind.value = "update";
      message.value = `发现新版本 v${update.version}，可以直接下载并更新。`;
      return;
    }

    runtime.value ||= await getRuntime();
    const latest = await checkGithubRelease();
    if (compareVersions(latest.version, currentVersion.value) <= 0) {
      resultKind.value = "latest";
      message.value = "当前已是最新版本";
      return;
    }
    updateInfo.value = latest;
    resultKind.value = "update";
    message.value = runtime.value === "desktop_web"
      ? `发现新版本 v${latest.version}，请回到 VNT Desktop 的“关于”页面完成更新。`
      : `发现新版本 v${latest.version}，请下载新版本并替换当前 vnt2_web 程序。`;
  } catch (error) {
    resultKind.value = "error";
    message.value = `检查更新失败：${error?.message || error}`;
  } finally {
    checking.value = false;
  }
};

const downloadAndInstall = async () => {
  installing.value = true;
  downloaded.value = 0;
  contentLength.value = 0;
  message.value = "正在准备下载更新…";
  try {
    await globalThis.__VNT_UPDATER__.downloadAndInstall((event) => {
      downloaded.value = event.downloaded;
      contentLength.value = event.contentLength;
      message.value = event.event === "Finished" ? "下载完成，正在安装…" : "正在下载更新…";
    });
  } catch (error) {
    resultKind.value = "error";
    message.value = `更新失败：${error?.message || error}`;
    installing.value = false;
  }
};

onMounted(async () => {
  if (!app.version) {
    try {
      app.version = await getVersion();
    } catch {
      // 顶栏的版本加载逻辑仍会继续重试。
    }
  }
  if (!isDesktop) {
    try {
      runtime.value = await getRuntime();
    } catch {
      runtime.value = "standalone_web";
    }
  }
});
</script>

<template>
  <div class="page-stack">
    <section class="card flex items-center gap-4">
      <img :src="vntIcon" alt="VNT" class="h-16 w-16 shrink-0 rounded-2xl" />
      <div class="min-w-0">
        <h2 class="text-lg font-bold text-slate-900 dark:text-white">VNT</h2>
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">简单、高效的异地组网与内网穿透工具</p>
        <p class="mt-2 font-mono text-xs text-slate-400">当前版本 v{{ currentVersion }}</p>
      </div>
    </section>

    <section class="card">
      <h2 class="text-sm font-semibold text-slate-900 dark:text-white">开源项目</h2>
      <p class="mt-2 text-sm leading-6 text-slate-500 dark:text-slate-400">项目代码、使用说明和问题反馈均托管在 GitHub。</p>
      <button class="btn-ghost mt-4" type="button" @click="openUrl(PROJECT_URL)">
        <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path d="M14 5h5v5m0-5-9 9M19 13v5a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" />
        </svg>
        github.com/vnt-dev/vnt
      </button>
    </section>

    <section class="card">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 class="text-sm font-semibold text-slate-900 dark:text-white">软件更新</h2>
          <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">
            {{ isDesktop ? "检查并安装 VNT Desktop 的最新版本。" : "检查 GitHub 上发布的最新版本。" }}
          </p>
        </div>
        <button class="btn-primary" type="button" :disabled="checking || installing" @click="checkUpdate">
          {{ checking ? "正在检查…" : "检查更新" }}
        </button>
      </div>

      <div
        v-if="message"
        class="mt-5 rounded-lg border px-4 py-3 text-sm"
        :class="resultKind === 'error'
          ? 'border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300'
          : resultKind === 'update'
            ? 'border-indigo-200 bg-indigo-50 text-indigo-700 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-300'
            : 'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-300'"
      >
        {{ message }}
      </div>

      <div v-if="installing && contentLength" class="mt-4">
        <div class="mb-1.5 flex justify-between text-xs text-slate-400">
          <span>下载进度</span>
          <span>{{ progress }}%</span>
        </div>
        <div class="h-1.5 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
          <div class="h-full rounded-full bg-indigo-600 transition-[width] dark:bg-indigo-500" :style="{ width: `${progress}%` }"></div>
        </div>
      </div>

      <div v-if="resultKind === 'update'" class="mt-4 flex flex-wrap gap-2">
        <button v-if="isDesktop && !updateInfo?.manualOnly" class="btn-primary" type="button" :disabled="installing" @click="downloadAndInstall">
          {{ installing ? "正在更新…" : "下载并更新" }}
        </button>
        <button v-else-if="updateInfo?.manualOnly || runtime === 'standalone_web'" class="btn-ghost" type="button" @click="openUrl(updateInfo?.url || RELEASES_URL)">查看发布版本</button>
      </div>

      <p v-if="isDesktop" class="mt-4 text-xs leading-5 text-slate-400">安装更新时桌面客户端可能自动退出，完成后将重新启动；已安装的 VNT Web 服务也会同步更新并恢复运行。</p>
    </section>
  </div>
</template>
