<script setup>
import { computed, onMounted, reactive, ref } from "vue";
import { useUiStore } from "../stores/ui";

const bridge = globalThis.__VNT_SETTINGS__;
const ui = useUiStore();
const draft = reactive({
  listenAddress: "127.0.0.1",
  port: 19099,
  token: "",
  autoStart: false,
});
const status = ref(null);
const loading = ref(true);
const saving = ref(false);
const installing = ref(false);
const uninstalling = ref(false);
const notice = ref("");
const error = ref("");

const isServiceMode = computed(() => status.value?.serviceInstalled === true);

const sync = (value) => {
  status.value = value;
  Object.assign(draft, {
    listenAddress: value.listenAddress,
    port: value.port,
    token: value.token,
    autoStart: value.autoStart,
  });
};

const load = async () => {
  loading.value = true;
  error.value = "";
  try {
    if (!bridge) throw new Error("内核设置仅在桌面客户端中提供");
    sync(await bridge.status());
  } catch (err) {
    error.value = err.message || String(err);
  } finally {
    loading.value = false;
  }
};

const configPayload = () => ({
  listenAddress: draft.listenAddress.trim(),
  port: Number(draft.port),
  token: draft.token.trim(),
  autoStart: Boolean(draft.autoStart),
});

const saveAndRestart = async () => {
  saving.value = true;
  notice.value = "";
  error.value = "";
  try {
    sync(await bridge.saveAndRestart(configPayload()));
    notice.value = "设置已保存，VNT Web 内核已重启";
  } catch (err) {
    error.value = err.message || String(err);
    try {
      sync(await bridge.status());
    } catch {
      // 保留重启错误，状态刷新失败不覆盖原始提示。
    }
  } finally {
    saving.value = false;
  }
};

const regenerate = async () => {
  draft.token = await bridge.generateToken();
  notice.value = "已生成新令牌，点击“保存并重启内核”后生效";
  error.value = "";
};

const installService = async () => {
  installing.value = true;
  notice.value = "";
  error.value = "";
  try {
    // 先保存当前输入，确保服务首次启动就使用本页配置。
    draft.autoStart = false;
    sync(await bridge.saveAndRestart(configPayload()));
    sync(await bridge.installService());
    notice.value = "VNT Web 已安装为系统服务，后续由服务托管内核";
  } catch (err) {
    error.value = err.message || String(err);
    try {
      sync(await bridge.status());
    } catch {
      // 保留安装错误。
    }
  } finally {
    installing.value = false;
  }
};

const uninstallService = async () => {
  const confirmed = await ui.confirm({
    title: "卸载系统服务",
    message: "将停止并删除 VNT Web 系统服务，随后改由桌面程序托管内核。开机启动也会同时关闭。",
    danger: true,
    confirmText: "卸载服务",
  });
  if (!confirmed) return;
  uninstalling.value = true;
  notice.value = "";
  error.value = "";
  try {
    sync(await bridge.uninstallService());
    notice.value = "系统服务已卸载，VNT Web 内核已切回桌面程序托管";
  } catch (err) {
    error.value = err.message || String(err);
    try {
      sync(await bridge.status());
    } catch {
      // 保留卸载错误。
    }
  } finally {
    uninstalling.value = false;
  }
};

const copyUrl = async () => {
  await navigator.clipboard.writeText(status.value.url);
  notice.value = "访问地址已复制";
  error.value = "";
};

const openBrowser = async () => {
  await bridge.openUrl(status.value.url);
};

onMounted(load);
</script>

<template>
  <div class="page-stack">
    <div v-if="loading" class="card text-sm text-slate-400">正在读取内核设置…</div>
    <div v-else-if="!bridge" class="card border-red-200 text-sm text-red-600 dark:border-red-900 dark:text-red-300">{{ error }}</div>
    <template v-else>
      <section class="card space-y-6">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h3 class="text-sm font-semibold text-slate-900 dark:text-white">VNT Web 内核</h3>
            <p class="mt-1 text-xs leading-5 text-slate-400">桌面端始终通过本机 HTTP 访问内置内核，Web 服务不可关闭。</p>
          </div>
          <div class="flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium"
            :class="status?.running ? 'border-green-200 bg-green-50 text-green-700 dark:border-green-900 dark:bg-green-950/40 dark:text-green-400' : 'border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400'">
            <span class="h-2 w-2 rounded-full" :class="status?.running ? 'bg-green-500' : 'bg-red-500'"></span>
            {{ status?.running ? "运行中" : "连接异常" }}
          </div>
        </div>

        <div class="grid gap-5 sm:grid-cols-2">
          <label class="block">
            <span class="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-200">监听地址</span>
            <input v-model="draft.listenAddress" class="input font-mono" type="text" placeholder="127.0.0.1" :disabled="saving || installing || uninstalling" />
            <span class="mt-1.5 block text-xs text-slate-400">使用 127.0.0.1 仅允许本机访问；使用 0.0.0.0 可供局域网访问。</span>
          </label>
          <label class="block">
            <span class="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-200">监听端口</span>
            <input v-model.number="draft.port" class="input font-mono" type="number" min="1" max="65535" :disabled="saving || installing || uninstalling" />
          </label>
        </div>

        <div>
          <div class="mb-2 flex items-center justify-between gap-3">
            <span class="text-sm font-medium text-slate-700 dark:text-slate-200">访问令牌</span>
            <button class="text-xs font-medium text-indigo-600 hover:text-indigo-500 disabled:opacity-50 dark:text-indigo-400" type="button" :disabled="saving || installing || uninstalling" @click="regenerate">生成新令牌</button>
          </div>
          <input v-model="draft.token" class="input font-mono text-xs" type="text" autocomplete="off" spellcheck="false" :disabled="saving || installing || uninstalling" />
          <p class="mt-2 text-xs text-slate-400">令牌至少 16 个字符。修改后，已登录的浏览器需要使用新令牌重新鉴权。</p>
        </div>

        <div class="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-5 dark:border-slate-800">
          <div class="min-h-5">
            <span v-if="notice" class="text-xs text-green-600 dark:text-green-400">{{ notice }}</span>
            <span v-else-if="error" class="text-xs text-red-600 dark:text-red-400">{{ error }}</span>
            <span v-else class="text-xs text-slate-400">监听配置和令牌会在重启内核后生效。</span>
          </div>
          <button class="btn-primary" type="button" :disabled="saving || installing || uninstalling" @click="saveAndRestart">
            {{ saving ? "正在重启…" : "保存并重启内核" }}
          </button>
        </div>
      </section>

      <section class="card space-y-5">
        <div>
          <h3 class="text-sm font-semibold text-slate-900 dark:text-white">系统服务</h3>
          <p class="mt-1 text-xs leading-5 text-slate-400">安装后，程序安装目录中的 VNT Web 内核将由 Windows 服务托管。安装和更改服务设置时需要管理员授权。</p>
        </div>

        <div class="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-950/50">
          <div class="flex min-w-0 items-center gap-3">
            <span class="h-2.5 w-2.5 shrink-0 rounded-full" :class="isServiceMode ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'"></span>
            <div>
              <div class="text-sm font-medium text-slate-900 dark:text-white">{{ isServiceMode ? "服务已安装" : "当前由桌面程序托管" }}</div>
              <div class="mt-0.5 text-xs text-slate-400">{{ isServiceMode ? (status?.serviceRunning ? "VNT Web 服务正在运行" : "服务当前未运行") : "退出桌面程序时内核随之退出" }}</div>
            </div>
          </div>
          <button v-if="status?.serviceSupported && !isServiceMode" class="btn-ghost btn-sm" type="button" :disabled="installing || uninstalling || saving" @click="installService">
            {{ installing ? "正在安装…" : "安装为服务" }}
          </button>
          <div v-else-if="isServiceMode" class="flex items-center gap-2">
            <span class="rounded-full bg-green-100 px-3 py-1 text-xs font-medium text-green-700 dark:bg-green-950 dark:text-green-400">服务模式</span>
            <button class="btn-ghost btn-sm text-red-600 hover:border-red-300 hover:text-red-700 dark:text-red-400 dark:hover:border-red-800" type="button" :disabled="uninstalling || saving" @click="uninstallService">
              {{ uninstalling ? "正在卸载…" : "卸载服务" }}
            </button>
          </div>
          <span v-else class="text-xs text-slate-400">当前系统暂不支持</span>
        </div>

        <div class="flex items-center justify-between gap-5">
          <div>
            <div class="text-sm font-medium text-slate-900 dark:text-white">开机启动内核</div>
            <div class="mt-1 text-xs text-slate-400">仅在安装为系统服务后可用，修改后请保存并重启内核。</div>
          </div>
          <button
            type="button"
            role="switch"
            aria-label="开机启动内核"
            :aria-checked="draft.autoStart"
            :disabled="!isServiceMode || saving || installing || uninstalling"
            class="settings-switch transition-colors disabled:cursor-not-allowed disabled:opacity-40"
            :class="draft.autoStart ? 'bg-indigo-600 dark:bg-indigo-500' : 'bg-slate-300 dark:bg-slate-600'"
            @click="draft.autoStart = !draft.autoStart"
          >
            <span class="settings-switch-knob bg-white shadow-sm" :class="{ 'settings-switch-knob-on': draft.autoStart }"></span>
          </button>
        </div>
      </section>

      <section class="card">
        <div class="flex items-start gap-3">
          <span class="mt-1 h-2.5 w-2.5 shrink-0 rounded-full" :class="status?.running ? 'bg-green-500' : 'bg-red-500'"></span>
          <div class="min-w-0 flex-1">
            <div class="text-sm font-semibold text-slate-900 dark:text-white">Web 访问</div>
            <div class="mt-1 text-xs text-slate-400">监听端点：{{ status?.listenEndpoint }}</div>
            <div class="mt-4 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 font-mono text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300">
              <span class="block truncate">{{ status?.url }}</span>
            </div>
            <div class="mt-3 flex flex-wrap gap-2">
              <button class="btn-primary btn-sm" type="button" :disabled="!status?.running" @click="openBrowser">打开浏览器</button>
              <button class="btn-ghost btn-sm" type="button" @click="copyUrl">复制访问地址</button>
            </div>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped>
.settings-switch {
  position: relative;
  display: inline-flex;
  flex: 0 0 44px;
  align-items: center;
  width: 44px;
  min-width: 44px;
  height: 24px;
  min-height: 24px;
  padding: 2px;
  border: 0;
  border-radius: 9999px;
  cursor: pointer;
}

.settings-switch-knob {
  display: block;
  width: 20px;
  min-width: 20px;
  height: 20px;
  border-radius: 9999px;
  transform: translateX(0);
  transition: transform 160ms ease;
}

.settings-switch-knob-on {
  transform: translateX(20px);
}
</style>
