<script setup>
import { onMounted, reactive, ref } from "vue";
import AppSelect from "../components/AppSelect.vue";

const bridge = globalThis.__VNT_WEB_ACCESS__;
const draft = reactive({ enabled: false, port: 19099, global: false, token: "" });
const status = ref(null);
const loading = ref(true);
const saving = ref(false);
const notice = ref("");
const error = ref("");
const listenScopeOptions = [
  { value: false, label: "仅本机（推荐）" },
  { value: true, label: "局域网内所有设备" },
];

const sync = (value) => {
  status.value = value;
  Object.assign(draft, {
    enabled: value.enabled,
    port: value.port,
    global: value.global,
    token: value.token,
  });
};

const load = async () => {
  loading.value = true;
  error.value = "";
  try {
    if (!bridge) throw new Error("Web 访问设置仅在桌面客户端中提供");
    sync(await bridge.status());
  } catch (err) {
    error.value = err.message || String(err);
  } finally {
    loading.value = false;
  }
};

const update = async (changes, successMessage) => {
  saving.value = true;
  error.value = "";
  notice.value = "";
  try {
    sync(await bridge.update({
      ...draft,
      ...changes,
      port: Number(changes.port ?? draft.port),
    }));
    notice.value = successMessage;
  } catch (err) {
    const message = err.message || String(err);
    try {
      sync(await bridge.status());
    } catch {
      // 保留原始操作错误，状态刷新失败不覆盖它。
    }
    error.value = message;
  } finally {
    saving.value = false;
  }
};

const toggleService = async () => {
  const enabled = !draft.enabled;
  await update(
    { enabled },
    enabled ? "Web 服务已启动" : "Web 服务已关闭",
  );
};

const regenerate = async () => {
  const token = await bridge.generateToken();
  await update(
    { token },
    draft.enabled ? "新令牌已生效，Web 服务已重新加载" : "新令牌已生成",
  );
};

const saveNetworkSettings = async () => {
  if (draft.enabled) return;
  await update({}, "监听设置已自动保存");
};

const updateListenScope = async (value) => {
  draft.global = value;
  await saveNetworkSettings();
};

const copyUrl = async () => {
  await navigator.clipboard.writeText(status.value.url);
  notice.value = "访问地址已复制";
};

const openBrowser = async () => {
  await bridge.openUrl(status.value.url);
};

onMounted(load);
</script>

<template>
  <div class="page-stack">
    <div v-if="loading" class="card text-sm text-slate-400">正在读取 Web 服务状态…</div>
    <div v-else-if="!bridge" class="card border-red-200 text-sm text-red-600 dark:border-red-900 dark:text-red-300">{{ error }}</div>
    <template v-else>
      <section class="card space-y-6">
        <div class="flex items-start justify-between gap-5">
          <div>
            <h3 class="text-sm font-semibold text-slate-900 dark:text-white">启用 Web 服务</h3>
          </div>
          <button
            type="button"
            role="switch"
            aria-label="启用 Web 服务"
            :aria-checked="draft.enabled"
            :disabled="saving"
            class="web-switch transition-colors disabled:opacity-50"
            :class="draft.enabled ? 'bg-indigo-600 dark:bg-indigo-500' : 'bg-slate-300 dark:bg-slate-600'"
            @click="toggleService"
          >
            <span class="web-switch-knob bg-white shadow-sm" :class="{ 'web-switch-knob-on': draft.enabled }"></span>
          </button>
        </div>

        <div class="grid gap-5 sm:grid-cols-2">
          <label class="block">
            <span class="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-200">监听端口</span>
            <input v-model.number="draft.port" class="input font-mono" type="number" min="1" max="65535" :disabled="saving || draft.enabled" @change="saveNetworkSettings" />
          </label>
          <label class="block">
            <span class="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-200">监听范围</span>
            <AppSelect
              :model-value="draft.global"
              :options="listenScopeOptions"
              :disabled="saving || draft.enabled"
              aria-label="监听范围"
              @update:model-value="updateListenScope"
            />
          </label>
        </div>
        <p class="-mt-3 text-xs text-slate-400">端口和监听范围会自动保存；需要修改时请先关闭 Web 服务。</p>

        <div>
          <div class="mb-2 flex items-center justify-between gap-3">
            <span class="text-sm font-medium text-slate-700 dark:text-slate-200">访问令牌</span>
            <button class="text-xs font-medium text-indigo-600 hover:text-indigo-500 disabled:opacity-50 dark:text-indigo-400" type="button" :disabled="saving" @click="regenerate">更换令牌</button>
          </div>
          <code class="block min-w-0 truncate rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300">{{ draft.token }}</code>
          <p class="mt-2 text-xs text-slate-400">更换令牌后，已登录的浏览器需要使用新令牌重新鉴权。</p>
        </div>

        <div v-if="notice || error" class="border-t border-slate-200 pt-5 dark:border-slate-800">
          <span v-if="notice" class="text-xs text-green-600 dark:text-green-400">{{ notice }}</span>
          <span v-if="error" class="text-xs text-red-600 dark:text-red-400">{{ error }}</span>
        </div>
      </section>

      <section class="card">
        <div class="flex items-start gap-3">
          <span class="mt-1 h-2.5 w-2.5 shrink-0 rounded-full" :class="status?.running ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'"></span>
          <div class="min-w-0 flex-1">
            <div class="text-sm font-semibold text-slate-900 dark:text-white">{{ status?.running ? "运行中" : "未运行" }}</div>
            <div class="mt-1 text-xs text-slate-400">监听地址：{{ status?.listenAddress }}</div>
            <div v-if="status?.running" class="mt-4 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 font-mono text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300">
              <span class="block truncate">{{ status.url }}</span>
            </div>
            <div v-if="status?.running" class="mt-3 flex flex-wrap gap-2">
              <button class="btn-primary btn-sm" type="button" @click="openBrowser">打开浏览器</button>
              <button class="btn-ghost btn-sm" type="button" @click="copyUrl">复制访问地址</button>
            </div>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped>
.web-switch {
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

.web-switch-knob {
  display: block;
  width: 20px;
  min-width: 20px;
  height: 20px;
  border-radius: 9999px;
  transform: translateX(0);
  transition: transform 160ms ease;
}

.web-switch-knob-on {
  transform: translateX(20px);
}
</style>
