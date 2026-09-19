<script setup>
import { ref, onMounted } from "vue";
import QRCode from "qrcode";
import { useAppStore } from "../stores/app";
import { useUiStore } from "../stores/ui";
import { clearSubscriptionOverrides, deleteConfig, detachSubscription, getConfig, getSubscriptionStatus } from "../api";
import EmptyState from "../components/EmptyState.vue";
import AppModal from "../components/AppModal.vue";
import ConfigEditor from "./ConfigEditor.vue";
import { parseTomlToForm } from "../utils/toml";
import { buildNetworkQrPayload } from "../utils/networkQr";

const app = useAppStore();
const ui = useUiStore();

const showEditor = ref(false);
const editorFileName = ref(null);
const showQr = ref(false);
const qrLoading = ref(false);
const qrImage = ref("");
const qrConfig = ref(null);
const qrError = ref("");
const managedStatuses = ref({});
const managedDetail = ref(null);

const refreshSubscriptionStatuses = async () => {
  const entries = await Promise.all(app.configList.map(async (cfg) => {
    try { return [cfg.file_name, await getSubscriptionStatus(cfg.file_name)]; } catch { return [cfg.file_name, null]; }
  }));
  managedStatuses.value = Object.fromEntries(entries);
};

const openManagedDetail = async (fileName) => {
  try { managedDetail.value = await getSubscriptionStatus(fileName); } catch (e) { ui.toast.error(e.message); }
};

const managedAction = async (action) => {
  if (!managedDetail.value) return;
  try {
    const file = managedDetail.value.file_name;
    if (action === "clear") managedDetail.value = await clearSubscriptionOverrides(file);
    if (action === "detach") { await detachSubscription(file); managedDetail.value = null; }
    await refreshSubscriptionStatuses();
    ui.toast.success(
      action === "detach"
        ? "已解除服务端管理，当前 TOML 保留"
        : "已清除本地覆盖；运行中实例会在下次服务端推送或重启后使用新配置",
    );
  } catch (e) { ui.toast.error(e.message); }
};

// 配置对应的实例运行状态(无实例返回 null)
const instStatus = (fileName) => {
  const inst = app.instanceList.find((i) => i.file_name === fileName);
  return inst ? inst.status : null;
};

const cardClass = (fileName) => {
  const status = instStatus(fileName);
  if (status === "running") return "ring-2 ring-green-500/60";
  if (status === "starting") return "ring-2 ring-indigo-500/60";
  return "";
};

const openEditor = (fileName) => {
  editorFileName.value = fileName;
  showEditor.value = true;
};

const onSaved = async () => {
  await app.fetchConfigList();
  await refreshSubscriptionStatuses();
};

const openQr = async (fileName) => {
  showQr.value = true;
  qrLoading.value = true;
  qrImage.value = "";
  qrConfig.value = null;
  qrError.value = "";
  try {
    const form = parseTomlToForm(await getConfig(fileName));
    const payload = buildNetworkQrPayload(form);
    qrConfig.value = payload;
    qrImage.value = await QRCode.toDataURL(JSON.stringify(payload), {
      errorCorrectionLevel: "M",
      width: 360,
      margin: 2,
      color: { dark: "#020617", light: "#ffffff" },
    });
  } catch (e) {
    qrError.value = e.message || "二维码生成失败";
  } finally {
    qrLoading.value = false;
  }
};

const handleDelete = async (fileName) => {
  const ok = await ui.confirm({
    title: "删除配置",
    message: `确定要删除配置 ${fileName} 吗?`,
    danger: true,
    confirmText: "删除",
  });
  if (!ok) return;
  try {
    await deleteConfig(fileName);
    ui.toast.success("配置已删除");
    app.fetchConfigList();
  } catch (e) {
    ui.toast.error(e.message);
  }
};

onMounted(async () => { await app.fetchConfigList(); await refreshSubscriptionStatuses(); });
</script>

<template>
  <div class="page-stack">
    <Teleport to="#page-actions">
      <div class="flex gap-2">
      <button class="btn-primary btn-sm" @click="openEditor(null)">
        <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
        新建配置
      </button>
      </div>
    </Teleport>

    <EmptyState v-if="app.configList.length === 0" text="暂无配置，点击右上角新建" />

    <div v-else class="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
      <div
        v-for="cfg in app.configList"
        :key="cfg.file_name"
        :class="cardClass(cfg.file_name)"
        class="card group relative flex min-h-[140px] cursor-pointer flex-col justify-between overflow-hidden"
        @click="openEditor(cfg.file_name)"
      >
        <button
          class="absolute right-3 top-3 z-10 rounded-lg p-1.5 text-slate-400 transition hover:bg-indigo-50 hover:text-indigo-600 focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:hover:bg-indigo-500/10 dark:hover:text-indigo-400"
          type="button"
          title="显示加入网络二维码"
          aria-label="显示加入网络二维码"
          @click.stop="openQr(cfg.file_name)"
        >
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 3h7v7H3V3zm11 0h7v7h-7V3zM3 14h7v7H3v-7zm12 0h2m4 0v2m-6 2h2v3m4-3v3h-2" />
          </svg>
        </button>
        <div
          v-if="instStatus(cfg.file_name) === 'running'"
          class="absolute right-12 top-3 rounded bg-green-500 px-2 py-1 text-xs text-white"
        >
          运行中
        </div>
        <button
          v-if="managedStatuses[cfg.file_name]"
          class="absolute left-4 bottom-4 rounded bg-violet-100 px-2 py-1 text-[11px] font-semibold text-violet-700 dark:bg-violet-500/10 dark:text-violet-300"
          @click.stop="openManagedDetail(cfg.file_name)"
        >订阅链接</button>
        <div
          v-else-if="instStatus(cfg.file_name) === 'starting'"
          class="absolute right-12 top-3 rounded bg-indigo-500 px-2 py-1 text-xs text-white"
        >
          启动中
        </div>
        <div class="flex items-start pr-28">
          <div class="mr-3 mt-1 rounded-lg bg-indigo-50 p-2 text-indigo-600 dark:bg-indigo-500/10 dark:text-indigo-400">
            <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
          </div>
          <div class="overflow-hidden">
            <h3 class="truncate text-lg font-bold text-slate-900 dark:text-white" :title="cfg.config_name">
              {{ cfg.config_name || "Unnamed" }}
            </h3>
            <p class="truncate font-mono text-xs text-slate-400" :title="cfg.file_name">
              {{ cfg.file_name }}
            </p>
          </div>
        </div>
        <div class="config-card-actions mt-4 flex justify-end transition-opacity">
          <button
            class="mr-4 text-sm text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
            @click.stop="openEditor(cfg.file_name)"
          >
            编辑
          </button>
          <button class="text-sm text-red-500 hover:text-red-400" @click.stop="handleDelete(cfg.file_name)">
            删除
          </button>
        </div>
      </div>
    </div>

    <ConfigEditor
      :show="showEditor"
      :file-name="editorFileName"
      @close="showEditor = false"
      @saved="onSaved"
    />

    <AppModal :show="showQr" panel-class="w-full max-w-md" @close="showQr = false">
      <template #header>
        <div>
          <h2 class="text-lg font-bold text-slate-900 dark:text-white">扫码加入网络</h2>
          <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">使用 VNT 安卓客户端扫描</p>
        </div>
        <button class="btn-ghost btn-sm" type="button" @click="showQr = false">关闭</button>
      </template>
      <template #body>
        <div class="p-6">
          <div v-if="qrLoading" class="py-20 text-center text-sm muted">正在生成二维码…</div>
          <div v-else-if="qrError" class="rounded-lg bg-red-50 p-4 text-sm text-red-600 dark:bg-red-500/10 dark:text-red-400">
            {{ qrError }}
          </div>
          <div v-else-if="qrConfig" class="space-y-5">
            <div class="mx-auto w-fit rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
              <img :src="qrImage" class="h-auto w-full max-w-[320px]" alt="VNT 加入网络二维码" />
            </div>
            <dl class="space-y-2 rounded-lg bg-slate-50 p-4 text-sm dark:bg-slate-800/60">
              <div class="flex gap-3"><dt class="w-20 shrink-0 muted">组网编号</dt><dd class="min-w-0 break-all font-mono text-slate-900 dark:text-white">{{ qrConfig.network_code }}</dd></div>
              <div class="flex gap-3"><dt class="w-20 shrink-0 muted">服务器</dt><dd class="min-w-0 break-all font-mono text-slate-900 dark:text-white">{{ qrConfig.server.join(", ") }}</dd></div>
              <div class="flex gap-3"><dt class="w-20 shrink-0 muted">MTU</dt><dd class="font-mono text-slate-900 dark:text-white">{{ qrConfig.mtu }}</dd></div>
              <div class="flex gap-3"><dt class="w-20 shrink-0 muted">加密密码</dt><dd class="text-slate-900 dark:text-white">{{ qrConfig.password ? "已包含" : "未设置" }}</dd></div>
            </dl>
            <p class="text-xs leading-5 text-amber-600 dark:text-amber-400">二维码包含组网凭据，请仅分享给可信设备。</p>
          </div>
        </div>
      </template>
    </AppModal>

    <AppModal :show="Boolean(managedDetail)" panel-class="w-full max-w-lg" @close="managedDetail = null">
      <template #header><div><h2 class="text-lg font-bold">服务端管理</h2><p class="mt-1 text-xs muted">字段来源与同步状态</p></div><button class="btn-ghost btn-sm" @click="managedDetail = null">关闭</button></template>
      <template #body><div v-if="managedDetail" class="space-y-4 p-6 text-sm">
        <dl class="grid grid-cols-[8rem_1fr] gap-2 rounded-lg bg-slate-50 p-4 dark:bg-slate-800"><dt class="muted">设备</dt><dd class="font-mono">{{ managedDetail.device_id }}</dd><dt class="muted">配置版本</dt><dd>{{ managedDetail.applied_revision }} / {{ managedDetail.target_revision }}</dd><dt class="muted">实时同步</dt><dd>{{ managedDetail.config_sync_verified ? '已验证同步服务器' : '暂无已验证同步服务器' }}</dd><dt class="muted">本地覆盖</dt><dd>{{ managedDetail.local_overrides.length ? managedDetail.local_overrides.join(', ') : '无' }}</dd><dt v-if="managedDetail.last_error" class="muted">错误</dt><dd v-if="managedDetail.last_error" class="text-red-500">{{ managedDetail.last_error }}</dd></dl>
        <div class="flex flex-wrap gap-2"><button class="btn-secondary" @click="managedAction('clear')">清除本地覆盖</button><button class="btn-danger" @click="managedAction('detach')">解除服务端管理</button></div>
      </div></template>
    </AppModal>
  </div>
</template>

<style scoped>
/* 触屏和窄屏设备没有可靠的 hover，操作按钮必须直接可见。 */
.config-card-actions {
  opacity: 1;
}

/* 只有宽屏且确实支持精细悬停的设备才使用移入显示。 */
@media (min-width: 640px) and (hover: hover) and (pointer: fine) {
  .config-card-actions {
    opacity: 0;
  }

  .group:hover .config-card-actions,
  .group:focus-within .config-card-actions {
    opacity: 1;
  }
}
</style>
