<script setup>
import { ref, computed, watch } from "vue";
import { useAppStore } from "../stores/app";
import { useUiStore } from "../stores/ui";
import { getConfig } from "../api";
import AppSelect from "./AppSelect.vue";
import AppModal from "./AppModal.vue";

// 启动组网面板:选择配置 + 启动,总览页与实例页复用
const app = useAppStore();
const ui = useUiStore();

const localSelectedConfig = ref("");
const showPreview = ref(false);
const previewText = ref("");
const previewName = ref("");
const previewLoading = ref(false);

// 只列出没有对应实例的配置(同一配置最多一个实例)
const availableConfigs = computed(() =>
  app.configList.filter(
    (cfg) => !app.instanceList.some((inst) => inst.file_name === cfg.file_name),
  ),
);
const configOptions = computed(() =>
  availableConfigs.value.map((cfg) => ({
    value: cfg.file_name,
    label: cfg.config_name || cfg.file_name,
  })),
);

// 默认选中第一个可用配置;当前选中项不可用时(如已启动)自动切到下一个
watch(
  availableConfigs,
  (list) => {
    if (!list.some((cfg) => cfg.file_name === localSelectedConfig.value)) {
      localSelectedConfig.value = list.length ? list[0].file_name : "";
    }
  },
  { immediate: true },
);

const handleStart = () => {
  if (!localSelectedConfig.value) {
    ui.toast.error("请先选择一个配置");
    return;
  }
  app.startVnt(localSelectedConfig.value);
};

// 预览配置文件的原始内容(尚未启动,没有合并后的生效配置)
const openPreview = async (fileName) => {
  previewName.value = fileName;
  previewText.value = "";
  previewLoading.value = true;
  showPreview.value = true;
  try {
    previewText.value = await getConfig(fileName);
  } catch (e) {
    ui.toast.error(e.message);
    showPreview.value = false;
  } finally {
    previewLoading.value = false;
  }
};

const copyPreview = async () => {
  try {
    await navigator.clipboard.writeText(previewText.value);
    ui.toast.success("已复制");
  } catch {
    ui.toast.error("复制失败");
  }
};
</script>

<template>
  <div class="card">
    <h2 class="mb-4 text-base font-bold text-slate-900 dark:text-white">启动组网</h2>

    <div v-if="app.configList.length === 0" class="flex flex-wrap items-center justify-between gap-3">
      <p class="text-sm muted">还没有任何配置，先创建一个组网配置吧。</p>
      <router-link to="/config" class="btn-primary btn-sm">去新建配置</router-link>
    </div>

    <div v-else-if="availableConfigs.length === 0" class="text-sm muted">
      所有配置均已启动。
    </div>

    <div v-else class="flex flex-col gap-3 sm:flex-row sm:items-end">
      <div class="flex-1">
        <label class="mb-1.5 block text-xs font-medium muted">选择配置</label>
        <AppSelect v-model="localSelectedConfig" :options="configOptions" placeholder="请选择配置…" aria-label="选择配置" />
      </div>
      <button
        class="btn-ghost"
        :disabled="!localSelectedConfig"
        @click="openPreview(localSelectedConfig)"
      >
        预览
      </button>
      <button
        class="btn-primary px-8"
        :disabled="!localSelectedConfig || !!app.loadingMap[localSelectedConfig]"
        @click="handleStart"
      >
        <span v-if="app.loadingMap[localSelectedConfig]" class="animate-spin">⟳</span>
        启动
      </button>
    </div>
  </div>

  <AppModal :show="showPreview" panel-class="w-full max-w-2xl" @close="showPreview = false">
    <template #header>
      <div>
        <h2 class="text-lg font-bold text-slate-900 dark:text-white">配置预览</h2>
        <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">{{ previewName }}</p>
      </div>
      <div class="flex gap-2">
        <button class="btn-ghost btn-sm" type="button" :disabled="!previewText" @click="copyPreview">复制</button>
        <button class="btn-ghost btn-sm" type="button" @click="showPreview = false">关闭</button>
      </div>
    </template>
    <template #body>
      <div class="p-6">
        <div v-if="previewLoading" class="py-16 text-center text-sm muted">正在读取…</div>
        <pre v-else class="max-h-[60vh] overflow-auto rounded-lg bg-slate-50 p-4 font-mono text-xs leading-5 text-slate-800 dark:bg-slate-800 dark:text-slate-200">{{ previewText }}</pre>
      </div>
    </template>
  </AppModal>
</template>
