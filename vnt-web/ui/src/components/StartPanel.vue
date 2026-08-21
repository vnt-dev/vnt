<script setup>
import { ref, computed, watch } from "vue";
import { useAppStore } from "../stores/app";
import { useUiStore } from "../stores/ui";
import AppSelect from "./AppSelect.vue";

// 启动组网面板:选择配置 + 启动,总览页与实例页复用
const app = useAppStore();
const ui = useUiStore();

const localSelectedConfig = ref("");

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
        class="btn-primary px-8"
        :disabled="!localSelectedConfig || !!app.loadingMap[localSelectedConfig]"
        @click="handleStart"
      >
        <span v-if="app.loadingMap[localSelectedConfig]" class="animate-spin">⟳</span>
        启动
      </button>
    </div>
  </div>
</template>
