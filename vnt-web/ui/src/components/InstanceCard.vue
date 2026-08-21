<script setup>
import { computed } from "vue";
import { useAppStore } from "../stores/app";
import { useUiStore } from "../stores/ui";

const props = defineProps({
  inst: { type: Object, required: true },
  // 是否显示选中高亮(实例页用)
  selectable: { type: Boolean, default: false },
});

const app = useAppStore();
const ui = useUiStore();

const info = computed(() => app.infoOf(props.inst.file_name));
const loading = computed(() => !!app.loadingMap[props.inst.file_name]);

const statusBadgeClass = (status) =>
  status === "running" ? "badge-green" : status === "starting" ? "badge-blue" : "badge-gray";
const statusText = (status) =>
  status === "running" ? "运行中" : status === "starting" ? "启动中" : "已停止";

const select = () => {
  if (props.selectable) app.selectedInstance = props.inst.file_name;
};

const confirmStop = async () => {
  const ok = await ui.confirm({
    title: "停止组网",
    message: `确定要停止 ${props.inst.file_name} 吗?`,
    danger: true,
    confirmText: "停止",
  });
  if (ok) app.stopVnt(props.inst.file_name);
};

const confirmRestart = async () => {
  const ok = await ui.confirm({
    title: "重启组网",
    message: `确定要重启 ${props.inst.file_name} 吗?`,
  });
  if (ok) app.restartVnt(props.inst.file_name);
};

const confirmDismiss = async () => {
  const ok = await ui.confirm({
    title: "移除实例",
    message: `确定要移除已停止的实例 ${props.inst.file_name} 吗?`,
    danger: true,
    confirmText: "移除",
  });
  if (ok) app.dismissInstance(props.inst.file_name);
};
</script>

<template>
  <div
    class="card"
    :class="[
      selectable ? 'cursor-pointer' : '',
      selectable && app.selectedInstance === inst.file_name
        ? 'ring-2 ring-indigo-500 dark:ring-indigo-400'
        : '',
    ]"
    @click="select"
  >
    <div class="flex items-center justify-between gap-2">
      <h3 class="truncate text-base font-bold text-slate-900 dark:text-white" :title="inst.file_name">
        {{ inst.config_name || inst.file_name }}
      </h3>
      <span class="shrink-0" :class="statusBadgeClass(inst.status)">{{ statusText(inst.status) }}</span>
    </div>

    <div class="mt-2 text-sm">
      <span class="muted">虚拟 IP:</span>
      <span class="ml-1 font-mono tabular-nums text-indigo-600 dark:text-indigo-400">{{
        info.ip || "-"
      }}</span>
    </div>

    <div class="mt-3 flex gap-4 text-xs muted">
      <span>
        在线
        <span class="font-bold tabular-nums text-blue-600 dark:text-blue-400">{{
          info.online_client_num || 0
        }}</span>
      </span>
      <span>
        直连
        <span class="font-bold tabular-nums text-green-600 dark:text-green-400">{{
          info.direct_client_num || 0
        }}</span>
      </span>
      <span>
        离线
        <span class="font-bold tabular-nums text-slate-400">{{ info.offline_client_num || 0 }}</span>
      </span>
    </div>

    <div class="mt-4 flex flex-wrap justify-end gap-2">
      <button
        v-if="inst.status === 'running' || inst.status === 'stopped'"
        class="btn-primary btn-sm"
        :disabled="loading"
        @click.stop="confirmRestart"
      >
        <span v-if="loading" class="animate-spin">⟳</span>
        {{ inst.status === "stopped" ? "重新启动" : "重启" }}
      </button>
      <button
        v-if="inst.status !== 'stopped'"
        class="btn-danger btn-sm"
        :disabled="loading"
        @click.stop="confirmStop"
      >
        <span v-if="loading" class="animate-spin">⟳</span>
        停止
      </button>
      <button
        v-if="inst.status === 'stopped'"
        class="btn-ghost btn-sm"
        :disabled="loading"
        @click.stop="confirmDismiss"
      >
        <span v-if="loading" class="animate-spin">⟳</span>
        移除
      </button>
    </div>
  </div>
</template>
