<script setup>
import { computed } from "vue";
import { useAppStore } from "../stores/app";
import { useStartLogStore } from "../stores/startLog";
import { useUiStore } from "../stores/ui";

const props = defineProps({
  inst: { type: Object, required: true },
  // 是否显示选中高亮(实例页用)
  selectable: { type: Boolean, default: false },
});

const app = useAppStore();
const startLog = useStartLogStore();
const ui = useUiStore();

const info = computed(() => app.infoOf(props.inst.file_name));
const loading = computed(() => !!app.loadingMap[props.inst.file_name]);
// 停止中:点击停止后直到实例真正消失/停止
const stopping = computed(() => !!app.stoppingMap[props.inst.file_name]);
// 展示名优先用配置名称,兜底文件名
const displayName = computed(() => props.inst.config_name || props.inst.file_name);

const statusBadgeClass = (status) =>
  stopping.value
    ? "badge-yellow"
    : status === "running"
      ? "badge-green"
      : status === "starting"
        ? "badge-blue"
        : "badge-gray";
const statusText = (status) =>
  stopping.value
    ? "停止中"
    : status === "running"
      ? "运行中"
      : status === "starting"
        ? "启动中"
        : "已停止";

const select = () => {
  if (props.selectable) app.selectedInstance = props.inst.file_name;
};

const confirmStop = async () => {
  const ok = await ui.confirm({
    title: "停止组网",
    message: `确定要停止 ${displayName.value} 吗?`,
    danger: true,
    confirmText: "停止",
  });
  if (ok) app.stopVnt(props.inst.file_name);
};

const confirmRestart = async () => {
  const ok = await ui.confirm({
    title: "重启组网",
    message: `确定要重启 ${displayName.value} 吗?`,
  });
  if (ok) app.restartVnt(props.inst.file_name);
};

const confirmDismiss = async () => {
  const ok = await ui.confirm({
    title: "移除实例",
    message: `确定要移除已停止的实例 ${displayName.value} 吗?`,
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
        {{ displayName }}
      </h3>
      <div class="flex shrink-0 items-center gap-1.5">
        <span
          v-if="info.config_changed"
          class="badge-yellow"
          title="配置文件在启动后被修改，重启实例后生效"
        >
          配置发生变化
        </span>
        <span :class="[statusBadgeClass(inst.status), stopping ? 'animate-pulse' : '']">{{
          statusText(inst.status)
        }}</span>
      </div>
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
      <template v-if="stopping">
        <span class="flex items-center gap-1.5 text-xs muted">
          <span class="inline-block animate-spin">⟳</span>
          正在停止，请稍候...
        </span>
      </template>
      <template v-else>
        <button
          v-if="inst.status === 'stopped'"
          class="btn-ghost btn-sm"
          @click.stop="startLog.openStartLog(inst.file_name)"
        >
          日志
        </button>
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
      </template>
    </div>
  </div>
</template>
