<script setup>
import { computed } from "vue";
import { useAppStore } from "../stores/app";
import StartPanel from "../components/StartPanel.vue";
import InstanceCard from "../components/InstanceCard.vue";
import EmptyState from "../components/EmptyState.vue";

const app = useAppStore();

// 在线设备数:汇总各 running 实例 info 的在线数
const onlineDevices = computed(() =>
  Object.values(app.instances).reduce(
    (sum, info) => sum + (info?.online_client_num || 0),
    0,
  ),
);

// 服务器连接:已连接的 running 实例数 / running 总数
const serverConnected = computed(() => {
  const running = app.instanceList.filter((i) => i.status === "running");
  const connected = running.filter((i) => {
    const info = app.instances[i.file_name];
    return info?.server_info?.some((s) => s.connected);
  });
  return { connected: connected.length, total: running.length };
});

const statusSummary = computed(() => {
  if (app.runningCount > 0) return `运行中 ${app.runningCount} 个实例`;
  if (app.startingCount > 0) return "有实例正在启动...";
  return "全部实例已停止";
});
</script>

<template>
  <div class="space-y-6">
    <!-- 欢迎/状态区 -->
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="page-title">总览</h1>
        <p class="page-subtitle">{{ statusSummary }}</p>
      </div>
      <router-link to="/config" class="btn-ghost btn-sm">管理配置</router-link>
    </div>

    <!-- 统计卡片 -->
    <div class="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <div class="card">
        <div class="text-xs font-medium muted">运行实例</div>
        <div class="mt-2 text-2xl font-bold tabular-nums text-slate-900 dark:text-white">
          {{ app.runningCount
          }}<span class="ml-1 text-sm font-normal muted">/ {{ app.instanceList.length }}</span>
        </div>
      </div>
      <div class="card">
        <div class="text-xs font-medium muted">配置总数</div>
        <div class="mt-2 text-2xl font-bold tabular-nums text-slate-900 dark:text-white">
          {{ app.configList.length }}
        </div>
      </div>
      <div class="card">
        <div class="text-xs font-medium muted">在线设备</div>
        <div class="mt-2 text-2xl font-bold tabular-nums text-slate-900 dark:text-white">
          {{ onlineDevices }}
        </div>
      </div>
      <div class="card">
        <div class="text-xs font-medium muted">服务器连接</div>
        <div class="mt-2 text-2xl font-bold tabular-nums text-slate-900 dark:text-white">
          <template v-if="serverConnected.total > 0">
            <span :class="serverConnected.connected > 0 ? 'text-green-600 dark:text-green-400' : 'text-red-500'">{{
              serverConnected.connected
            }}</span>
            <span class="text-sm font-normal muted">/ {{ serverConnected.total }} 已连接</span>
          </template>
          <span v-else class="muted">-</span>
        </div>
      </div>
    </div>

    <!-- 启动组网 -->
    <StartPanel />

    <!-- 实例概览 -->
    <div>
      <div class="mb-3 flex items-center justify-between">
        <h2 class="text-base font-bold text-slate-900 dark:text-white">实例概览</h2>
        <router-link
          to="/instances"
          class="text-sm font-medium text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
          >查看详情 →</router-link
        >
      </div>
      <EmptyState
        v-if="app.instanceList.length === 0"
        :text="app.configList.length === 0 ? '暂无配置，请先新建配置' : '暂无运行中的组网，请在上方选择配置启动'"
      />
      <TransitionGroup v-else name="card-list" tag="div" class="grid grid-cols-1 gap-4 md:grid-cols-2">
        <InstanceCard v-for="inst in app.instanceList" :key="inst.file_name" :inst="inst" />
      </TransitionGroup>
    </div>
  </div>
</template>
