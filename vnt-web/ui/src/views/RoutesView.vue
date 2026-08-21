<script setup>
import { ref, onMounted, onUnmounted, watch } from "vue";
import { useAppStore } from "../stores/app";
import { getRoutes } from "../api";
import StatusDot from "../components/StatusDot.vue";
import EmptyState from "../components/EmptyState.vue";

const app = useAppStore();
const routes = ref([]);
let timer = null;

const currentStatus = () => {
  const inst = app.instanceList.find((i) => i.file_name === app.selectedInstance);
  return inst ? inst.status : null;
};

const fetchRoutes = async () => {
  if (!app.selectedInstance || currentStatus() !== "running") {
    routes.value = [];
    return;
  }
  try {
    routes.value = (await getRoutes(app.selectedInstance)) || [];
  } catch (e) {
    console.error(e);
  }
};

onMounted(() => {
  fetchRoutes();
  timer = setInterval(() => {
    if (app.isPageVisible) fetchRoutes();
  }, 3000);
});

onUnmounted(() => {
  if (timer) clearInterval(timer);
});

// 切换实例时重新拉取
watch(
  () => app.selectedInstance,
  () => {
    fetchRoutes();
  },
);

// 监听选中实例状态变化,当变为 running 时立即获取数据
watch(currentStatus, (newStatus) => {
  if (newStatus === "running") {
    fetchRoutes();
  }
});

const switcherClass = (fileName) =>
  app.selectedInstance === fileName
    ? "border-indigo-600 bg-indigo-600 text-white dark:border-indigo-500 dark:bg-indigo-500"
    : "border-slate-300 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700";
</script>

<template>
  <div class="space-y-4">
    <div>
      <h1 class="page-title">路由</h1>
      <p class="page-subtitle">查看各实例的路由表</p>
    </div>

    <!-- 实例切换器 -->
    <div v-if="app.instanceList.length > 0" class="scrollbar-hide flex items-center gap-2 overflow-x-auto">
      <button
        v-for="inst in app.instanceList"
        :key="inst.file_name"
        @click="app.selectedInstance = inst.file_name"
        :class="switcherClass(inst.file_name)"
        class="flex shrink-0 items-center rounded-lg border px-4 py-2 text-sm font-medium transition-colors"
      >
        <StatusDot :status="inst.status" size="w-2 h-2" class="mr-2" />
        {{ inst.config_name || inst.file_name }}
      </button>
    </div>

    <EmptyState v-if="!app.selectedInstance" text="暂无运行中的组网实例" />

    <div v-else class="card overflow-hidden p-0">
      <div class="border-b border-slate-200 px-6 py-4 dark:border-slate-700">
        <h2 class="text-base font-bold text-slate-900 dark:text-white">路由表</h2>
      </div>
      <div class="custom-scrollbar max-h-[600px] overflow-x-auto">
        <table class="table">
          <thead>
            <tr>
              <th>目标节点IP</th>
              <th>目标网络</th>
              <th>跳数</th>
              <th>延迟</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="item in routes" :key="item.ip">
              <tr
                v-for="(route, rIdx) in item.routes"
                :key="rIdx"
                class="hover:bg-slate-50 dark:hover:bg-slate-800/50"
              >
                <td
                  v-if="rIdx === 0"
                  :rowspan="item.routes.length"
                  class="font-mono tabular-nums text-indigo-600 dark:text-indigo-400"
                >
                  {{ item.ip }}
                </td>
                <td class="font-mono tabular-nums text-yellow-700 dark:text-yellow-300">{{ route.addr }}</td>
                <td class="tabular-nums">{{ route.metric }}</td>
                <td class="tabular-nums">{{ route.rtt }} ms</td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
