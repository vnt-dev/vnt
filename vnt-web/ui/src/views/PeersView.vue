<script setup>
import { ref, reactive, onMounted, onUnmounted, watch, inject } from "vue";
import { useAppStore } from "../stores/app";
import { getPeers } from "../api";
import { formatTime, formatBytes, formatSpeed } from "../utils/format";
import StatusDot from "../components/StatusDot.vue";
import EmptyState from "../components/EmptyState.vue";
import SpeedChart from "../components/SpeedChart.vue";

const app = useAppStore();
const tooltipRef = inject("peerTooltip");
const showPeerTooltip = (e, peer) => tooltipRef.value?.showPeerTooltip(e, peer);
const hidePeerTooltip = () => tooltipRef.value?.hidePeerTooltip();

const peers = ref([]);
let timer = null;
// 记录上次流量数据和时间,用于前端计算网速
let lastTrafficMap = {};
let lastFetchTime = 0;
// 展开状态和网速历史
const expandedPeers = reactive({});
const speedHistoryMap = reactive({});
const HISTORY_SIZE = 60;

const toggleExpand = (ip) => {
  expandedPeers[ip] = !expandedPeers[ip];
};

const currentStatus = () => {
  const inst = app.instanceList.find((i) => i.file_name === app.selectedInstance);
  return inst ? inst.status : null;
};

const resetPeerState = () => {
  peers.value = [];
  lastTrafficMap = {};
  lastFetchTime = 0;
  for (const key in speedHistoryMap) delete speedHistoryMap[key];
  for (const key in expandedPeers) delete expandedPeers[key];
};

const fetchPeers = async () => {
  if (!app.selectedInstance || currentStatus() !== "running") {
    resetPeerState();
    return;
  }
  try {
    const list = (await getPeers(app.selectedInstance)) || [];
    const now = Date.now();
    const elapsed = lastFetchTime > 0 ? (now - lastFetchTime) / 1000 : 0;
    const newTrafficMap = {};
    for (const peer of list) {
      if (peer.traffic) {
        const key = peer.ip;
        const prev = lastTrafficMap[key];
        if (prev && elapsed > 0) {
          const txDiff = Math.max(0, peer.traffic.tx_bytes - prev.tx_bytes);
          const rxDiff = Math.max(0, peer.traffic.rx_bytes - prev.rx_bytes);
          peer.traffic.tx_speed = Math.round(txDiff / elapsed);
          peer.traffic.rx_speed = Math.round(rxDiff / elapsed);
        } else {
          peer.traffic.tx_speed = 0;
          peer.traffic.rx_speed = 0;
        }
        newTrafficMap[key] = { tx_bytes: peer.traffic.tx_bytes, rx_bytes: peer.traffic.rx_bytes };
        // 记录速度历史
        if (!speedHistoryMap[key]) speedHistoryMap[key] = { tx: [], rx: [] };
        speedHistoryMap[key].tx.push(peer.traffic.tx_speed);
        speedHistoryMap[key].rx.push(peer.traffic.rx_speed);
        if (speedHistoryMap[key].tx.length > HISTORY_SIZE) {
          speedHistoryMap[key].tx.shift();
          speedHistoryMap[key].rx.shift();
        }
      }
    }
    lastTrafficMap = newTrafficMap;
    lastFetchTime = now;
    peers.value = list;
  } catch (e) {
    console.error(e);
  }
};

onMounted(() => {
  fetchPeers();
  timer = setInterval(() => {
    if (app.isPageVisible) fetchPeers();
  }, 3000);
});

onUnmounted(() => {
  if (timer) clearInterval(timer);
});

// 切换实例时重置并重新拉取
watch(
  () => app.selectedInstance,
  () => {
    resetPeerState();
    fetchPeers();
  },
);

// 监听选中实例状态变化,当变为 running 时立即获取数据
watch(currentStatus, (newStatus) => {
  if (newStatus === "running") {
    fetchPeers();
  }
});

const getRouteModeClass = (route) => {
  // 判断是否直连:metric === 1
  const isDirect = route.metric === 1;
  if (isDirect) {
    return "font-medium text-green-600 dark:text-green-400";
  } else {
    return "text-blue-600 dark:text-blue-400";
  }
};

const getRouteModeText = (route) => {
  const isDirect = route.metric === 1;
  const isTcp = route.protocol.includes("Tcp");
  if (isDirect) {
    return isTcp ? "打洞TCP直连" : "打洞UDP直连";
  } else {
    return isTcp ? "客户端TCP中继" : "客户端UDP中继";
  }
};

const keyEqualText = (keyEqual) =>
  keyEqual === 3
    ? "己方加密对方未加密"
    : keyEqual === 4
      ? "己方未加密对方加密"
      : keyEqual === 5
        ? "密钥不一致"
        : "未知错误";

const switcherClass = (fileName) =>
  app.selectedInstance === fileName
    ? "border-indigo-600 bg-indigo-600 text-white dark:border-indigo-500 dark:bg-indigo-500"
    : "border-slate-300 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700";
</script>

<template>
  <div class="space-y-4">
    <div>
      <h1 class="page-title">设备列表</h1>
      <p class="page-subtitle">查看各实例的设备连接与流量状况</p>
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
      <div class="flex items-center justify-between border-b border-slate-200 px-6 py-4 dark:border-slate-700">
        <h2 class="text-base font-bold text-slate-900 dark:text-white">设备列表</h2>
        <div class="flex gap-4 text-sm muted">
          <span>
            Online:
            <span class="font-medium tabular-nums text-slate-900 dark:text-white">{{
              peers.filter((p) => p.online).length
            }}</span>
          </span>
          <span>
            Total:
            <span class="font-medium tabular-nums text-slate-900 dark:text-white">{{ peers.length }}</span>
          </span>
        </div>
      </div>
      <div class="custom-scrollbar max-h-[600px] overflow-x-auto">
        <table class="table peer-table">
          <thead>
            <tr>
              <th class="w-8 px-2"></th>
              <th>IP地址</th>
              <th>名称</th>
              <th class="hidden md:table-cell">版本</th>
              <th>状态</th>
              <th>模式</th>
              <th>延迟</th>
              <th>丢包率</th>
              <th>流量</th>
              <th class="hidden md:table-cell">最后在线</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="peer in peers" :key="peer.ip">
              <tr class="transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/50">
                <td class="cursor-pointer select-none px-2 text-center" @click="toggleExpand(peer.ip)">
                  <svg
                    class="inline-block h-4 w-4 text-slate-400 transition-transform duration-200"
                    :class="{ 'rotate-90': expandedPeers[peer.ip] }"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                  </svg>
                </td>
                <td class="font-mono tabular-nums text-indigo-600 dark:text-indigo-400">
                  <span
                    class="cursor-help border-b border-dotted border-indigo-400/50 pb-0.5"
                    @mouseenter="showPeerTooltip($event, peer)"
                    @mouseleave="hidePeerTooltip"
                  >
                    {{ peer.ip }}
                  </span>
                </td>
                <td>{{ peer.name || "-" }}</td>
                <td class="hidden text-xs text-slate-400 md:table-cell">{{ peer.version || "-" }}</td>
                <td>
                  <div class="flex items-center gap-2">
                    <span :class="peer.online ? 'badge-green' : 'badge-gray'">{{
                      peer.online ? "在线" : "离线"
                    }}</span>
                    <!-- 加密状态图标 -->
                    <div v-if="peer.online && peer.key_equal === 1" class="tooltip">
                      <svg class="h-4 w-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                        />
                      </svg>
                      <span class="tooltip-text">双方加密传输</span>
                    </div>
                    <div v-else-if="peer.online && peer.key_equal === 2" class="tooltip">
                      <svg class="h-4 w-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"
                        />
                      </svg>
                      <span class="tooltip-text">双方未加密</span>
                    </div>
                    <div v-else-if="peer.online && [3, 4, 5].includes(peer.key_equal)" class="tooltip cursor-help">
                      <svg class="h-4 w-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                      <span class="tooltip-text">{{ keyEqualText(peer.key_equal) }}</span>
                    </div>
                  </div>
                </td>
                <td>
                  <span v-if="peer.online && peer.route" :class="getRouteModeClass(peer.route)">{{
                    getRouteModeText(peer.route)
                  }}</span>
                  <span v-else-if="peer.online" class="text-yellow-600 dark:text-yellow-400">服务器中继</span>
                  <span v-else class="text-slate-400">-</span>
                </td>
                <td class="tabular-nums">{{ peer.route ? peer.route.rtt + " ms" : "-" }}</td>
                <td>
                  <span
                    v-if="peer.packet_loss"
                    :class="
                      peer.packet_loss.loss_rate > 10
                        ? 'text-red-600 dark:text-red-400'
                        : peer.packet_loss.loss_rate > 5
                          ? 'text-yellow-600 dark:text-yellow-400'
                          : 'text-green-600 dark:text-green-400'
                    "
                    :title="'Sent: ' + peer.packet_loss.sent + ', Received: ' + peer.packet_loss.received"
                    >{{ peer.packet_loss.loss_rate.toFixed(1) }}%</span
                  >
                  <span v-else class="text-slate-400">-</span>
                </td>
                <td class="text-xs">
                  <div v-if="peer.traffic" class="leading-relaxed">
                    <div class="text-green-600 tabular-nums dark:text-green-400">
                      ↑ {{ formatBytes(peer.traffic.tx_bytes) }} ({{ formatSpeed(peer.traffic.tx_speed) }})
                    </div>
                    <div class="text-blue-600 tabular-nums dark:text-blue-400">
                      ↓ {{ formatBytes(peer.traffic.rx_bytes) }} ({{ formatSpeed(peer.traffic.rx_speed) }})
                    </div>
                  </div>
                  <span v-else class="text-slate-400">-</span>
                </td>
                <td class="hidden font-mono text-xs text-slate-400 md:table-cell">
                  {{ formatTime(peer.last_connected_time) }}
                </td>
              </tr>
              <tr v-if="expandedPeers[peer.ip]">
                <td colspan="10" class="p-0">
                  <div class="border-t border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-700/50 dark:bg-slate-950/60">
                    <SpeedChart :history="speedHistoryMap[peer.ip] || { tx: [], rx: [] }" :size="60" />
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.peer-table :deep(thead th) {
  padding: 0.5rem;
  font-size: 0.6875rem;
}

.peer-table :deep(tbody td) {
  padding: 0.5rem;
  font-size: 0.75rem;
}

.peer-table :deep(th:first-child),
.peer-table :deep(td:first-child) {
  padding-left: 0.25rem;
  padding-right: 0;
}
</style>
