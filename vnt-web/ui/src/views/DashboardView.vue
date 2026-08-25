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

</script>

<template>
  <div class="page-stack">
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
        <div
          class="mt-2 text-2xl font-bold tabular-nums"
          :class="onlineDevices > 0 ? 'text-green-600 dark:text-green-400' : 'text-slate-900 dark:text-white'"
        >
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

    <!-- 实例列表 -->
    <div>
      <div class="mb-3 flex items-center justify-between">
        <h2 class="text-base font-bold text-slate-900 dark:text-white">组网实例</h2>
        <span v-if="app.instanceList.length > 0" class="text-xs muted">点击卡片查看详情</span>
      </div>
      <EmptyState
        v-if="app.instanceList.length === 0"
        :text="app.configList.length === 0 ? '暂无配置，请先新建配置' : '暂无运行中的组网，请在上方选择配置启动'"
      />
      <TransitionGroup v-else name="card-list" tag="div" class="grid grid-cols-1 gap-4 md:grid-cols-2">
        <InstanceCard v-for="inst in app.instanceList" :key="inst.file_name" :inst="inst" selectable />
      </TransitionGroup>
    </div>

    <!-- 选中实例详情 -->
    <template v-if="app.selectedInstance && app.selectedInfo">
      <div class="card">
        <h2 class="mb-4 text-lg font-bold text-slate-900 dark:text-white">
          网络详情
          <span class="ml-2 text-sm font-medium text-indigo-600 dark:text-indigo-400">{{
            app.selectedConfigName
          }}</span>
        </h2>
        <div class="grid grid-cols-1 gap-4 text-sm md:grid-cols-2">
          <div class="flex justify-between border-b border-slate-100 pb-2 dark:border-slate-700">
            <span class="muted">虚拟 IP / 掩码</span>
            <span class="font-mono tabular-nums text-slate-900 dark:text-white"
              >{{ app.selectedInfo.ip || "-" }} / {{ app.selectedInfo.prefix_len || "-" }}</span
            >
          </div>
          <div class="flex justify-between border-b border-slate-100 pb-2 dark:border-slate-700">
            <span class="muted">网关</span>
            <span class="font-mono text-slate-900 dark:text-white">{{ app.selectedInfo.gateway || "-" }}</span>
          </div>
          <div class="flex justify-between border-b border-slate-100 pb-2 dark:border-slate-700">
            <span class="muted">网络编号</span>
            <span class="font-mono text-slate-900 dark:text-white">{{ app.selectedInfo.network_code || "-" }}</span>
          </div>
          <div class="flex justify-between border-b border-slate-100 pb-2 dark:border-slate-700">
            <span class="muted">MTU</span>
            <span class="font-mono tabular-nums text-slate-900 dark:text-white">{{ app.selectedInfo.mtu || "" }}</span>
          </div>
          <div class="flex justify-between border-b border-slate-100 pb-2 dark:border-slate-700">
            <span class="muted">NAT 类型</span>
            <span class="font-mono text-indigo-600 dark:text-indigo-400">{{
              app.selectedInfo.nat_type || "Unknown"
            }}</span>
          </div>
          <div class="flex justify-between border-b border-slate-100 pb-2 dark:border-slate-700">
            <span class="muted">Public IPv6</span>
            <span
              class="max-w-[200px] truncate font-mono text-slate-900 dark:text-white"
              :title="app.selectedInfo.public_ipv6"
              >{{ app.selectedInfo.public_ipv6 || "-" }}</span
            >
          </div>
          <div class="flex justify-between border-b border-slate-100 pb-2 dark:border-slate-700">
            <span class="muted">设备名称</span>
            <span class="text-slate-900 dark:text-white">{{ app.selectedInfo.name || "-" }}</span>
          </div>
          <div class="flex justify-between border-b border-slate-100 pb-2 dark:border-slate-700">
            <span class="muted">设备 ID</span>
            <span
              class="max-w-[200px] truncate font-mono text-xs text-slate-500 dark:text-slate-400"
              :title="app.selectedInfo.device_id"
              >{{ app.selectedInfo.device_id || "-" }}</span
            >
          </div>
        </div>
        <div class="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <div
            v-for="feat in [
              { key: 'encrypt', label: '加密' },
              { key: 'compress', label: '压缩' },
              { key: 'fec', label: 'FEC纠错' },
              { key: 'rtx', label: 'QUIC传输' },
            ]"
            :key="feat.key"
            class="flex items-center gap-2 rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-800/50"
          >
            <span
              class="h-2 w-2 rounded-full"
              :class="app.selectedInfo[feat.key] ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'"
            ></span>
            <span class="text-sm text-slate-600 dark:text-slate-300">{{ feat.label }}</span>
          </div>
        </div>
        <div class="mt-4">
          <span class="mb-2 block text-sm muted">Public IPv4s</span>
          <div class="flex flex-wrap gap-2">
            <span
              v-for="pip in app.selectedInfo.public_ipv4s"
              :key="pip"
              class="rounded border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-xs tabular-nums text-green-700 dark:border-slate-600 dark:bg-slate-800 dark:text-green-300"
              >{{ pip }}</span
            >
            <span
              v-if="!app.selectedInfo.public_ipv4s || app.selectedInfo.public_ipv4s.length === 0"
              class="text-xs text-slate-400"
              >无</span
            >
          </div>
        </div>
      </div>

      <div class="card p-0 overflow-hidden">
        <div class="border-b border-slate-200 px-6 py-4 dark:border-slate-700">
          <h2 class="text-lg font-bold text-slate-900 dark:text-white">服务器连接列表</h2>
        </div>
        <div class="custom-scrollbar max-h-[400px] overflow-x-auto">
          <table class="table">
            <thead>
              <tr>
                <th>地址</th>
                <th>状态</th>
                <th>延迟</th>
                <th>版本</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(server, idx) in app.selectedInfo.server_info" :key="idx">
                <td class="font-mono">{{ server.server }}</td>
                <td>
                  <span :class="server.connected ? 'badge-green' : 'badge-red'">
                    {{ server.connected ? "已连接" : "未连接" }}
                  </span>
                </td>
                <td class="tabular-nums">{{ server.server_rtt ? server.server_rtt + " ms" : "-" }}</td>
                <td>{{ server.server_version || "-" }}</td>
              </tr>
              <tr v-if="!app.selectedInfo.server_info || app.selectedInfo.server_info.length === 0">
                <td colspan="4" class="text-center text-slate-400">暂无数据</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
