<script setup>
import { ref } from "vue";

// 全局 NAT tooltip(保留原定位/悬停逻辑)
const tooltipState = ref({ show: false, x: 0, y: 0, info: null });
let tooltipHideTimer = null;

const showPeerTooltip = (event, peer) => {
  if (!peer.nat_info) return;
  if (tooltipHideTimer) {
    clearTimeout(tooltipHideTimer);
    tooltipHideTimer = null;
  }
  const rect = event.currentTarget.getBoundingClientRect();
  tooltipState.value = {
    show: true,
    x: rect.left + rect.width / 2,
    y: rect.bottom + 10,
    info: peer.nat_info,
  };
};

const hidePeerTooltip = () => {
  tooltipHideTimer = setTimeout(() => {
    tooltipState.value.show = false;
  }, 100);
};

const onTooltipEnter = () => {
  if (tooltipHideTimer) {
    clearTimeout(tooltipHideTimer);
    tooltipHideTimer = null;
  }
};

const onTooltipLeave = () => {
  tooltipState.value.show = false;
};

defineExpose({ showPeerTooltip, hidePeerTooltip });
</script>

<template>
  <teleport to="body">
    <div
      v-if="tooltipState.show"
      :style="{ top: tooltipState.y + 'px', left: tooltipState.x + 'px' }"
      class="fixed z-[9999] mt-1 -translate-x-1/2 transform"
      @mouseenter="onTooltipEnter"
      @mouseleave="onTooltipLeave"
    >
      <div
        class="w-auto min-w-[260px] max-w-[320px] rounded-lg border border-slate-200 bg-white p-4 text-left text-sm text-slate-600 shadow-2xl dark:border-slate-600 dark:bg-slate-800 dark:text-slate-200"
      >
        <div
          class="absolute -top-2 left-1/2 h-4 w-4 -translate-x-1/2 rotate-45 transform border-l border-t border-slate-200 bg-white dark:border-slate-600 dark:bg-slate-800"
        ></div>
        <div class="relative z-10 mb-2 flex items-center justify-between border-b border-slate-200 pb-2 dark:border-slate-600">
          <span class="text-xs font-bold uppercase text-slate-400">NAT Type</span>
          <span class="badge-green border border-green-200 dark:border-green-800">{{
            tooltipState.info.nat_type
          }}</span>
        </div>
        <div
          v-if="tooltipState.info.public_ips && tooltipState.info.public_ips.length > 0"
          class="relative z-10 mb-3"
        >
          <span class="mb-1 block text-xs text-slate-400">Public IPv4:</span>
          <div class="flex flex-wrap gap-1">
            <span
              v-for="pip in tooltipState.info.public_ips"
              :key="pip"
              class="rounded border border-slate-200 bg-slate-100 px-1.5 py-0.5 font-mono text-xs tabular-nums text-slate-600 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200"
              >{{ pip }}</span
            >
          </div>
        </div>
        <div v-if="tooltipState.info.ipv6" class="relative z-10">
          <span class="mb-1 block text-xs text-slate-400">IPv6:</span>
          <div
            class="whitespace-normal break-all rounded border border-slate-200 bg-slate-50 p-1.5 font-mono text-xs leading-relaxed text-slate-600 dark:border-slate-700/50 dark:bg-slate-900/50 dark:text-slate-200"
          >
            {{ tooltipState.info.ipv6 }}
          </div>
        </div>
      </div>
    </div>
  </teleport>
</template>
