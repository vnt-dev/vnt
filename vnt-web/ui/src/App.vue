<script setup>
import { computed, onBeforeUnmount, onMounted, provide, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useAppStore } from "./stores/app";
import { useStartLogStore } from "./stores/startLog";
import { visibleNavItems } from "./navigation";
import AppSidebar from "./components/AppSidebar.vue";
import AppModal from "./components/AppModal.vue";
import AppTooltip from "./components/AppTooltip.vue";
import ConfirmHost from "./components/ConfirmHost.vue";
import ToastHost from "./components/ToastHost.vue";
import AccessGate from "./components/AccessGate.vue";
import { authorized, isDesktop } from "./auth";

const app = useAppStore();
const startLog = useStartLogStore();
const route = useRoute();
const router = useRouter();

const tooltipRef = ref(null);
provide("peerTooltip", tooltipRef);

const mobileNavOpen = ref(false);
const items = visibleNavItems();
const pageMeta = computed(() => items.find((item) => item.to === route.path) || items[0]);

const savedTheme = localStorage.getItem("vnt-theme");
const isDark = ref(savedTheme
  ? savedTheme === "dark"
  : window.matchMedia("(prefers-color-scheme: dark)").matches);
const applyTheme = () => document.documentElement.classList.toggle("dark", isDark.value);
const toggleTheme = () => {
  isDark.value = !isDark.value;
  localStorage.setItem("vnt-theme", isDark.value ? "dark" : "light");
  applyTheme();
};
applyTheme();

watch(() => route.path, () => { mobileNavOpen.value = false; });

const handleKeydown = (event) => {
  if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
  const index = Number(event.key) - 1;
  if (index >= 0 && index < items.length) {
    event.preventDefault();
    router.push(items[index].to);
  }
};

onMounted(() => window.addEventListener("keydown", handleKeydown));
onBeforeUnmount(() => window.removeEventListener("keydown", handleKeydown));
</script>

<template>
  <AccessGate v-if="!isDesktop && !authorized" />
  <div v-else class="flex h-[100dvh] min-h-0 overflow-hidden bg-slate-50 text-slate-700 dark:bg-slate-950 dark:text-slate-200">
    <aside class="hidden w-60 shrink-0 border-r border-slate-200 dark:border-slate-800 lg:block">
      <AppSidebar />
    </aside>

    <transition name="drawer">
      <div v-if="mobileNavOpen" class="fixed inset-0 z-40 lg:hidden">
        <button class="absolute inset-0 bg-slate-950/45 backdrop-blur-[2px]" aria-label="关闭导航" @click="mobileNavOpen = false"></button>
        <aside class="drawer-panel relative h-full w-[min(82vw,288px)] border-r border-slate-200 shadow-2xl dark:border-slate-700">
          <AppSidebar @navigate="mobileNavOpen = false" />
        </aside>
      </div>
    </transition>

    <div class="flex min-w-0 flex-1 flex-col">
      <header class="flex h-16 shrink-0 items-center gap-3 border-b border-slate-200 bg-white/90 px-4 backdrop-blur lg:px-6 dark:border-slate-800 dark:bg-slate-900/90">
        <button
          class="grid h-9 w-9 shrink-0 place-items-center rounded-lg text-slate-500 hover:bg-slate-100 hover:text-slate-900 lg:hidden dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white"
          aria-label="打开导航"
          @click="mobileNavOpen = true"
        >
          <svg class="h-5 w-5 fill-none stroke-current" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16" stroke-linecap="round" stroke-width="2" /></svg>
        </button>

        <div class="min-w-0">
          <h1 class="truncate text-lg font-bold text-slate-900 dark:text-white">{{ pageMeta.label }}</h1>
          <p class="hidden text-xs text-slate-400 sm:block">{{ pageMeta.subtitle || "VNT 虚拟局域网管理" }}</p>
        </div>

        <div class="ml-auto flex items-center gap-2">
          <div id="page-actions" class="flex items-center gap-2"></div>
          <div class="flex h-8 items-center gap-2 rounded-lg border border-slate-200 bg-white px-2.5 text-xs font-medium text-slate-500 sm:px-3 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            <span
              class="h-1.5 w-1.5 rounded-full"
              :class="app.runningCount > 0 ? 'bg-green-500' : app.startingCount > 0 ? 'animate-pulse bg-amber-400' : 'bg-slate-300 dark:bg-slate-600'"
            ></span>
            <span class="hidden sm:inline">{{ app.headerStatusText }}</span>
          </div>
          <button
            class="grid h-8 w-8 place-items-center rounded-lg border border-slate-200 bg-white text-slate-500 hover:border-indigo-300 hover:text-indigo-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400 dark:hover:border-indigo-500 dark:hover:text-indigo-400"
            :title="isDark ? '切换浅色模式' : '切换深色模式'"
            :aria-label="isDark ? '切换浅色模式' : '切换深色模式'"
            @click="toggleTheme"
          >
            <svg v-if="isDark" class="h-4 w-4 fill-none stroke-current" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" stroke-linecap="round" stroke-width="1.7"/></svg>
            <svg v-else class="h-4 w-4 fill-none stroke-current" viewBox="0 0 24 24"><path d="M20.5 15.2A8.5 8.5 0 0 1 8.8 3.5 8.5 8.5 0 1 0 20.5 15.2Z" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.7"/></svg>
          </button>
        </div>
      </header>

      <main class="custom-scrollbar min-h-0 flex-1 overflow-x-hidden overflow-y-auto">
        <div class="mx-auto w-full max-w-[1700px] px-4 py-5 sm:px-5 lg:px-7 lg:py-6">
          <router-view v-slot="{ Component }">
            <transition name="fade" mode="out-in"><component :is="Component" /></transition>
          </router-view>
        </div>
      </main>
    </div>

    <AppModal
      :show="startLog.showStartLog"
      :mask-closable="startLog.startStatus !== 'starting'"
      :esc-closable="startLog.startStatus !== 'starting'"
      panel-class="w-full max-w-2xl"
      @close="startLog.close"
    >
      <template #header>
        <div class="flex min-w-0 items-center gap-3">
          <span
            class="h-2 w-2 shrink-0 rounded-full"
            :class="startLog.startStatus === 'starting' ? 'animate-pulse bg-amber-400' : startLog.startStatus === 'running' ? 'bg-green-500' : 'bg-red-500'"
          ></span>
          <h3 class="truncate text-base font-bold text-slate-900 sm:text-lg dark:text-white">
            {{ startLog.startStatus === "starting" ? "正在建立虚拟网络" : startLog.startStatus === "running" ? "网络已连接" : "连接未完成" }}
          </h3>
        </div>
        <span class="max-w-[40%] truncate font-mono text-xs text-indigo-600 dark:text-indigo-400">{{ startLog.logConfigName }}</span>
      </template>
      <template #body>
        <div
          :ref="(el) => (startLog.logContainer = el)"
          class="custom-scrollbar h-64 space-y-2 overflow-y-auto border-y border-slate-200 bg-slate-50 p-4 font-mono text-xs text-slate-600 sm:h-80 sm:p-6 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300"
        >
          <div v-for="(log, idx) in startLog.startLogs" :key="idx" class="flex gap-3">
            <span class="text-indigo-600 dark:text-indigo-400">›</span><span class="break-all">{{ log }}</span>
          </div>
          <div v-if="startLog.startStatus === 'starting'" class="animate-pulse text-indigo-600 dark:text-indigo-400">等待下一阶段…</div>
        </div>
      </template>
      <template #footer>
        <button v-if="startLog.startStatus === 'starting'" class="btn-ghost" @click="startLog.cancelStart">取消连接</button>
        <button v-else class="btn-primary" @click="startLog.close">完成</button>
      </template>
    </AppModal>

    <ToastHost />
    <ConfirmHost />
    <AppTooltip ref="tooltipRef" />
  </div>
</template>
