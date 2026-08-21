<script setup>
import { ref, provide } from "vue";
import { useAppStore } from "./stores/app";
import { useStartLogStore } from "./stores/startLog";
import AppModal from "./components/AppModal.vue";
import ToastHost from "./components/ToastHost.vue";
import ConfirmHost from "./components/ConfirmHost.vue";
import StatusDot from "./components/StatusDot.vue";
import AppTooltip from "./components/AppTooltip.vue";

const app = useAppStore();
const startLog = useStartLogStore();

const tooltipRef = ref(null);
provide("peerTooltip", tooltipRef);

// 主题切换:localStorage 持久化,默认跟随系统
const isDark = ref(document.documentElement.classList.contains("dark"));
const toggleTheme = () => {
  isDark.value = !isDark.value;
  document.documentElement.classList.toggle("dark", isDark.value);
  localStorage.setItem("vnt-theme", isDark.value ? "dark" : "light");
};

const mobileNavOpen = ref(false);
const closeMobileNav = () => {
  mobileNavOpen.value = false;
};

const navItems = [
  {
    to: "/",
    label: "总览",
    exact: true,
    icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6",
  },
  {
    to: "/instances",
    label: "实例",
    icon: "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01",
  },
  {
    to: "/config",
    label: "配置",
    icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z",
    icon2: "M15 12a3 3 0 11-6 0 3 3 0 016 0z",
  },
  {
    to: "/peers",
    label: "设备列表",
    icon: "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z",
  },
  {
    to: "/routes",
    label: "路由",
    icon: "M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 01-.806-.98l-3.747-1.874M12 7v13m3-13v13m-3 0l3 3",
  },
];
</script>

<template>
  <div class="flex min-h-screen flex-col">
    <!-- 顶部导航栏 -->
    <header
      class="sticky top-0 z-30 border-b border-slate-200 bg-white/80 backdrop-blur dark:border-slate-800 dark:bg-slate-900/80"
    >
      <div class="mx-auto flex h-14 max-w-6xl items-center gap-3 px-4 lg:px-8">
        <!-- 移动端汉堡 -->
        <button
          class="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900 lg:hidden dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white"
          @click="mobileNavOpen = !mobileNavOpen"
        >
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>

        <!-- Logo -->
        <router-link to="/" class="flex items-center gap-2" @click="closeMobileNav">
          <span class="text-lg font-bold tracking-wide text-indigo-600 dark:text-indigo-400">VNT</span>
          <span class="text-sm font-medium text-slate-400 dark:text-slate-500">Web</span>
        </router-link>

        <!-- 桌面导航 -->
        <nav class="ml-6 hidden h-14 items-stretch gap-1 lg:flex">
          <router-link
            v-for="item in navItems"
            :key="item.to"
            :to="item.to"
            custom
            v-slot="{ navigate, isActive, isExactActive }"
          >
            <button
              @click="navigate"
              class="relative flex items-center px-3 text-sm font-medium transition-colors"
              :class="
                (item.exact ? isExactActive : isActive)
                  ? 'text-indigo-600 dark:text-indigo-400'
                  : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
              "
            >
              {{ item.label }}
              <span
                v-if="item.exact ? isExactActive : isActive"
                class="absolute inset-x-3 bottom-0 h-0.5 rounded-full bg-indigo-600 dark:bg-indigo-400"
              ></span>
            </button>
          </router-link>
        </nav>

        <div class="ml-auto flex items-center gap-3">
          <!-- 全局状态点 -->
          <div
            class="flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 dark:border-slate-700 dark:bg-slate-800"
            :title="app.headerStatusText"
          >
            <StatusDot
              :status="app.runningCount > 0 ? 'running' : app.startingCount > 0 ? 'starting' : 'stopped'"
            />
            <span class="hidden text-xs font-medium text-slate-600 sm:inline dark:text-slate-300">{{
              app.headerStatusText
            }}</span>
          </div>
          <span class="hidden text-xs text-slate-400 md:inline dark:text-slate-500"
            >v{{ app.version || "-" }}</span
          >
          <!-- 主题切换 -->
          <button
            class="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 shadow-sm transition-colors hover:bg-slate-50 hover:text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-white"
            :title="isDark ? '切换到浅色模式' : '切换到深色模式'"
            @click="toggleTheme"
          >
            <svg v-if="isDark" class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
              />
            </svg>
            <svg v-else class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
              />
            </svg>
          </button>
        </div>
      </div>

      <!-- 移动端下拉导航 -->
      <transition name="navdrop">
        <nav
          v-if="mobileNavOpen"
          class="border-t border-slate-200 bg-white px-4 py-2 lg:hidden dark:border-slate-800 dark:bg-slate-900"
        >
          <router-link
            v-for="item in navItems"
            :key="item.to"
            :to="item.to"
            custom
            v-slot="{ navigate, isActive, isExactActive }"
          >
            <button
              @click="
                navigate();
                closeMobileNav();
              "
              class="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors"
              :class="
                (item.exact ? isExactActive : isActive)
                  ? 'bg-indigo-50 text-indigo-600 dark:bg-indigo-500/10 dark:text-indigo-400'
                  : 'text-slate-500 hover:bg-slate-50 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white'
              "
            >
              <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="item.icon" />
                <path v-if="item.icon2" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="item.icon2" />
              </svg>
              {{ item.label }}
            </button>
          </router-link>
        </nav>
      </transition>
    </header>

    <!-- 内容区 -->
    <main class="flex-1 overflow-x-hidden">
      <div class="mx-auto w-full max-w-6xl px-4 py-6 lg:px-8">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </div>
    </main>

    <!-- 启动日志弹窗 (全局) -->
    <AppModal
      :show="startLog.showStartLog"
      :mask-closable="startLog.startStatus !== 'starting'"
      :esc-closable="startLog.startStatus !== 'starting'"
      panel-class="w-full max-w-2xl"
      @close="startLog.close"
    >
      <template #header>
        <div class="flex items-center gap-3">
          <div
            v-if="startLog.startStatus === 'starting'"
            class="h-3 w-3 animate-ping rounded-full bg-blue-500"
          ></div>
          <div v-else-if="startLog.startStatus === 'running'" class="h-3 w-3 rounded-full bg-green-500"></div>
          <div v-else class="h-3 w-3 rounded-full bg-red-500"></div>
          <h3 class="text-lg font-bold text-slate-900 dark:text-white">
            {{
              startLog.startStatus === "starting"
                ? "正在启动组网..."
                : startLog.startStatus === "running"
                  ? "启动成功"
                  : "启动失败"
            }}
          </h3>
        </div>
        <div class="flex items-center gap-3">
          <span
            class="max-w-[200px] truncate text-sm font-medium text-indigo-600 dark:text-indigo-400"
            :title="startLog.logFileName"
            >{{ startLog.logConfigName }}</span
          >
          <span class="font-mono text-xs uppercase tracking-widest text-slate-400">{{
            startLog.startStatus
          }}</span>
        </div>
      </template>
      <template #body>
        <div
          :ref="(el) => (startLog.logContainer = el)"
          class="scrollbar-hide h-80 space-y-2 overflow-y-auto bg-slate-50 p-6 font-mono text-sm dark:bg-black/20"
        >
          <div v-for="(log, idx) in startLog.startLogs" :key="idx" class="flex gap-3">
            <span class="shrink-0 text-indigo-500 dark:text-indigo-400">>>></span>
            <span class="break-all text-slate-600 dark:text-slate-300">{{ log }}</span>
          </div>
          <div v-if="startLog.startStatus === 'starting'" class="mt-4 animate-pulse italic text-blue-500">
            等待后续步骤...
          </div>
          <div
            v-if="startLog.startStatus === 'stopped' && startLog.startLogs.length > 0"
            class="mt-4 rounded-lg border border-red-200 bg-red-50 p-3 text-red-600 dark:border-red-900/50 dark:bg-red-900/20 dark:text-red-400"
          >
            <strong>启动失败:</strong>
            请检查配置或网络连接。
          </div>
        </div>
      </template>
      <template #footer>
        <button v-if="startLog.startStatus === 'starting'" class="btn-ghost" @click="startLog.cancelStart">
          取消组网
        </button>
        <button
          v-if="startLog.startStatus === 'stopped' || startLog.startStatus === 'running'"
          class="btn-primary"
          @click="startLog.close"
        >
          关闭窗口
        </button>
      </template>
    </AppModal>

    <ToastHost />
    <ConfirmHost />
    <AppTooltip ref="tooltipRef" />
  </div>
</template>
