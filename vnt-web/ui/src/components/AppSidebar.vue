<script setup>
import { useRoute } from "vue-router";
import { useAppStore } from "../stores/app";
import { visibleNavItems } from "../navigation";
import vntIcon from "../assets/vnt-icon.png";

defineEmits(["navigate"]);
const route = useRoute();
const app = useAppStore();
const items = visibleNavItems();
</script>

<template>
  <div class="flex h-full min-h-0 flex-col bg-white dark:bg-slate-900">
    <div class="flex h-16 shrink-0 items-center gap-3 border-b border-slate-200 px-5 dark:border-slate-800">
      <img :src="vntIcon" alt="" class="h-8 w-8 shrink-0" />
      <div>
        <div class="text-sm font-bold tracking-wide text-slate-900 dark:text-white">VNT</div>
        <div class="text-[9px] font-semibold tracking-[0.18em] text-slate-400">CONTROL CENTER</div>
      </div>
    </div>

    <nav class="mt-4 flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto px-3" aria-label="主导航">
      <router-link
        v-for="item in items"
        :key="item.to"
        :to="item.to"
        class="flex min-h-10 items-center gap-3 rounded-lg px-3 text-sm font-medium transition-colors"
        :class="route.path === item.to
          ? 'bg-indigo-50 text-indigo-700 dark:bg-indigo-500/10 dark:text-indigo-300'
          : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white'"
        @click="$emit('navigate')"
      >
        <svg class="h-[18px] w-[18px] shrink-0 fill-none stroke-current" viewBox="0 0 24 24">
          <path :d="item.icon" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.7" />
        </svg>
        <span>{{ item.label }}</span>
      </router-link>
    </nav>

    <div class="mx-3 mt-3 shrink-0 border-t border-slate-200 px-1 py-4 dark:border-slate-800">
      <div class="flex items-center gap-2 text-xs text-slate-400">
        <span class="h-1.5 w-1.5 rounded-full" :class="app.version ? 'bg-green-500' : 'bg-amber-400'"></span>
        <span>{{ app.version ? "本地服务正常" : "正在连接服务…" }}</span>
        <span class="ml-auto font-mono text-[10px]">v{{ app.version || "2.0" }}</span>
      </div>
    </div>
  </div>
</template>
