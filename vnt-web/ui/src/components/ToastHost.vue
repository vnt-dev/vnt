<script setup>
import { useUiStore } from "../stores/ui";

const ui = useUiStore();

// 浅色卡片 + 左侧色条
const barClass = (type) =>
  type === "success" ? "bg-green-500" : type === "error" ? "bg-red-500" : "bg-indigo-500";

const iconClass = (type) =>
  type === "success"
    ? "text-green-500"
    : type === "error"
      ? "text-red-500"
      : "text-indigo-500";

const iconPath = (type) =>
  type === "success"
    ? "M5 13l4 4L19 7"
    : type === "error"
      ? "M6 18L18 6M6 6l12 12"
      : "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z";
</script>

<template>
  <teleport to="body">
    <div class="pointer-events-none fixed right-4 top-4 z-[100] flex flex-col items-end gap-2">
      <transition-group name="toast">
        <div
          v-for="t in ui.toasts"
          :key="t.id"
          class="pointer-events-auto flex max-w-sm items-stretch overflow-hidden rounded-lg border border-slate-200 bg-white shadow-lg dark:border-slate-700 dark:bg-slate-800"
        >
          <span class="w-1 shrink-0" :class="barClass(t.type)"></span>
          <div class="flex items-center gap-2 px-4 py-2.5">
            <svg class="h-4 w-4 shrink-0" :class="iconClass(t.type)" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="iconPath(t.type)" />
            </svg>
            <span class="break-all text-sm text-slate-700 dark:text-slate-200">{{ t.message }}</span>
          </div>
        </div>
      </transition-group>
    </div>
  </teleport>
</template>
