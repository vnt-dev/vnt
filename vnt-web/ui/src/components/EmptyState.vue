<script setup>
defineProps({
  text: { type: String, default: "暂无数据" },
});
</script>

<template>
  <div class="card p-12 text-center text-slate-500 dark:text-slate-400">
    <svg
      class="w-12 h-12 mx-auto mb-3 text-slate-300 dark:text-slate-600"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        stroke-width="1.5"
        d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"
      />
    </svg>
    <p>{{ text }}</p>
  </div>
</template>
