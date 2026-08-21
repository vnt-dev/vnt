<script setup>
defineProps({
  status: { type: String, default: "stopped" },
  size: { type: String, default: "w-2.5 h-2.5" },
});

const dotClass = (status) =>
  status === "running"
    ? "bg-green-500"
    : status === "starting"
      ? "bg-blue-500 animate-pulse"
      : "bg-slate-400 dark:bg-slate-500";
</script>

<template>
  <span class="rounded-full inline-block shrink-0" :class="[size, dotClass(status)]" />
</template>
