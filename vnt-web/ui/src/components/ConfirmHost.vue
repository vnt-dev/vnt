<script setup>
import { useUiStore } from "../stores/ui";
import AppModal from "./AppModal.vue";

const ui = useUiStore();
</script>

<template>
  <AppModal
    :show="ui.confirmState.show"
    panel-class="w-full max-w-sm"
    @close="ui.confirmCancel"
  >
    <template #header>
      <h3 class="text-lg font-bold text-slate-900 flex items-center gap-2 dark:text-white">
        <svg
          v-if="ui.confirmState.danger"
          class="w-5 h-5 text-red-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
        {{ ui.confirmState.title }}
      </h3>
    </template>
    <template #body>
      <p class="px-6 py-5 text-sm text-slate-600 break-all dark:text-slate-300">
        {{ ui.confirmState.message }}
      </p>
    </template>
    <template #footer>
      <button class="btn-ghost" @click="ui.confirmCancel">取消</button>
      <button
        :class="ui.confirmState.danger ? 'btn-danger' : 'btn-primary'"
        @click="ui.confirmOk"
      >
        {{ ui.confirmState.confirmText }}
      </button>
    </template>
  </AppModal>
</template>
