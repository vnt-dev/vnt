<script setup>
import { watch, onUnmounted } from "vue";

const props = defineProps({
  show: { type: Boolean, default: false },
  // 点击遮罩是否关闭
  maskClosable: { type: Boolean, default: true },
  // ESC 是否关闭
  escClosable: { type: Boolean, default: true },
  panelClass: { type: String, default: "w-full max-w-2xl" },
});

const emit = defineEmits(["close"]);

const onKeydown = (e) => {
  if (props.escClosable && e.key === "Escape") emit("close");
};

watch(
  () => props.show,
  (val) => {
    if (val) window.addEventListener("keydown", onKeydown);
    else window.removeEventListener("keydown", onKeydown);
  },
);

onUnmounted(() => window.removeEventListener("keydown", onKeydown));

const onMaskClick = () => {
  if (props.maskClosable) emit("close");
};
</script>

<template>
  <teleport to="body">
    <transition name="modal">
      <div
        v-if="show"
        class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4 backdrop-blur-sm"
        @click.self="onMaskClick"
      >
        <div
          class="modal-panel flex max-h-[90vh] flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900"
          :class="panelClass"
        >
          <div
            v-if="$slots.header"
            class="flex shrink-0 items-center justify-between gap-3 border-b border-slate-200 bg-slate-50/60 px-6 py-4 dark:border-slate-700 dark:bg-slate-800/50"
          >
            <slot name="header" />
          </div>
          <div class="custom-scrollbar min-h-0 flex-1 overflow-y-auto">
            <slot name="body" />
          </div>
          <div
            v-if="$slots.footer"
            class="flex shrink-0 items-center justify-end gap-3 border-t border-slate-200 bg-slate-50/60 px-6 py-4 dark:border-slate-700 dark:bg-slate-800/50"
          >
            <slot name="footer" />
          </div>
        </div>
      </div>
    </transition>
  </teleport>
</template>
