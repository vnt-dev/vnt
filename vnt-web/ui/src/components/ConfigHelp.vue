<script setup>
import { computed, nextTick, onBeforeUnmount, ref } from "vue";

const props = defineProps({
  help: { type: Object, required: true },
});

const trigger = ref(null);
const panel = ref(null);
const open = ref(false);
const pinned = ref(false);
const position = ref({ top: 0, left: 0, width: 360, side: "bottom", arrow: 20 });
const tooltipId = `config-help-${Math.random().toString(36).slice(2, 10)}`;
let closeTimer = null;

const ariaExpanded = computed(() => (open.value ? "true" : "false"));

const clearCloseTimer = () => {
  if (closeTimer) {
    clearTimeout(closeTimer);
    closeTimer = null;
  }
};

const updatePosition = () => {
  if (!trigger.value) return;
  const rect = trigger.value.getBoundingClientRect();
  const viewportWidth = document.documentElement.clientWidth;
  const viewportHeight = document.documentElement.clientHeight;
  const width = Math.min(360, viewportWidth - 24);
  const panelHeight = Math.min(panel.value?.offsetHeight || 260, viewportHeight - 24);
  const gap = 10;
  const left = Math.min(Math.max(rect.left + rect.width / 2 - width / 2, 12), viewportWidth - width - 12);
  const roomBelow = viewportHeight - rect.bottom;
  const side =
    roomBelow >= panelHeight + gap
      ? "bottom"
      : rect.top >= panelHeight + gap
        ? "top"
        : roomBelow >= rect.top
          ? "bottom"
          : "top";
  const desiredTop = side === "bottom" ? rect.bottom + gap : rect.top - panelHeight - gap;
  const top = Math.min(Math.max(12, desiredTop), viewportHeight - panelHeight - 12);
  const arrow = Math.min(Math.max(rect.left + rect.width / 2 - left, 18), width - 18);
  position.value = { top, left, width, side, arrow };
};

const addViewportListeners = () => {
  window.addEventListener("resize", updatePosition);
  window.addEventListener("scroll", updatePosition, true);
  document.addEventListener("pointerdown", onDocumentPointerDown);
  document.addEventListener("keydown", onDocumentKeydown);
};

const removeViewportListeners = () => {
  window.removeEventListener("resize", updatePosition);
  window.removeEventListener("scroll", updatePosition, true);
  document.removeEventListener("pointerdown", onDocumentPointerDown);
  document.removeEventListener("keydown", onDocumentKeydown);
};

const show = async () => {
  clearCloseTimer();
  if (!open.value) {
    open.value = true;
    addViewportListeners();
  }
  await nextTick();
  updatePosition();
  requestAnimationFrame(updatePosition);
};

const close = () => {
  clearCloseTimer();
  open.value = false;
  pinned.value = false;
  removeViewportListeners();
};

const scheduleClose = () => {
  clearCloseTimer();
  if (pinned.value) return;
  closeTimer = setTimeout(close, 120);
};

const togglePinned = async () => {
  if (open.value && pinned.value) {
    close();
    return;
  }
  pinned.value = true;
  await show();
};

function onDocumentPointerDown(event) {
  if (!pinned.value) return;
  if (trigger.value?.contains(event.target) || panel.value?.contains(event.target)) return;
  close();
}

function onDocumentKeydown(event) {
  if (event.key === "Escape") {
    // 先关闭说明层，避免同一次按键继续冒泡并关闭外层配置弹窗。
    event.stopPropagation();
    close();
  }
}

onBeforeUnmount(() => {
  clearCloseTimer();
  removeViewportListeners();
});
</script>

<template>
  <span class="inline-flex align-middle" @mouseenter="show" @mouseleave="scheduleClose">
    <button
      ref="trigger"
      type="button"
      class="group ml-1 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-slate-400 transition hover:bg-indigo-50 hover:text-indigo-600 focus-visible:bg-indigo-50 focus-visible:text-indigo-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500/40 dark:text-slate-500 dark:hover:bg-indigo-500/15 dark:hover:text-indigo-300"
      :aria-label="`查看 ${help.param} 参数说明`"
      :aria-controls="tooltipId"
      :aria-expanded="ariaExpanded"
      aria-haspopup="dialog"
      @click.stop.prevent="togglePinned"
      @focus="show"
      @blur="scheduleClose"
      @keydown.esc.stop.prevent="close"
    >
      <svg class="h-4 w-4" viewBox="0 0 20 20" fill="none" aria-hidden="true">
        <circle cx="10" cy="10" r="7.25" stroke="currentColor" stroke-width="1.5" />
        <path d="M10 9.25v4.25" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        <circle cx="10" cy="6.5" r=".85" fill="currentColor" />
      </svg>
    </button>
  </span>

  <teleport to="body">
    <transition
      enter-active-class="transition duration-150 ease-out"
      enter-from-class="translate-y-1 opacity-0"
      enter-to-class="translate-y-0 opacity-100"
      leave-active-class="transition duration-100 ease-in"
      leave-from-class="opacity-100"
      leave-to-class="opacity-0"
    >
      <section
        v-if="open"
        :id="tooltipId"
        ref="panel"
        role="dialog"
        :aria-label="`${help.param} 参数说明`"
        class="custom-scrollbar fixed z-[10000] max-h-[calc(100vh-1.5rem)] overflow-y-auto rounded-xl border border-slate-200/90 bg-white/95 p-4 text-left shadow-2xl shadow-slate-900/15 backdrop-blur-md dark:border-slate-700 dark:bg-slate-900/95 dark:shadow-black/35"
        :style="{ top: `${position.top}px`, left: `${position.left}px`, width: `${position.width}px` }"
        @mouseenter="clearCloseTimer"
        @mouseleave="scheduleClose"
        @pointerdown.stop
      >
        <span
          class="absolute h-3 w-3 rotate-45 border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900"
          :class="position.side === 'bottom' ? '-top-1.5 border-l border-t' : '-bottom-1.5 border-b border-r'"
          :style="{ left: `${position.arrow - 6}px` }"
          aria-hidden="true"
        ></span>
        <div class="relative">
          <div class="mb-3 flex items-start justify-between gap-3">
            <div>
              <span class="mb-1.5 inline-flex rounded-md bg-indigo-50 px-2 py-0.5 font-mono text-[11px] font-semibold text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300">
                {{ help.param }}
              </span>
              <p class="text-sm font-semibold leading-5 text-slate-900 dark:text-white">{{ help.summary }}</p>
            </div>
            <span v-if="pinned" class="mt-0.5 shrink-0 text-[10px] text-slate-400">已固定</span>
          </div>

          <dl class="space-y-2.5 text-xs leading-5">
            <div>
              <dt class="font-semibold text-slate-500 dark:text-slate-400">用法与用途</dt>
              <dd class="mt-0.5 text-slate-600 dark:text-slate-300">{{ help.usage }}</dd>
            </div>
            <div v-if="help.format">
              <dt class="font-semibold text-slate-500 dark:text-slate-400">填写格式</dt>
              <dd class="mt-0.5 text-slate-600 dark:text-slate-300">{{ help.format }}</dd>
            </div>
            <div v-if="help.example">
              <dt class="font-semibold text-slate-500 dark:text-slate-400">示例</dt>
              <dd class="mt-1 break-all rounded-md bg-slate-100 px-2 py-1 font-mono text-[11px] text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                {{ help.example }}
              </dd>
            </div>
          </dl>

          <ul v-if="help.notes?.length" class="mt-3 space-y-1 border-t border-slate-100 pt-2.5 text-[11px] leading-4 text-amber-700 dark:border-slate-800 dark:text-amber-300">
            <li v-for="note in help.notes" :key="note" class="flex gap-1.5">
              <span class="mt-1 h-1 w-1 shrink-0 rounded-full bg-current opacity-70"></span>
              <span>{{ note }}</span>
            </li>
          </ul>
        </div>
      </section>
    </transition>
  </teleport>
</template>
