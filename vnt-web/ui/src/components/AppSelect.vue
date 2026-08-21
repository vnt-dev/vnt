<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from "vue";

defineOptions({ inheritAttrs: false });

const props = defineProps({
  modelValue: { default: null },
  options: { type: Array, default: () => [] },
  placeholder: { type: String, default: "请选择" },
  disabled: { type: Boolean, default: false },
});

const emit = defineEmits(["update:modelValue"]);
const root = ref(null);
const trigger = ref(null);
const open = ref(false);
const activeIndex = ref(-1);
const listboxId = `app-select-${useId().replaceAll(":", "")}`;

const selectedIndex = computed(() =>
  props.options.findIndex((option) => Object.is(option.value, props.modelValue)),
);
const selectedOption = computed(() => props.options[selectedIndex.value] || null);

const firstEnabledIndex = (from, direction) => {
  if (!props.options.length) return -1;
  let index = from;
  for (let count = 0; count < props.options.length; count += 1) {
    index = (index + direction + props.options.length) % props.options.length;
    if (!props.options[index]?.disabled) return index;
  }
  return -1;
};

const openMenu = async () => {
  if (props.disabled) return;
  open.value = true;
  activeIndex.value = selectedIndex.value >= 0
    ? selectedIndex.value
    : firstEnabledIndex(-1, 1);
  await nextTick();
  root.value?.querySelector(`[data-option-index="${activeIndex.value}"]`)?.scrollIntoView({ block: "nearest" });
};

const closeMenu = (restoreFocus = false) => {
  open.value = false;
  if (restoreFocus) trigger.value?.focus();
};

const choose = (option) => {
  if (option.disabled) return;
  emit("update:modelValue", option.value);
  closeMenu(true);
};

const moveActive = (direction) => {
  activeIndex.value = firstEnabledIndex(activeIndex.value, direction);
  nextTick(() => {
    root.value?.querySelector(`[data-option-index="${activeIndex.value}"]`)?.scrollIntoView({ block: "nearest" });
  });
};

const onKeydown = (event) => {
  if (props.disabled) return;
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    if (!open.value) openMenu();
    else moveActive(event.key === "ArrowDown" ? 1 : -1);
    return;
  }
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    if (!open.value) openMenu();
    else if (activeIndex.value >= 0) choose(props.options[activeIndex.value]);
    return;
  }
  if (event.key === "Escape" && open.value) {
    event.preventDefault();
    closeMenu(true);
    return;
  }
  if (event.key === "Home" && open.value) {
    event.preventDefault();
    activeIndex.value = firstEnabledIndex(-1, 1);
  } else if (event.key === "End" && open.value) {
    event.preventDefault();
    activeIndex.value = firstEnabledIndex(0, -1);
  } else if (event.key === "Tab") {
    closeMenu();
  }
};

const onDocumentPointerDown = (event) => {
  if (open.value && !root.value?.contains(event.target)) closeMenu();
};

watch(() => props.disabled, (disabled) => {
  if (disabled) closeMenu();
});
onMounted(() => document.addEventListener("pointerdown", onDocumentPointerDown));
onBeforeUnmount(() => document.removeEventListener("pointerdown", onDocumentPointerDown));
</script>

<template>
  <div ref="root" class="relative w-full">
    <button
      ref="trigger"
      v-bind="$attrs"
      type="button"
      role="combobox"
      :aria-expanded="open"
      :aria-controls="listboxId"
      aria-haspopup="listbox"
      :disabled="disabled"
      class="input flex min-h-10 items-center justify-between gap-3 text-left"
      :class="open ? 'border-indigo-500 ring-2 ring-indigo-500/25' : ''"
      @click="open ? closeMenu() : openMenu()"
      @keydown="onKeydown"
    >
      <span class="min-w-0 flex-1 truncate" :class="selectedOption ? '' : 'text-slate-400 dark:text-slate-500'">
        {{ selectedOption?.label || placeholder }}
      </span>
      <svg
        class="h-4 w-4 shrink-0 fill-none stroke-current text-slate-400 transition-transform duration-150"
        :class="open ? 'rotate-180 text-indigo-500' : ''"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path d="m7 10 5 5 5-5" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" />
      </svg>
    </button>

    <transition name="select-menu">
      <div
        v-if="open"
        :id="listboxId"
        role="listbox"
        class="custom-scrollbar absolute z-40 mt-1.5 max-h-60 w-full overflow-y-auto rounded-xl border border-slate-200 bg-white p-1.5 shadow-xl shadow-slate-900/10 dark:border-slate-700 dark:bg-slate-800 dark:shadow-black/30"
      >
        <button
          v-for="(option, index) in options"
          :key="`${String(option.value)}-${index}`"
          type="button"
          role="option"
          :aria-selected="Object.is(option.value, modelValue)"
          :disabled="option.disabled"
          :data-option-index="index"
          class="flex w-full items-center gap-2 rounded-lg px-3 py-2.5 text-left text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-40"
          :class="[
            Object.is(option.value, modelValue)
              ? 'bg-indigo-50 font-medium text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300'
              : 'text-slate-600 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700/70',
            activeIndex === index && !Object.is(option.value, modelValue)
              ? 'bg-slate-100 dark:bg-slate-700/70'
              : '',
          ]"
          @mouseenter="activeIndex = index"
          @click="choose(option)"
        >
          <span class="min-w-0 flex-1 truncate">{{ option.label }}</span>
          <svg v-if="Object.is(option.value, modelValue)" class="h-4 w-4 shrink-0 fill-none stroke-current" viewBox="0 0 24 24" aria-hidden="true">
            <path d="m5 12 4 4L19 6" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" />
          </svg>
        </button>
        <div v-if="options.length === 0" class="px-3 py-4 text-center text-xs text-slate-400">暂无可选项</div>
      </div>
    </transition>
  </div>
</template>

<style scoped>
.select-menu-enter-active,
.select-menu-leave-active {
  transform-origin: top;
  transition: opacity 120ms ease, transform 120ms ease;
}

.select-menu-enter-from,
.select-menu-leave-to {
  opacity: 0;
  transform: translateY(-4px) scale(0.98);
}
</style>
