<script setup>
import { ref, onMounted } from "vue";
import { useAppStore } from "../stores/app";
import { useUiStore } from "../stores/ui";
import { deleteConfig } from "../api";
import EmptyState from "../components/EmptyState.vue";
import ConfigEditor from "./ConfigEditor.vue";

const app = useAppStore();
const ui = useUiStore();

const showEditor = ref(false);
const editorFileName = ref(null);

// 配置对应的实例运行状态(无实例返回 null)
const instStatus = (fileName) => {
  const inst = app.instanceList.find((i) => i.file_name === fileName);
  return inst ? inst.status : null;
};

const cardClass = (fileName) => {
  const status = instStatus(fileName);
  if (status === "running") return "ring-2 ring-green-500/60";
  if (status === "starting") return "ring-2 ring-indigo-500/60";
  return "";
};

const openEditor = (fileName) => {
  editorFileName.value = fileName;
  showEditor.value = true;
};

const onSaved = () => {
  app.fetchConfigList();
};

const handleDelete = async (fileName) => {
  const ok = await ui.confirm({
    title: "删除配置",
    message: `确定要删除配置 ${fileName} 吗?`,
    danger: true,
    confirmText: "删除",
  });
  if (!ok) return;
  try {
    await deleteConfig(fileName);
    ui.toast.success("配置已删除");
    app.fetchConfigList();
  } catch (e) {
    ui.toast.error(e.message);
  }
};

onMounted(() => app.fetchConfigList());
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-end justify-between gap-4">
      <div>
        <h1 class="page-title">配置</h1>
        <p class="page-subtitle">管理组网配置文件</p>
      </div>
      <button class="btn-primary" @click="openEditor(null)">
        <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
        新建配置
      </button>
    </div>

    <EmptyState v-if="app.configList.length === 0" text="暂无配置，点击右上角新建" />

    <div v-else class="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
      <div
        v-for="cfg in app.configList"
        :key="cfg.file_name"
        :class="cardClass(cfg.file_name)"
        class="card group relative flex min-h-[140px] cursor-pointer flex-col justify-between overflow-hidden"
        @click="openEditor(cfg.file_name)"
      >
        <div
          v-if="instStatus(cfg.file_name) === 'running'"
          class="absolute right-0 top-0 rounded-bl bg-green-500 px-2 py-1 text-xs text-white"
        >
          运行中
        </div>
        <div
          v-else-if="instStatus(cfg.file_name) === 'starting'"
          class="absolute right-0 top-0 rounded-bl bg-indigo-500 px-2 py-1 text-xs text-white"
        >
          启动中
        </div>
        <div class="flex items-start">
          <div class="mr-3 mt-1 rounded-lg bg-indigo-50 p-2 text-indigo-600 dark:bg-indigo-500/10 dark:text-indigo-400">
            <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
          </div>
          <div class="overflow-hidden">
            <h3 class="truncate text-lg font-bold text-slate-900 dark:text-white" :title="cfg.config_name">
              {{ cfg.config_name || "Unnamed" }}
            </h3>
            <p class="truncate font-mono text-xs text-slate-400" :title="cfg.file_name">
              {{ cfg.file_name }}
            </p>
          </div>
        </div>
        <div class="config-card-actions mt-4 flex justify-end transition-opacity">
          <button
            class="mr-4 text-sm text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
            @click.stop="openEditor(cfg.file_name)"
          >
            编辑
          </button>
          <button class="text-sm text-red-500 hover:text-red-400" @click.stop="handleDelete(cfg.file_name)">
            删除
          </button>
        </div>
      </div>
    </div>

    <ConfigEditor
      :show="showEditor"
      :file-name="editorFileName"
      @close="showEditor = false"
      @saved="onSaved"
    />
  </div>
</template>

<style scoped>
/* 触屏和窄屏设备没有可靠的 hover，操作按钮必须直接可见。 */
.config-card-actions {
  opacity: 1;
}

/* 只有宽屏且确实支持精细悬停的设备才使用移入显示。 */
@media (min-width: 640px) and (hover: hover) and (pointer: fine) {
  .config-card-actions {
    opacity: 0;
  }

  .group:hover .config-card-actions,
  .group:focus-within .config-card-actions {
    opacity: 1;
  }
}
</style>
