import { defineStore } from "pinia";
import { ref, computed, onMounted, onUnmounted, getCurrentInstance } from "vue";
import {
  getInstances,
  getInstanceInfo,
  getConfigList,
  getVersion,
  startVntApi,
  stopVntApi,
  restartVntApi,
  deleteInstance,
} from "../api";
import { useUiStore } from "./ui";
import { useStartLogStore } from "./startLog";
import { getAccessToken, isDesktop } from "../auth";

export const useAppStore = defineStore("app", () => {
  const ui = useUiStore();
  const startLog = useStartLogStore();

  // 多实例状态:key=file_name, value=该实例 info
  const instances = ref({});
  const instanceList = ref([]);
  const selectedInstance = ref(null);
  const configList = ref([]);
  const loadingMap = ref({});
  // 停止中的实例:key=file_name;点击停止后置位,实例从列表消失或变为 stopped 时清除
  const stoppingMap = ref({});

  // 页面可见性
  const isPageVisible = ref(!document.hidden);
  const visibilityHandler = () => {
    isPageVisible.value = !document.hidden;
  };

  let infoTimer = null;

  const runningCount = computed(
    () => instanceList.value.filter((i) => i.status === "running").length,
  );
  const startingCount = computed(
    () => instanceList.value.filter((i) => i.status === "starting").length,
  );
  const headerStatusText = computed(() => {
    if (runningCount.value > 0) return `运行中 x${runningCount.value}`;
    if (startingCount.value > 0) return "启动中...";
    return "未启动";
  });
  const selectedInfo = computed(() =>
    selectedInstance.value ? instances.value[selectedInstance.value] || null : null,
  );
  const selectedConfigName = computed(() => {
    if (!selectedInstance.value) return "";
    const inst = instanceList.value.find(
      (i) => i.file_name === selectedInstance.value,
    );
    return inst ? inst.config_name || inst.file_name : selectedInstance.value;
  });
  // 客户端版本号,来自 /api/version,与组网状态无关
  const version = ref("");

  const fetchVersion = async () => {
    try {
      version.value = (await getVersion()) || "";
    } catch (e) {
      console.error("Fetch version error", e);
    }
  };
  const isServerConnected = computed(
    () =>
      !!(
        selectedInfo.value &&
        selectedInfo.value.server_info &&
        selectedInfo.value.server_info.some((s) => s.connected)
      ),
  );
  const serverStatusText = computed(() => {
    const si = selectedInfo.value;
    if (!si || !si.server_info || !si.server_info.length) return "未配置服务器";
    return `${si.server_info.filter((s) => s.connected).length} / ${si.server_info.length} 已连接`;
  });

  const infoOf = (fileName) => instances.value[fileName] || {};

  const fetchInstanceInfo = async (fileName) => {
    try {
      instances.value[fileName] = await getInstanceInfo(fileName);
    } catch (e) {
      console.error("Fetch info error", e);
    }
  };

  const fetchInstances = async () => {
    try {
      const list = (await getInstances()) || [];
      instanceList.value = list;
      // 清理已消失实例的 info 缓存
      for (const key of Object.keys(instances.value)) {
        if (!list.some((i) => i.file_name === key)) {
          delete instances.value[key];
        }
      }
      // 停止已生效(实例消失或进入 stopped)时清除停止中标记
      for (const key of Object.keys(stoppingMap.value)) {
        const inst = list.find((i) => i.file_name === key);
        if (!inst || inst.status === "stopped") {
          delete stoppingMap.value[key];
        }
      }
      // 默认选中逻辑:当前选中失效时优先第一个 running,否则第一个,否则 null
      if (
        !selectedInstance.value ||
        !list.some((i) => i.file_name === selectedInstance.value)
      ) {
        const running = list.find((i) => i.status === "running");
        selectedInstance.value = running
          ? running.file_name
          : list.length > 0
            ? list[0].file_name
            : null;
      }
      // 拉取 running 实例的详情
      for (const inst of list) {
        if (inst.status === "running") {
          fetchInstanceInfo(inst.file_name);
        }
      }
    } catch (e) {
      console.error("Fetch instances error", e);
    }
  };

  const fetchConfigList = async () => {
    try {
      configList.value = (await getConfigList()) || [];
    } catch (e) {
      console.error("Fetch list error", e);
    }
  };

  const startVnt = async (fileName) => {
    if (!fileName) {
      ui.toast.error("请先选择一个配置");
      return;
    }
    if (loadingMap.value[fileName]) return;
    loadingMap.value[fileName] = true;
    try {
      await startVntApi(fileName);
      startLog.openStartLog(fileName);
      fetchInstances();
    } catch (e) {
      ui.toast.error("启动失败: " + e.message);
    } finally {
      loadingMap.value[fileName] = false;
    }
  };

  const stopVnt = async (fileName) => {
    if (!fileName || loadingMap.value[fileName]) return;
    loadingMap.value[fileName] = true;
    stoppingMap.value[fileName] = true;
    try {
      await stopVntApi(fileName);
      ui.toast.success("已停止");
      if (startLog.logFileName === fileName) {
        startLog.stopPolling();
        startLog.showStartLog = false;
      }
      fetchInstances();
    } catch (e) {
      ui.toast.error("停止失败: " + e.message);
      console.error(e);
      // 停止失败,恢复可操作状态
      delete stoppingMap.value[fileName];
    } finally {
      loadingMap.value[fileName] = false;
    }
  };

  const restartVnt = async (fileName) => {
    if (!fileName || loadingMap.value[fileName]) return;
    loadingMap.value[fileName] = true;
    try {
      await restartVntApi(fileName);
      startLog.openStartLog(fileName);
      fetchInstances();
    } catch (e) {
      ui.toast.error("重启失败: " + e.message);
    } finally {
      loadingMap.value[fileName] = false;
    }
  };

  // 移除已停止(启动失败残留)的实例条目
  const dismissInstance = async (fileName) => {
    if (!fileName || loadingMap.value[fileName]) return;
    loadingMap.value[fileName] = true;
    try {
      await deleteInstance(fileName);
      ui.toast.success("已移除");
      if (startLog.logFileName === fileName) {
        startLog.stopPolling();
        startLog.showStartLog = false;
      }
      if (selectedInstance.value === fileName) {
        selectedInstance.value = null;
      }
      fetchInstances();
    } catch (e) {
      ui.toast.error("移除失败: " + e.message);
    } finally {
      loadingMap.value[fileName] = false;
    }
  };

  // 注入依赖,供启动日志 store 刷新实例与解析配置名
  startLog.bindApp({ fetchInstances, instanceList, configList });

  const init = async () => {
    if (!isDesktop && !getAccessToken()) return;
    document.addEventListener("visibilitychange", visibilityHandler);
    fetchVersion();
    await fetchInstances();
    fetchConfigList();
    // 页面加载时若有正在启动的实例,恢复其日志弹窗
    const starting = instanceList.value.find((i) => i.status === "starting");
    if (starting) startLog.openStartLog(starting.file_name);
    // 全局 3s 轮询实例列表及 running 实例详情(仅页面可见)
    infoTimer = setInterval(() => {
      if (isPageVisible.value) fetchInstances();
    }, 3000);
  };

  const destroy = () => {
    document.removeEventListener("visibilitychange", visibilityHandler);
    startLog.stopPolling();
    if (infoTimer) clearInterval(infoTimer);
  };

  // store 在组件 setup 中被使用时自动挂接生命周期
  if (getCurrentInstance()) {
    onMounted(init);
    onUnmounted(destroy);
  }

  return {
    instances,
    instanceList,
    selectedInstance,
    configList,
    loadingMap,
    stoppingMap,
    isPageVisible,
    runningCount,
    startingCount,
    headerStatusText,
    selectedInfo,
    selectedConfigName,
    version,
    isServerConnected,
    serverStatusText,
    infoOf,
    fetchInstances,
    fetchInstanceInfo,
    fetchConfigList,
    startVnt,
    stopVnt,
    restartVnt,
    dismissInstance,
  };
});
