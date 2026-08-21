import { defineStore } from "pinia";
import { ref, computed, nextTick } from "vue";
import { getStartStatus, stopVntApi } from "../api";

// 启动日志弹窗状态
export const useStartLogStore = defineStore("startLog", () => {
  const showStartLog = ref(false);
  const startLogs = ref([]);
  const startStatus = ref("stopped");
  const logFileName = ref(null);
  const logContainer = ref(null);
  let statusInterval = null;

  // 由 app store 注入,避免循环依赖
  let fetchInstancesFn = null;
  let instanceListRef = null;
  let configListRef = null;
  const bindApp = ({ fetchInstances, instanceList, configList }) => {
    fetchInstancesFn = fetchInstances;
    instanceListRef = instanceList;
    configListRef = configList;
  };

  const logConfigName = computed(() => {
    if (!logFileName.value) return "";
    const inst = (instanceListRef?.value || []).find(
      (i) => i.file_name === logFileName.value,
    );
    if (inst) return inst.config_name || inst.file_name;
    const cfg = (configListRef?.value || []).find(
      (c) => c.file_name === logFileName.value,
    );
    return cfg ? cfg.config_name || cfg.file_name : logFileName.value;
  });

  const pollStartStatus = async () => {
    if (!logFileName.value) return;
    try {
      const data = await getStartStatus(logFileName.value);
      startLogs.value = data.logs || [];
      startStatus.value = data.status;
      nextTick(() => {
        if (logContainer.value)
          logContainer.value.scrollTop = logContainer.value.scrollHeight;
      });

      if (startStatus.value === "running") {
        stopPolling();
        fetchInstancesFn && fetchInstancesFn();
        showStartLog.value = false;
      } else if (startStatus.value === "stopped" && startLogs.value.length > 0) {
        stopPolling();
        fetchInstancesFn && fetchInstancesFn();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const stopPolling = () => {
    if (statusInterval) {
      clearInterval(statusInterval);
      statusInterval = null;
    }
  };

  const startPolling = () => {
    stopPolling();
    statusInterval = setInterval(pollStartStatus, 1000);
    pollStartStatus();
  };

  const openStartLog = (fileName) => {
    logFileName.value = fileName;
    startLogs.value = [];
    startStatus.value = "starting";
    showStartLog.value = true;
    startPolling();
  };

  // 取消组网:停止轮询并 POST /api/stop
  const cancelStart = async () => {
    stopPolling();
    const fileName = logFileName.value;
    if (fileName) {
      try {
        await stopVntApi(fileName);
        startLogs.value.push("启动已手动取消");
      } catch (e) {
        // 忽略取消时的网络错误
      }
    }
    startStatus.value = "stopped";
    fetchInstancesFn && fetchInstancesFn();
  };

  const close = () => {
    showStartLog.value = false;
  };

  return {
    showStartLog,
    startLogs,
    startStatus,
    logFileName,
    logContainer,
    logConfigName,
    bindApp,
    openStartLog,
    pollStartStatus,
    startPolling,
    stopPolling,
    cancelStart,
    close,
  };
});
