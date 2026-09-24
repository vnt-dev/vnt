import { defineStore } from "pinia";
import { ref, computed, nextTick } from "vue";
import { getInstanceLogs, getStartStatus, stopVntApi } from "../api";

// 实例日志弹窗状态
export const useStartLogStore = defineStore("startLog", () => {
  const showStartLog = ref(false);
  // 日志条目: {level: "info"|"warn"|"error", message, time}
  const startLogs = ref([]);
  const startStatus = ref("stopped");
  // start: 启动观察(组网成功后自动关闭)；view: 手动查看(不自动关闭)
  const watchMode = ref("start");
  const logFileName = ref(null);
  const logContainer = ref(null);
  let statusInterval = null;
  // 用于废弃关闭弹窗或开始新一轮启动前已发出的轮询请求。
  let pollSession = 0;
  // 兼容旧内核：启动请求返回后，后台任务可能尚未切换到 Starting。
  let ignoreStoppedUntil = 0;

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

  const pollStartStatus = async (session = pollSession) => {
    const fileName = logFileName.value;
    if (!fileName || session !== pollSession) return;
    try {
      const [statusData, logsData] = await Promise.all([
        getStartStatus(fileName),
        getInstanceLogs(fileName),
      ]);
      // 用户可能已关闭弹窗、取消启动或切换到另一个实例。
      if (session !== pollSession || fileName !== logFileName.value) return;
      // 不让启动请求前的旧 Stopped/旧日志结束本次轮询。
      if (
        watchMode.value === "start" &&
        statusData.status === "stopped" &&
        Date.now() < ignoreStoppedUntil
      ) {
        return;
      }
      if (statusData.status !== "stopped") ignoreStoppedUntil = 0;
      startLogs.value = logsData || [];
      startStatus.value = statusData.status;
      nextTick(() => {
        if (logContainer.value)
          logContainer.value.scrollTop = logContainer.value.scrollHeight;
      });

      // 启动观察模式下组网成功即关闭弹窗；手动查看模式保持打开
      if (watchMode.value === "start" && startStatus.value === "running") {
        stopPolling(true);
        fetchInstancesFn && fetchInstancesFn();
        showStartLog.value = false;
      } else if (startStatus.value === "stopped" && startLogs.value.length > 0) {
        // 已停止且日志已产出：停止后不会有新日志，结束轮询
        stopPolling(true);
        fetchInstancesFn && fetchInstancesFn();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const stopPolling = (invalidate = false) => {
    if (statusInterval) {
      clearInterval(statusInterval);
      statusInterval = null;
    }
    if (invalidate) pollSession += 1;
  };

  const startPolling = (session = pollSession) => {
    if (session !== pollSession) return;
    stopPolling();
    if (watchMode.value === "start") ignoreStoppedUntil = Date.now() + 3000;
    statusInterval = setInterval(() => pollStartStatus(session), 1000);
    pollStartStatus(session);
  };

  const openStartLog = (fileName, pollImmediately = true) => {
    stopPolling(true);
    const session = pollSession;
    ignoreStoppedUntil = 0;
    logFileName.value = fileName;
    startLogs.value = pollImmediately
      ? []
      : [
          {
            level: "info",
            message: "正在提交启动请求…",
            time: new Date().toTimeString().slice(0, 8),
          },
        ];
    startStatus.value = "starting";
    watchMode.value = "start";
    showStartLog.value = true;
    // 点击启动时要等 POST /api/start 完成状态占位后再轮询，
    // 否则首次 GET 会跑在 POST 前面，读到上一轮的状态和日志。
    if (pollImmediately) startPolling(session);
    return session;
  };

  // 查看实例最近日志(运行中/已停止均可,不随组网成功自动关闭)
  const openInstanceLog = (fileName) => {
    stopPolling(true);
    const session = pollSession;
    ignoreStoppedUntil = 0;
    logFileName.value = fileName;
    startLogs.value = [];
    startStatus.value = "starting";
    watchMode.value = "view";
    showStartLog.value = true;
    startPolling(session);
  };

  const markStartFailed = (session, message) => {
    if (session !== pollSession) return;
    stopPolling(true);
    startStatus.value = "stopped";
    startLogs.value = [
      {
        level: "error",
        message,
        time: new Date().toTimeString().slice(0, 8),
      },
    ];
  };

  // 取消组网:停止轮询并 POST /api/stop
  const cancelStart = async () => {
    stopPolling(true);
    const fileName = logFileName.value;
    if (fileName) {
      try {
        await stopVntApi(fileName);
        startLogs.value.push({
          level: "info",
          message: "启动已手动取消",
          time: new Date().toTimeString().slice(0, 8),
        });
      } catch (e) {
        // 忽略取消时的网络错误
      }
    }
    startStatus.value = "stopped";
    fetchInstancesFn && fetchInstancesFn();
  };

  const close = () => {
    stopPolling(true);
    showStartLog.value = false;
  };

  return {
    showStartLog,
    startLogs,
    startStatus,
    watchMode,
    logFileName,
    logContainer,
    logConfigName,
    bindApp,
    openStartLog,
    openInstanceLog,
    markStartFailed,
    pollStartStatus,
    startPolling,
    stopPolling,
    cancelStart,
    close,
  };
});
