import { defineStore } from "pinia";
import { reactive, ref } from "vue";

let toastId = 0;

export const useUiStore = defineStore("ui", () => {
  // toast 队列
  const toasts = ref([]);

  const pushToast = (type, message, duration = 3000) => {
    const id = ++toastId;
    toasts.value.push({ id, type, message });
    setTimeout(() => {
      toasts.value = toasts.value.filter((t) => t.id !== id);
    }, duration);
  };

  const toast = {
    success: (msg) => pushToast("success", msg),
    error: (msg) => pushToast("error", msg, 4500),
    info: (msg) => pushToast("info", msg),
  };

  // confirm 弹窗:返回 Promise<boolean>
  const confirmState = reactive({
    show: false,
    title: "",
    message: "",
    danger: false,
    confirmText: "确定",
    resolve: null,
  });

  const confirm = ({ title = "确认操作", message = "", danger = false, confirmText = "确定" } = {}) =>
    new Promise((resolve) => {
      confirmState.show = true;
      confirmState.title = title;
      confirmState.message = message;
      confirmState.danger = danger;
      confirmState.confirmText = confirmText;
      confirmState.resolve = resolve;
    });

  const confirmOk = () => {
    confirmState.show = false;
    confirmState.resolve && confirmState.resolve(true);
    confirmState.resolve = null;
  };

  const confirmCancel = () => {
    confirmState.show = false;
    confirmState.resolve && confirmState.resolve(false);
    confirmState.resolve = null;
  };

  return {
    toasts,
    toast,
    confirmState,
    confirm,
    confirmOk,
    confirmCancel,
  };
});
