<script setup>
import { ref, watch, nextTick } from "vue";
import AppModal from "../components/AppModal.vue";
import AppSelect from "../components/AppSelect.vue";
import { useUiStore } from "../stores/ui";
import { getConfig, saveConfig } from "../api";
import { emptyFormData, parseTomlToForm, formToToml, NEW_CONFIG_TEMPLATE } from "../utils/toml";

const props = defineProps({
  show: { type: Boolean, default: false },
  // null 表示新建
  fileName: { type: String, default: null },
});

const emit = defineEmits(["close", "saved"]);

const ui = useUiStore();

const editorContent = ref("");
const editorFileName = ref("");
const editorMode = ref("new"); // 'new' 或 'edit'
const editMode = ref("form"); // 'form' 或 'toml'
const originalToml = ref(""); // 保存原始TOML内容(包含用户注释)
const hasTomlChanges = ref(false);
const hasFormChanges = ref(false);
const isParsingToml = ref(false);
const formData = ref(emptyFormData());
const certificateModeOptions = [
  { value: "skip", label: "跳过验证(默认)" },
  { value: "standard", label: "系统证书验证" },
  { value: "finger", label: "证书指纹验证" },
];
const deviceModeOptions = [
  { value: "no", label: "无虚拟网卡" },
  { value: "tun", label: "TUN(三层)" },
  { value: "tap", label: "TAP(二层)" },
];
const isWindows = /Windows/i.test(globalThis.navigator?.userAgent || "");

// 打开时加载内容
watch(
  () => props.show,
  async (val) => {
    if (!val) return;
    editorFileName.value = props.fileName || "";
    editorMode.value = props.fileName ? "edit" : "new";
    editMode.value = "form"; // 默认表单模式
    hasTomlChanges.value = false;
    hasFormChanges.value = false;

    if (props.fileName) {
      try {
        const data = await getConfig(props.fileName);
        editorContent.value = data;
        originalToml.value = data; // 保存原始TOML
        isParsingToml.value = true;
        formData.value = parseTomlToForm(data);
        nextTick(() => {
          isParsingToml.value = false;
        });
      } catch (e) {
        ui.toast.error("获取配置失败: " + e.message);
        emit("close");
      }
    } else {
      // 新建配置,初始化表单
      originalToml.value = "";
      formData.value = emptyFormData();
      editorContent.value = NEW_CONFIG_TEMPLATE;
    }
  },
);

// 切换到表单模式
const switchToFormMode = () => {
  if (editMode.value === "toml") {
    try {
      const parsed = parseTomlToForm(editorContent.value);
      editMode.value = "form";
      isParsingToml.value = true;
      formData.value = parsed;
      nextTick(() => {
        isParsingToml.value = false;
      });
    } catch (e) {
      ui.toast.error("配置解析失败: " + e.message);
    }
  } else {
    editMode.value = "form";
  }
};

// 切换到TOML模式
const switchToTomlMode = () => {
  if (editMode.value === "form") {
    // 如果表单被修改过,生成新的TOML
    if (hasFormChanges.value) {
      editorContent.value = formToToml(formData.value);
      hasFormChanges.value = false;
    } else if (originalToml.value && !hasTomlChanges.value) {
      // 表单未修改且TOML未修改,使用原始TOML(保留用户注释)
      editorContent.value = originalToml.value;
    } else {
      editorContent.value = formToToml(formData.value);
    }
  }
  editMode.value = "toml";
};

// 监听TOML内容变化(只在TOML模式下)
watch(editorContent, (newVal, oldVal) => {
  if (editMode.value === "toml" && oldVal !== undefined) {
    hasTomlChanges.value = true;
  }
});

// 监听表单数据变化
watch(
  formData,
  () => {
    if (editMode.value === "form" && props.show && !isParsingToml.value) {
      hasFormChanges.value = true;
    }
  },
  { deep: true },
);

const handleSave = async () => {
  try {
    // 表单模式先转换为TOML
    let configContent = editorContent.value;
    if (editMode.value === "form") {
      // 验证必填项
      if (!formData.value.network_code.trim()) {
        ui.toast.error("请填写网络编号");
        return;
      }
      const servers = formData.value.server.filter((s) => s.trim());
      if (servers.length === 0) {
        ui.toast.error("请至少填写一个服务器地址");
        return;
      }
      configContent = formToToml(formData.value);
    }

    await saveConfig(editorFileName.value || null, configContent);
    ui.toast.success("配置已保存");
    emit("close");
    emit("saved");
  } catch (e) {
    ui.toast.error("保存失败: " + e.message);
  }
};

// 表单分组内的小型重复控件
const checkboxClass =
  "h-5 w-5 rounded border-slate-300 bg-white text-indigo-600 focus:ring-indigo-500 dark:border-slate-600 dark:bg-slate-700";
const toggleLabelClass =
  "flex cursor-pointer items-center justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800/50 dark:hover:bg-slate-800";
const removeBtnClass =
  "shrink-0 rounded-lg bg-red-50 px-3 py-2 text-red-500 transition-colors hover:bg-red-100 dark:bg-red-900/20 dark:text-red-500 dark:hover:bg-red-900/40";
const addBtnClass =
  "flex w-full items-center justify-center gap-1 rounded-lg bg-slate-100 px-3 py-2 text-sm text-slate-600 transition-colors hover:bg-slate-200 dark:bg-slate-700/50 dark:text-slate-300 dark:hover:bg-slate-700";
const sectionTitleClass = "text-md mb-4 flex items-center font-bold text-slate-900 dark:text-white";
</script>

<template>
  <AppModal
    :show="show"
    :mask-closable="false"
    panel-class="w-full max-w-6xl h-[85vh]"
    @close="emit('close')"
  >
    <template #header>
      <h3 class="text-lg font-bold text-slate-900 dark:text-white">
        {{ editorMode === "new" ? "新建配置" : "编辑配置" }}
      </h3>
      <div class="flex items-center gap-4">
        <!-- 模式切换按钮 -->
        <div class="flex rounded-lg border border-slate-300 bg-slate-100 p-1 dark:border-slate-600 dark:bg-slate-800">
          <button
            @click="switchToFormMode"
            :class="editMode === 'form' ? 'bg-white text-slate-900 shadow-sm dark:bg-indigo-600 dark:text-white' : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'"
            class="px-4 py-1.5 rounded text-sm font-medium transition-colors flex items-center"
          >
            <svg class="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
            表单模式
          </button>
          <button
            @click="switchToTomlMode"
            :class="editMode === 'toml' ? 'bg-white text-slate-900 shadow-sm dark:bg-indigo-600 dark:text-white' : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'"
            class="px-4 py-1.5 rounded text-sm font-medium transition-colors flex items-center"
          >
            <svg class="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"
              />
            </svg>
            TOML模式
          </button>
        </div>
        <div class="text-sm text-slate-500 font-mono hidden md:block" v-if="editorFileName">
          {{ editorFileName }}
        </div>
      </div>
    </template>

    <template #body>
      <!-- 表单模式 -->
      <div v-show="editMode === 'form'" class="h-full overflow-y-auto scrollbar-hide p-6">
        <div class="max-w-4xl mx-auto space-y-6">
          <!-- 基础配置 -->
          <div class="card">
            <h4 :class="sectionTitleClass">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              基础配置
            </h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">配置名称</label>
                <input v-model="formData.config_name" type="text" placeholder="例如: 我的VPN配置" class="input" />
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                  网络编号 <span class="text-red-500">*</span>
                </label>
                <input v-model="formData.network_code" type="text" placeholder="例如: my_network" required class="input" />
              </div>
            </div>
            <div class="mt-4">
              <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                服务器地址 <span class="text-red-500">*</span>
                <span class="text-xs text-slate-500 ml-2">支持 quic:// tcp:// wss:// dynamic://</span>
              </label>
              <div class="space-y-2">
                <div v-for="(server, idx) in formData.server" :key="idx" class="flex gap-2">
                  <input v-model="formData.server[idx]" type="text" placeholder="例如: quic://1.2.3.4:29872" class="input flex-1" />
                  <button @click="formData.server.splice(idx, 1)" v-if="formData.server.length > 1" :class="removeBtnClass">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                </div>
                <button
                  @click="formData.server.push('')"
                  :class="addBtnClass"
                >
                  <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                  </svg>
                  添加服务器
                </button>
              </div>
            </div>
            <div class="mt-4">
              <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                可直连节点地址
                <span class="text-xs text-slate-500 ml-2">支持 ip:端口、tcp://、udp://</span>
              </label>
              <div class="space-y-2">
                <div v-for="(peerAddress, idx) in formData.peer_address" :key="idx" class="flex gap-2">
                  <input
                    v-model="formData.peer_address[idx]"
                    type="text"
                    placeholder="例如: 192.168.1.10:29873"
                    class="input flex-1"
                  />
                  <button @click="formData.peer_address.splice(idx, 1)" :class="removeBtnClass">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                </div>
                <button @click="formData.peer_address.push('')" :class="addBtnClass">
                  <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                  </svg>
                  添加可直连节点
                </button>
              </div>
              <p class="mt-2 text-xs text-slate-400">不带协议时会同时尝试 TCP 和 UDP；端口填写对端的隧道端口。</p>
            </div>
            <div class="mt-4">
              <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                指定中转规则
                <span class="text-xs text-slate-500 ml-2">目标IP或CIDR,中转虚拟IP</span>
              </label>
              <div class="space-y-2">
                <div v-for="(turnRule, idx) in formData.turn" :key="idx" class="flex gap-2">
                  <input
                    v-model="formData.turn[idx]"
                    type="text"
                    placeholder="例如: 10.26.0.0/24,10.26.0.2"
                    class="input flex-1"
                  />
                  <button @click="formData.turn.splice(idx, 1)" :class="removeBtnClass">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                </div>
                <button @click="formData.turn.push('')" :class="addBtnClass">
                  <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                  </svg>
                  添加中转规则
                </button>
              </div>
              <p class="mt-2 text-xs text-slate-400">命中目标不参与 P2P 打洞；中转节点已直连时优先经其转发，填写网关 IP 时强制走服务器。</p>
            </div>
          </div>

          <!-- 网络设置 -->
          <div class="card">
            <h4 :class="sectionTitleClass">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
                />
              </svg>
              网络设置
            </h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                  自定义虚拟IP
                  <span class="text-xs text-slate-500 ml-1">(可选)</span>
                </label>
                <input v-model="formData.ip" type="text" placeholder="例如: 10.26.0.2" class="input" />
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">MTU</label>
                <input v-model.number="formData.mtu" type="number" placeholder="1380" class="input" />
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">隧道端口</label>
                <input v-model.number="formData.tunnel_port" type="number" placeholder="0 (自动分配)" class="input" />
              </div>
            </div>
          </div>

          <!-- 传输优化 -->
          <div class="card">
            <h4 :class="sectionTitleClass">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              传输优化
            </h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label :class="toggleLabelClass">
                <div class="flex-1">
                  <div class="text-sm font-medium text-slate-800 dark:text-white">QUIC传输优化</div>
                  <div class="text-xs text-slate-400 mt-0.5">重传丢包</div>
                </div>
                <input v-model="formData.rtx" type="checkbox" :class="checkboxClass" />
              </label>
              <label :class="toggleLabelClass">
                <div class="flex-1">
                  <div class="text-sm font-medium text-slate-800 dark:text-white">FEC前向纠错</div>
                  <div class="text-xs text-slate-400 mt-0.5">损失部分带宽提升稳定性</div>
                </div>
                <input v-model="formData.fec" type="checkbox" :class="checkboxClass" />
              </label>
              <label :class="toggleLabelClass">
                <div class="flex-1">
                  <div class="text-sm font-medium text-slate-800 dark:text-white">LZ4压缩</div>
                  <div class="text-xs text-slate-400 mt-0.5">减少传输数据量</div>
                </div>
                <input v-model="formData.compress" type="checkbox" :class="checkboxClass" />
              </label>
              <label :class="toggleLabelClass">
                <div class="flex-1">
                  <div class="text-sm font-medium text-slate-800 dark:text-white">关闭P2P打洞</div>
                  <div class="text-xs text-slate-400 mt-0.5">关闭自动打洞；显式节点地址仍可直连</div>
                </div>
                <input v-model="formData.no_punch" type="checkbox" :class="checkboxClass" />
              </label>
              <label :class="toggleLabelClass">
                <div class="flex-1">
                  <div class="text-sm font-medium text-slate-800 dark:text-white">关闭IPv4广播和组播</div>
                  <div class="text-xs text-slate-400 mt-0.5">停止转发本机发出的 IPv4 广播和组播</div>
                </div>
                <input v-model="formData.no_broadcast" type="checkbox" :class="checkboxClass" />
              </label>
            </div>
          </div>

          <!-- 安全配置 -->
          <div class="card">
            <h4 :class="sectionTitleClass">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
              安全配置
            </h4>
            <div class="space-y-4">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300"
                    >组网加密密码(同一组网密码需要相同)</label
                  >
                  <input v-model="formData.password" type="password" placeholder="留空则不加密" class="input" />
                </div>
                <div>
                  <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">服务端证书校验模式</label>
                  <AppSelect v-model="formData.cert_mode" :options="certificateModeOptions" aria-label="服务端证书校验模式" />
                </div>
              </div>
              <div v-if="formData.cert_mode === 'finger'">
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                  证书指纹
                  <span class="text-xs text-slate-500 ml-1">(服务端启动时日志会输出指纹)</span>
                </label>
                <input
                  v-model="formData.fingerprint"
                  type="text"
                  placeholder="例如: 3bdd8675606837cdf95d5e13445606315762315a78555f9da652940a25feaec1"
                  class="input font-mono text-sm"
                />
              </div>
            </div>
          </div>

          <!-- NAT与路由 -->
          <div class="card">
            <h4 :class="sectionTitleClass">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 01-.806-.98L15 9m0 0V7m0 2v6"
                />
              </svg>
              NAT与路由 (点对网)
            </h4>
            <div class="space-y-4">
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                  入栈网段
                  <span class="text-xs text-slate-500 ml-1">格式: CIDR,目标IP</span>
                </label>
                <div class="space-y-2">
                  <div v-for="(item, idx) in formData.input" :key="idx" class="flex gap-2">
                    <input v-model="formData.input[idx]" type="text" placeholder="例如: 192.168.0.0/24,10.26.0.2" class="input flex-1" />
                    <button @click="formData.input.splice(idx, 1)" :class="removeBtnClass">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <button
                    @click="formData.input.push('')"
                    :class="addBtnClass"
                  >
                    + 添加入栈网段
                  </button>
                </div>
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                  出栈网段
                  <span class="text-xs text-slate-500 ml-1">格式: CIDR (允许转发的网段)</span>
                </label>
                <div class="space-y-2">
                  <div v-for="(item, idx) in formData.output" :key="idx" class="flex gap-2">
                    <input v-model="formData.output[idx]" type="text" placeholder="例如: 0.0.0.0/0" class="input flex-1" />
                    <button @click="formData.output.splice(idx, 1)" :class="removeBtnClass">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <button
                    @click="formData.output.push('')"
                    :class="addBtnClass"
                  >
                    + 添加出栈网段
                  </button>
                </div>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label :class="toggleLabelClass">
                  <div class="flex-1">
                    <div class="text-sm font-medium text-slate-800 dark:text-white">关闭内置NAT</div>
                    <div class="text-xs text-slate-400 mt-0.5">使用系统网卡转发</div>
                  </div>
                  <input v-model="formData.no_nat" type="checkbox" :class="checkboxClass" />
                </label>
                <div class="rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-700 dark:bg-slate-800/50">
                  <div class="flex-1">
                    <div class="text-sm font-medium text-slate-800 dark:text-white">虚拟网卡模式</div>
                    <div class="mt-0.5 text-xs text-slate-400">
                      <template v-if="formData.device_mode === 'no'">使用端口转发，无需管理员权限</template>
                      <template v-else-if="formData.device_mode === 'tap'">
                        构建虚拟以太网<template v-if="isWindows"
                          >；需要安装tap-windows驱动，建议指定<span class="font-medium text-slate-500 dark:text-slate-300">虚拟网卡名</span></template
                        >
                      </template>
                      <template v-else>构建虚拟IP网络</template>
                    </div>
                  </div>
                  <AppSelect v-model="formData.device_mode" :options="deviceModeOptions" class="mt-2" aria-label="虚拟网卡模式" />
                </div>
              </div>
            </div>
          </div>

          <!-- 端口映射 -->
          <div class="card">
            <h4 :class="sectionTitleClass">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"
                />
              </svg>
              端口映射
            </h4>
            <div class="space-y-4">
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">
                  映射规则
                  <span class="text-xs text-slate-500 ml-1">格式: 协议://监听地址-虚拟IP-目标地址</span>
                </label>
                <div class="space-y-2">
                  <div v-for="(item, idx) in formData.port_mapping" :key="idx" class="flex gap-2">
                    <input
                      v-model="formData.port_mapping[idx]"
                      type="text"
                      placeholder="例如: tcp://0.0.0.0:81-10.0.0.2-10.0.0.2:80"
                      class="input flex-1 font-mono"
                    />
                    <button @click="formData.port_mapping.splice(idx, 1)" :class="removeBtnClass">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <button
                    @click="formData.port_mapping.push('')"
                    :class="addBtnClass"
                  >
                    + 添加映射规则
                  </button>
                </div>
              </div>
              <label :class="toggleLabelClass">
                <div class="flex-1">
                  <div class="text-sm font-medium text-slate-800 dark:text-white">允许作为映射出口</div>
                  <div class="text-xs text-slate-400 mt-0.5">允许其他设备使用本机作跳板来进行端口映射</div>
                </div>
                <input v-model="formData.allow_mapping" type="checkbox" :class="checkboxClass" />
              </label>
            </div>
          </div>

          <!-- 设备配置 -->
          <div class="card">
            <h4 :class="sectionTitleClass">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                />
              </svg>
              设备配置
            </h4>
            <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">设备名称</label>
                <input v-model="formData.device_name" type="text" placeholder="默认为主机名" class="input" />
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">设备ID</label>
                <input v-model="formData.device_id" type="text" placeholder="自动生成" class="input" />
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">虚拟网卡名</label>
                <input v-model="formData.tun_name" type="text" placeholder="可选" class="input" />
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">绑定出口网卡</label>
                <input
                  v-model="formData.outbound_interface"
                  type="text"
                  placeholder="例如 Ethernet、Wi-Fi、eth0"
                  class="input"
                />
                <p class="mt-1.5 text-xs leading-5 text-slate-400">服务端通信、P2P 打洞及转发流量将使用此网卡</p>
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">事件脚本</label>
                <input
                  v-model="formData.event_script"
                  type="text"
                  placeholder="外部脚本路径，留空不触发"
                  class="input"
                />
                <p class="mt-1.5 text-xs leading-5 text-slate-400">
                  网卡创建成功、掉线、重连成功、IP 变化时以命令行参数调用事件脚本（例如 C:\scripts\vnt-event.bat）
                </p>
              </div>
            </div>
          </div>

          <!-- STUN配置 -->
          <div class="card">
            <h4 :class="sectionTitleClass">
              <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              STUN配置 (高级)
            </h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">UDP STUN服务器</label>
                <div class="space-y-2">
                  <div v-for="(item, idx) in formData.udp_stun" :key="idx" class="flex gap-2">
                    <input v-model="formData.udp_stun[idx]" type="text" placeholder="例如: stun.l.google.com:19302" class="input flex-1" />
                    <button @click="formData.udp_stun.splice(idx, 1)" :class="removeBtnClass">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <button
                    @click="formData.udp_stun.push('')"
                    :class="addBtnClass"
                  >
                    + 添加UDP STUN
                  </button>
                </div>
              </div>
              <div>
                <label class="mb-2 block text-sm font-medium text-slate-600 dark:text-slate-300">TCP STUN服务器</label>
                <div class="space-y-2">
                  <div v-for="(item, idx) in formData.tcp_stun" :key="idx" class="flex gap-2">
                    <input v-model="formData.tcp_stun[idx]" type="text" placeholder="例如: stun.nextcloud.com:443" class="input flex-1" />
                    <button @click="formData.tcp_stun.splice(idx, 1)" :class="removeBtnClass">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <button
                    @click="formData.tcp_stun.push('')"
                    :class="addBtnClass"
                  >
                    + 添加TCP STUN
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- TOML模式 -->
      <div v-show="editMode === 'toml'" class="h-full">
        <textarea
          v-model="editorContent"
          class="h-full w-full resize-none bg-slate-50 p-4 font-mono text-sm text-slate-800 focus:outline-none dark:bg-slate-950 dark:text-slate-200"
          spellcheck="false"
          placeholder="# 在此处输入 TOML 配置..."
        ></textarea>
      </div>
    </template>

    <template #footer>
      <div class="flex-1 text-left text-xs text-slate-500">
        <span v-if="editMode === 'form'">填写完成后保存即可生成配置文件</span>
        <span v-else>* 请使用标准 TOML 格式</span>
      </div>
      <button class="btn-ghost" @click="emit('close')">取消</button>
      <button class="btn-primary" @click="handleSave">保存配置</button>
    </template>
  </AppModal>
</template>
