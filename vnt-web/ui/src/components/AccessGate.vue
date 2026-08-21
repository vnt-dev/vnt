<script setup>
import { ref } from "vue";
import { saveAccessToken } from "../auth";
import vntIcon from "../assets/vnt-icon.png";

const token = ref("");
const submit = () => {
  if (!token.value.trim()) return;
  saveAccessToken(token.value);
  window.location.reload();
};
</script>

<template>
  <main class="grid h-[100dvh] place-items-center overflow-y-auto bg-slate-50 p-4 text-slate-700 dark:bg-slate-950 dark:text-slate-200">
    <form class="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8 dark:border-slate-800 dark:bg-slate-900" @submit.prevent="submit">
      <div class="mb-7 flex items-center gap-3">
        <img :src="vntIcon" alt="" class="h-10 w-10 shrink-0" />
        <div>
          <h1 class="text-lg font-bold text-slate-900 dark:text-white">访问 VNT 控制台</h1>
          <p class="mt-0.5 text-xs text-slate-400">请输入桌面端 Web 访问设置中的令牌</p>
        </div>
      </div>
      <label class="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-200" for="access-token">访问令牌</label>
      <input id="access-token" v-model="token" class="input font-mono" type="password" autocomplete="current-password" autofocus placeholder="粘贴访问令牌" />
      <button class="btn-primary mt-5 w-full" type="submit" :disabled="!token.trim()">进入控制台</button>
      <p class="mt-5 text-center text-xs leading-5 text-slate-400">令牌只保存在当前浏览器中，可随时在桌面端重新生成。</p>
    </form>
  </main>
</template>
