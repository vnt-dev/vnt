<script setup>
import { ref, watch, onMounted, nextTick } from "vue";
import { formatSpeed, niceNumber } from "../utils/format";

const props = defineProps({
  history: { type: Object, required: true }, // { tx: [], rx: [] }
  size: { type: Number, default: 60 }, // 历史点数
});

const canvasRef = ref(null);
const maxLabel = ref("");

const draw = () => {
  const canvas = canvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const txArr = props.history ? props.history.tx : [];
  const rxArr = props.history ? props.history.rx : [];
  const HISTORY_SIZE = props.size;

  // 高清适配
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0) return;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const w = rect.width;
  const h = rect.height;
  const isDark = document.documentElement.classList.contains("dark");
  const colors = isDark
    ? { bg: "#0c1222", grid: "rgba(71, 85, 105, 0.3)", rx: "#60a5fa", rxFill: "rgba(96, 165, 250, 0.15)", tx: "#4ade80", txFill: "rgba(74, 222, 128, 0.15)" }
    : { bg: "#f8fafc", grid: "rgba(148, 163, 184, 0.35)", rx: "#3b82f6", rxFill: "rgba(59, 130, 246, 0.12)", tx: "#22c55e", txFill: "rgba(34, 197, 94, 0.12)" };

  const padTop = 8,
    padBottom = 4,
    padLeft = 0,
    padRight = 0;
  const chartW = w - padLeft - padRight;
  const chartH = h - padTop - padBottom;

  // 背景
  ctx.fillStyle = colors.bg;
  ctx.fillRect(0, 0, w, h);

  // 计算Y轴最大值
  const allValues = [...txArr, ...rxArr];
  let maxVal = allValues.length > 0 ? Math.max(...allValues) : 0;
  if (maxVal < 1024) maxVal = 1024; // 最小1KB
  const niceMax = niceNumber(maxVal);

  maxLabel.value = "峰值: " + formatSpeed(niceMax);

  // 网格线
  const gridLines = 4;
  ctx.strokeStyle = colors.grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= gridLines; i++) {
    const y = padTop + (chartH / gridLines) * i;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(padLeft + chartW, y);
    ctx.stroke();
  }
  // 垂直网格线
  const vLines = 6;
  for (let i = 0; i <= vLines; i++) {
    const x = padLeft + (chartW / vLines) * i;
    ctx.beginPath();
    ctx.moveTo(x, padTop);
    ctx.lineTo(x, padTop + chartH);
    ctx.stroke();
  }

  // 绘制曲线
  const drawLine = (data, strokeColor, fillColor) => {
    if (data.length < 2) return;
    const step = chartW / (HISTORY_SIZE - 1);
    const offset = HISTORY_SIZE - data.length;

    // 填充区域
    ctx.beginPath();
    ctx.moveTo(padLeft + offset * step, padTop + chartH);
    for (let i = 0; i < data.length; i++) {
      const x = padLeft + (offset + i) * step;
      const y = padTop + chartH - (data[i] / niceMax) * chartH;
      if (i === 0) ctx.lineTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.lineTo(padLeft + (offset + data.length - 1) * step, padTop + chartH);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();

    // 线条
    ctx.beginPath();
    for (let i = 0; i < data.length; i++) {
      const x = padLeft + (offset + i) * step;
      const y = padTop + chartH - (data[i] / niceMax) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 1.5;
    ctx.stroke();
  };

  drawLine(rxArr, colors.rx, colors.rxFill);
  drawLine(txArr, colors.tx, colors.txFill);
};

onMounted(() => nextTick(draw));

// 历史数据更新时重绘(数组原地 push/shift,监听引用内每个点)
watch(
  () => [props.history?.tx?.length, props.history?.rx?.length, props.history?.tx?.at(-1), props.history?.rx?.at(-1)],
  () => nextTick(draw),
);

defineExpose({ draw });
</script>

<template>
  <div>
    <div class="flex items-center gap-4 mb-2 text-xs text-slate-400">
      <span class="flex items-center"
        ><span class="inline-block w-3 h-0.5 bg-green-400 mr-1"></span>上传速度</span
      >
      <span class="flex items-center"
        ><span class="inline-block w-3 h-0.5 bg-blue-400 mr-1"></span>下载速度</span
      >
      <span class="ml-auto">{{ maxLabel }}</span>
    </div>
    <canvas ref="canvasRef" class="rounded w-full block h-[150px]"></canvas>
  </div>
</template>
