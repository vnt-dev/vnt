import { copyFileSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import process from "node:process";

const profile = process.argv[2] === "debug" ? "debug" : "release";
const desktopRoot = resolve(import.meta.dirname, "..");
const workspaceRoot = resolve(desktopRoot, "..");

const rustc = spawnSync("rustc", ["-vV"], { encoding: "utf8", shell: false });
if (rustc.status !== 0) {
  throw new Error(`无法读取 Rust 目标信息：${rustc.stderr || rustc.error}`);
}
const host = rustc.stdout.match(/^host:\s*(.+)$/m)?.[1]?.trim();
const target = process.env.TAURI_ENV_TARGET_TRIPLE || process.env.CARGO_BUILD_TARGET || host;
if (!target) throw new Error("无法确定 VNT Web sidecar 的 Rust target triple");

const cargoArgs = ["build", "--bin", "vnt2_web", "--features", "vnt-web"];
if (target !== host) cargoArgs.push("--target", target);
if (profile === "release") cargoArgs.push("--release");
const build = spawnSync("cargo", cargoArgs, {
  cwd: workspaceRoot,
  stdio: "inherit",
  shell: false,
});
if (build.status !== 0) {
  throw new Error(`构建内置 VNT Web 程序失败（exit ${build.status ?? "unknown"}）`);
}

const extension = target.includes("windows") ? ".exe" : "";
const source = join(
  workspaceRoot,
  "target",
  ...(target === host ? [] : [target]),
  profile,
  `vnt2_web${extension}`,
);
const destination = join(
  desktopRoot,
  "src-tauri",
  "binaries",
  `vnt2-web-${target}${extension}`,
);
mkdirSync(dirname(destination), { recursive: true });
copyFileSync(source, destination);
process.stdout.write(`VNT Web sidecar: ${destination}\n`);
