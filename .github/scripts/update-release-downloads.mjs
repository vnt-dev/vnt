import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const START_MARKER = "<!-- vnt-downloads:start -->";
const END_MARKER = "<!-- vnt-downloads:end -->";

const TOOL_TARGETS = [
  ["Windows", "x86_64", "x86_64-pc-windows-msvc"],
  ["Windows", "x86", "i686-pc-windows-msvc"],
  ["Windows", "ARM64", "aarch64-pc-windows-msvc"],
  ["Linux", "x86_64", "x86_64-unknown-linux-musl"],
  ["Linux", "ARM64", "aarch64-unknown-linux-musl"],
  ["Linux", "ARMv7 hard-float", "armv7-unknown-linux-musleabihf"],
  ["Linux", "ARMv7 soft-float", "armv7-unknown-linux-musleabi"],
  ["Linux", "ARM hard-float", "arm-unknown-linux-musleabihf"],
  ["Linux", "ARM soft-float", "arm-unknown-linux-musleabi"],
  ["Linux", "MIPS little-endian", "mipsel-unknown-linux-musl"],
  ["Linux", "MIPS big-endian", "mips-unknown-linux-musl"],
  ["macOS", "Apple Silicon", "aarch64-apple-darwin"],
  ["macOS", "Intel", "x86_64-apple-darwin"],
  ["FreeBSD 13.2", "x86_64", "x86_64-unknown-freebsd"],
];

const DOWNLOADS = [
  {
    product: "VNT Desktop",
    platform: "Windows",
    architecture: "x86_64",
    format: "EXE 安装包",
    filename: ({ version }) => `VNT.Desktop_${version}_windows_x64-setup.exe`,
  },
  {
    product: "VNT Desktop",
    platform: "Windows",
    architecture: "x86_64",
    format: "MSI 安装包",
    filename: ({ version }) => `VNT.Desktop_${version}_windows_x64.msi`,
  },
  ...TOOL_TARGETS.map(([platform, architecture, target]) => ({
    product: "VNT 工具包",
    platform,
    architecture,
    format: "ZIP",
    filename: ({ tag }) => `vnt2-${target}-${tag}.zip`,
  })),
];

export function buildDownloadSection({ version, tag, releaseUrl, assetNames }) {
  const rows = DOWNLOADS.flatMap((download) => {
    const filename = download.filename({ version, tag });
    if (!assetNames.has(filename)) return [];
    const url = `${releaseUrl}/${encodeURIComponent(filename)}`;
    return [
      `| ${download.product} | ${download.platform} | ${download.architecture} | [${download.format}](${url}) |`,
    ];
  });

  if (rows.length === 0) return undefined;

  return [
    START_MARKER,
    "## 下载",
    "",
    "> VNT 工具包包含 `vnt2_web`、`vnt2_cli` 和 `vnt2_ctrl`。",
    "",
    "| 产品 | 平台 | 架构 | 下载 |",
    "|---|---|---|---|",
    ...rows,
    END_MARKER,
  ].join("\n");
}

export function mergeDownloadSection(notes, section) {
  const start = notes.indexOf(START_MARKER);
  if (start === -1) {
    const existing = notes.trimEnd();
    return existing.length === 0 ? `${section}\n` : `${existing}\n\n${section}\n`;
  }

  const end = notes.indexOf(END_MARKER, start);
  if (end === -1) {
    throw new Error("release notes contain an incomplete download section");
  }

  return `${notes.slice(0, start)}${section}${notes.slice(end + END_MARKER.length)}`;
}

function releaseAssetId(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  if (parsed.hostname !== "api.github.com") return undefined;
  return parsed.pathname.match(/\/releases\/assets\/(\d+)$/)?.[1];
}

export function normalizeUpdaterManifest(manifest, assets) {
  const downloadUrls = new Map(
    assets.map((asset) => [String(asset.id), asset.browser_download_url]),
  );
  let changed = false;
  const platforms = Object.fromEntries(
    Object.entries(manifest.platforms || {}).map(([target, platform]) => {
      const assetId = releaseAssetId(platform.url);
      if (!assetId) return [target, platform];

      const downloadUrl = downloadUrls.get(assetId);
      if (!downloadUrl) {
        throw new Error(
          `updater platform ${target} references unknown release asset ${assetId}`,
        );
      }
      changed = true;
      return [target, { ...platform, url: downloadUrl }];
    }),
  );

  return {
    changed,
    manifest: changed ? { ...manifest, platforms } : manifest,
  };
}

function normalizeReleaseUpdaterManifest({ repository, tag, release }) {
  const latestAsset = release.assets.find((asset) => asset.name === "latest.json");
  if (!latestAsset) throw new Error(`release ${tag} does not contain latest.json`);

  const manifest = JSON.parse(
    execFileSync(
      "gh",
      [
        "api",
        "-H",
        "Accept: application/octet-stream",
        `repos/${repository}/releases/assets/${latestAsset.id}`,
      ],
      { encoding: "utf8", env: process.env, windowsHide: true },
    ),
  );
  const normalized = normalizeUpdaterManifest(manifest, release.assets);
  if (!normalized.changed) return;

  const manifestDir = mkdtempSync(join(tmpdir(), "vnt-updater-manifest-"));
  const manifestPath = join(manifestDir, "latest.json");
  try {
    writeFileSync(manifestPath, `${JSON.stringify(normalized.manifest, null, 2)}\n`);
    execFileSync(
      "gh",
      ["release", "upload", tag, manifestPath, "--repo", repository, "--clobber"],
      { stdio: "inherit", env: process.env, windowsHide: true },
    );
  } finally {
    rmSync(manifestDir, { recursive: true, force: true });
  }
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function main() {
  const repository = requiredEnv("GITHUB_REPOSITORY");
  const tag = requiredEnv("GITHUB_REF_NAME");
  const serverUrl = requiredEnv("GITHUB_SERVER_URL").replace(/\/$/, "");
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const configPath = resolve(workspace, "vnt-desktop/src-tauri/tauri.conf.json");
  const version = JSON.parse(readFileSync(configPath, "utf8")).version;
  const release = JSON.parse(
    execFileSync(
      "gh",
      ["api", `repos/${repository}/releases/tags/${tag}`],
      { encoding: "utf8", env: process.env, windowsHide: true },
    ),
  );

  normalizeReleaseUpdaterManifest({ repository, tag, release });
  const assetNames = new Set(release.assets.map((asset) => asset.name));
  const releaseUrl = `${serverUrl}/${repository}/releases/download/${tag}`;
  const section = buildDownloadSection({ version, tag, releaseUrl, assetNames });
  if (!section) throw new Error(`release ${tag} does not contain recognized assets`);

  const notes = release.body || "";
  const updatedNotes = mergeDownloadSection(notes, section);
  if (updatedNotes === notes) return;

  const notesFile = join(
    process.env.RUNNER_TEMP || tmpdir(),
    `vnt-release-notes-${process.pid}.md`,
  );
  try {
    writeFileSync(notesFile, updatedNotes);
    execFileSync(
      "gh",
      ["release", "edit", tag, "--repo", repository, "--notes-file", notesFile],
      { stdio: "inherit", env: process.env, windowsHide: true },
    );
  } finally {
    if (existsSync(notesFile)) unlinkSync(notesFile);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
