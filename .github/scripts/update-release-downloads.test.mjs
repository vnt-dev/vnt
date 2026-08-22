import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDownloadSection,
  mergeDownloadSection,
  normalizeUpdaterManifest,
} from "./update-release-downloads.mjs";

test("builds links for desktop installers and target tool bundles", () => {
  const section = buildDownloadSection({
    version: "2.0.0",
    tag: "v2.0.0",
    releaseUrl: "https://github.com/vnt-dev/vnt/releases/download/v2.0.0",
    assetNames: new Set([
      "VNT.Desktop_2.0.0_windows_x64-setup.exe",
      "vnt2-x86_64-unknown-linux-musl-v2.0.0.zip",
    ]),
  });

  assert.match(section, /VNT\.Desktop_2\.0\.0_windows_x64-setup\.exe/);
  assert.match(section, /vnt2-x86_64-unknown-linux-musl-v2\.0\.0\.zip/);
  assert.doesNotMatch(section, /VNT\.Desktop_2\.0\.0_windows_x64\.msi/);
});

test("replaces an existing release download section", () => {
  const oldSection = [
    "<!-- vnt-downloads:start -->",
    "old links",
    "<!-- vnt-downloads:end -->",
  ].join("\n");
  const merged = mergeDownloadSection(`Release notes\n\n${oldSection}\n`, "new links");

  assert.equal(merged, "Release notes\n\nnew links\n");
});

test("replaces GitHub API updater URLs with public download URLs", () => {
  const manifest = {
    version: "2.0.0",
    platforms: {
      "windows-x86_64": {
        signature: "windows-signature",
        url: "https://api.github.com/repos/vnt-dev/vnt/releases/assets/101",
      },
    },
  };
  const assets = [
    {
      id: 101,
      browser_download_url:
        "https://github.com/vnt-dev/vnt/releases/download/v2.0.0/VNT.exe",
    },
  ];

  const normalized = normalizeUpdaterManifest(manifest, assets);

  assert.equal(normalized.changed, true);
  assert.equal(
    normalized.manifest.platforms["windows-x86_64"].url,
    assets[0].browser_download_url,
  );
  assert.equal(
    normalized.manifest.platforms["windows-x86_64"].signature,
    "windows-signature",
  );
});

test("rejects updater URLs for unknown release assets", () => {
  assert.throws(
    () =>
      normalizeUpdaterManifest(
        {
          platforms: {
            "windows-x86_64": {
              signature: "signature",
              url: "https://api.github.com/repos/vnt-dev/vnt/releases/assets/999",
            },
          },
        },
        [],
      ),
    /unknown release asset 999/,
  );
});
