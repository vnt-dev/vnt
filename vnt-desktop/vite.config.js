import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import tailwindcss from "@tailwindcss/vite";

const sharedUi = fileURLToPath(new URL("../vnt-web/ui/src", import.meta.url));
const desktopRoot = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      "@shared": sharedUi,
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    fs: { allow: [desktopRoot, sharedUi] },
    watch: { ignored: ["**/src-tauri/**"] },
  },
  clearScreen: false,
});
