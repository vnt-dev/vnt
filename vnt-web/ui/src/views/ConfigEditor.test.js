import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import vue from "@vitejs/plugin-vue";
import { createServer } from "vite";
import { createRenderer, h, nextTick, reactive, ssrContextKey } from "vue";

const fakeDependencies = {
  "virtual:editor-api": `
    export const api = {};
    export const getConfig = (...args) => api.getConfig(...args);
    export const previewSubscription = (...args) => api.previewSubscription(...args);
    export const saveConfig = (...args) => api.saveConfig(...args);
  `,
  "virtual:editor-ui": `
    export const toast = { success() {}, error() {} };
    export const useUiStore = () => ({ toast });
  `,
};

let vite;
let editor;
let api;
let toast;
before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("../../", import.meta.url)),
    configFile: false,
    optimizeDeps: { noDiscovery: true },
    server: { middlewareMode: true, hmr: false, watch: null, ws: false },
    plugins: [
      {
        name: "config-editor-test-dependencies",
        enforce: "pre",
        resolveId(id, importer) {
          if (importer?.endsWith("/ConfigEditor.vue")) {
            if (id === "../api") return "\0virtual:editor-api";
            if (id === "../stores/ui") return "\0virtual:editor-ui";
          }
          if (id in fakeDependencies) return "\0" + id;
        },
        load(id) { return fakeDependencies[id.slice(1)]; },
      },
      vue(),
    ],
  });
  ({ default: editor } = await vite.ssrLoadModule("/src/views/ConfigEditor.vue"));
  ({ api } = await vite.ssrLoadModule("virtual:editor-api"));
  ({ toast } = await vite.ssrLoadModule("virtual:editor-ui"));
});
after(async () => { await vite?.close(); });

const renderer = createRenderer({
  createComment: () => ({}),
  insert(node, parent) { node.parent = parent; },
  parentNode: (node) => node.parent,
  nextSibling: () => null,
  remove() {},
});
const config = (name) => `network_code = "${name}"\nip = "10.10.0.2/24"\n`;

function openEditor(t, fileName = "a.toml") {
  const props = reactive({ show: true, fileName });
  const reads = [];
  const writes = [];
  const errors = [];
  const events = [];
  api.getConfig = (name) => new Promise((resolve, reject) => reads.push({ name, resolve, reject }));
  api.saveConfig = async (...args) => { writes.push(args); };
  toast.error = (error) => { errors.push(error); };
  let state;
  const component = {
    ...editor,
    setup(props, context) {
      state = editor.setup(props, context);
      return state;
    },
    render: () => null,
  };
  const app = renderer.createApp({
    render: () => h(component, {
      ...props, onClose: () => events.push("close"), onSaved: () => events.push("saved"),
    }),
  });
  app.provide(ssrContextKey, {});
  app.mount({});
  t.after(() => app.unmount());
  return { state, props, reads, writes, errors, events };
}

test("changing files clears the old form and blocks saves until the new file loads", async (t) => {
  const { state, props, reads, writes } = openEditor(t);
  reads[0].resolve(config("a"));
  await nextTick();
  assert.equal(state.formData.value.network_code, "a");

  props.show = false;
  await nextTick();
  props.fileName = "b.toml";
  props.show = true;
  await nextTick();
  assert.equal(state.canEdit.value, false);
  assert.equal(state.formData.value.network_code, "");
  assert.equal(state.editorContent.value, "");
  await state.handleSave();
  assert.deepEqual(writes, []);

  assert.equal(reads[1].name, "b.toml");
  reads[1].resolve(config("b"));
  await nextTick();
  assert.equal(state.canEdit.value, true);
  await state.handleSave();
  assert.deepEqual(writes, [["b.toml", config("b")]]);
});

test("an old response cannot replace a newer file that has already loaded", async (t) => {
  const { state, props, reads, writes } = openEditor(t);
  props.fileName = "b.toml"; // The modal can stay open while its target changes.
  await nextTick();
  reads[1].resolve(config("b"));
  await nextTick();
  reads[0].resolve(config("a"));
  await nextTick();
  await state.handleSave();
  assert.deepEqual(writes, [["b.toml", config("b")]]);
});

test("an old failure cannot close a reopened editor for the same filename", async (t) => {
  const { state, props, reads, errors, events } = openEditor(t);
  props.show = false;
  await nextTick();
  props.show = true;
  await nextTick();
  reads[0].reject(new Error("old request"));
  await nextTick();
  assert.equal(state.canEdit.value, false);
  assert.deepEqual(errors, []);
  assert.deepEqual(events, []);

  reads[1].resolve(config("fresh"));
  await nextTick();
  assert.equal(state.formData.value.network_code, "fresh");
  assert.equal(state.canEdit.value, true);
});

test("a file that cannot open as a form can still be corrected in TOML mode", async (t) => {
  const { state, reads, writes } = openEditor(t);
  reads[0].resolve("ip = [");
  await nextTick();
  assert.equal(state.canEdit.value, true);
  assert.equal(state.editMode.value, "toml");
  assert.equal(state.editorContent.value, "ip = [");

  state.editorContent.value = config("repaired");
  await state.handleSave();
  assert.deepEqual(writes, [["a.toml", config("repaired")]]);
});

test("a save finishing after a switch does not close the new editor", async (t) => {
  const { state, props, reads, writes, events } = openEditor(t);
  let finishSave;
  api.saveConfig = (...args) => new Promise((resolve) => {
    writes.push(args);
    finishSave = resolve;
  });
  reads[0].resolve(config("a"));
  await nextTick();
  const pending = state.handleSave();
  await state.handleSave();
  assert.deepEqual(writes, [["a.toml", config("a")]]);

  props.fileName = "b.toml";
  await nextTick();
  reads[1].resolve(config("b"));
  await nextTick();
  finishSave();
  await pending;
  assert.deepEqual(events, ["saved"]);
  assert.equal(state.formData.value.network_code, "b");
  assert.equal(state.canEdit.value, true);
});
