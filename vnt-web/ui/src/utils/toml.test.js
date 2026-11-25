import assert from "node:assert/strict";
import test from "node:test";
import { emptyFormData, formToToml, parseTomlToForm } from "./toml.js";

test("DNS addresses work without a separate switch", () => {
  const form = emptyFormData();
  form.dns = ["10.26.0.3", "223.5.5.5"];
  const toml = formToToml(form);
  assert.match(toml, /dns = \["10.26.0.3", "223.5.5.5"\]/);
  assert.doesNotMatch(toml, /dns_tunnel/);
  assert.deepEqual(parseTomlToForm(toml).dns, form.dns);
});

test("clearing DNS preserves an explicit empty list", () => {
  const form = parseTomlToForm('dns = ["10.26.0.3"]');
  form.dns = [" "];
  const toml = formToToml(form);
  assert.match(toml, /dns = \[\]/);
  const parsed = parseTomlToForm(toml);
  assert.deepEqual(parsed.dns, []);
  assert.equal(parsed.dns_explicit, true);
});

test("default DNS is omitted and explicit empty DNS survives editing", () => {
  assert.doesNotMatch(formToToml(emptyFormData()), /^dns\s*=/m);
  assert.match(formToToml(parseTomlToForm("dns = []")), /^dns = \[\]/m);
});

test("an unrelated form edit preserves multiline arrays, explicit defaults, and extension data", () => {
  const source = [
    "# keep this comment",
    "'server' = [",
    "  'tcp://server.example:29872', # primary",
    '  "quic://backup.example:29872",',
    "]",
    "no_nat = false # true is not the value",
    "dns = []",
    'cert_mode = "skip"',
    "[other]",
    'device_name = "not the root device name"',
    "large_integer = 9223372036854775807",
    "decimal = 1.0",
    "",
  ].join("\n");
  const form = parseTomlToForm(source);
  assert.deepEqual(form.server, ["tcp://server.example:29872", "quic://backup.example:29872"]);
  assert.equal(form.no_nat, false);
  assert.equal(form.device_name, "");
  assert.equal(formToToml(form, source), source);
  form.device_name = "updated";
  const saved = formToToml(form, source);
  assert.equal(saved, source.replace("[other]", 'device_name = "updated"\n[other]'));
  assert.equal(parseTomlToForm(saved).device_name, "updated");
});

test("Windows paths and quotes survive both literal input and edited output", () => {
  const path = String.raw`C:\scripts\vnt-event.bat`;
  const source = `event_script = '${path}' # keep\n`;
  const form = parseTomlToForm(source);
  assert.equal(form.event_script, path);
  form.event_script = path + ' "quoted"';
  form.password = "line1\nline2\t\x7f";
  const updated = formToToml(form, source);
  assert.match(updated, /# keep/);
  const parsed = parseTomlToForm(updated);
  assert.equal(parsed.event_script, form.event_script);
  assert.equal(parsed.password, form.password);
});

test("edits the intended fields without rewriting comments or nested names", () => {
  const source = [
    'subscription = "old" # link',
    "compress = true",
    'dns = ["10.26.0.3"]',
    "tunnel_port = 29873 # legacy port",
    "extra.enabled = true",
    '[[extras]]',
    'subscription = "leave me alone"',
    "",
  ].join("\r\n");
  const form = parseTomlToForm(source);
  assert.deepEqual(form.tunnel_addr, ["0.0.0.0:29873"]);
  assert.equal(formToToml(form, source), source);
  form.subscription = "";
  form.compress = false;
  form.dns = [""];
  form.tunnel_addr = ["[::]:29874"];
  const updated = formToToml(form, source);
  assert.doesNotMatch(updated, /subscription = "old"|^tunnel_port\s*=/m);
  assert.match(updated, /compress = false\r\n/);
  assert.match(updated, /dns = \[\]\r\n/);
  assert.match(updated, /# link|# legacy port/);
  assert.match(updated, /extra\.enabled = true/);
  assert.match(updated, /\[\[extras\]\]\r\nsubscription = "leave me alone"/);
  assert.deepEqual(parseTomlToForm(updated).tunnel_addr, ["[::]:29874"]);
});
