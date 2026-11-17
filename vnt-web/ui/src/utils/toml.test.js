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
