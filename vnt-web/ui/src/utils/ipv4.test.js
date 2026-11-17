import assert from "node:assert/strict";
import test from "node:test";
import { isValidIpv4 } from "./ipv4.js";

test("IPv4 DNS validation agrees with the backend address format", () => {
  for (const value of ["0.0.0.0", "255.255.255.255", " 10.26.0.3 "]) {
    assert.equal(isValidIpv4(value), true, value);
  }
  for (const value of ["010.26.0.3", "10.026.0.3", "256.0.0.1", "10.26.0", "::1", "invalid", ""]) {
    assert.equal(isValidIpv4(value), false, value);
  }
});
