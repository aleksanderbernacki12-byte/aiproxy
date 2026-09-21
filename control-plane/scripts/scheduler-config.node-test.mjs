import assert from "node:assert/strict";
import test from "node:test";
import { internalBaseUrl, requestTimeout } from "./scheduler-config.mjs";

test("scheduler accepts only credential-free HTTP(S) internal URLs", () => {
  assert.equal(internalBaseUrl("http://app:3000").href, "http://app:3000/");
  assert.equal(internalBaseUrl("https://control.internal").href, "https://control.internal/");
  for (const value of ["ftp://app", "http://user:secret@app", "http://app?secret=x", "http://app#fragment"]) {
    assert.throws(() => internalBaseUrl(value));
  }
});

test("scheduler request timeout is bounded", () => {
  assert.equal(requestTimeout(undefined), 70_000);
  assert.equal(requestTimeout("5000"), 5_000);
  assert.equal(requestTimeout("300000"), 300_000);
  for (const value of ["4999", "300001", "1.5", "invalid"]) assert.throws(() => requestTimeout(value));
});
