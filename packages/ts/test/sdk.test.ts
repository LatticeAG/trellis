import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, parseStrict, JsonError } from "../src/json.js";
import { exitCode, envelope, frame, Deframer } from "../src/wire.js";
import { FleetConsole, HostedUnsupportedError, CloudControl } from "../src/hosted.js";

test("canonical: sorted keys, no whitespace", () => {
  assert.equal(canonical({ b: 2, a: "1" }), '{"a":"1","b":2}');
});

test("canonical: no unicode normalization", () => {
  const a = canonical({ x: "é" });
  const b = canonical({ x: "é" });
  assert.notEqual(a, b);
});

test("parseStrict: duplicate key rejected", () => {
  assert.throws(() => parseStrict('{"v":1,"v":1}'), JsonError);
});

test("parseStrict: -0 rejected", () => {
  assert.throws(() => parseStrict('{"x":-0}'), JsonError);
});

test("parseStrict: floats/exponents rejected", () => {
  assert.throws(() => parseStrict('{"x":1.5}'), JsonError);
  assert.throws(() => parseStrict('{"x":1e3}'), JsonError);
});

test("parseStrict: leading zero rejected", () => {
  assert.throws(() => parseStrict('{"x":00}'), JsonError);
});

test("frame: 4-byte BE length + canonical payload", () => {
  const f = frame({ v: 1, method: "host.get", params: {}, id: "trq_000000000000000000001" });
  const n = f.readUInt32BE(0);
  assert.equal(n, f.length - 4);
  assert.equal(f.subarray(4).toString(), canonical({ v: 1, id: "trq_000000000000000000001", method: "host.get", params: {} }));
});

test("Deframer: partial then complete", () => {
  const d = new Deframer();
  const f = frame(envelope("host.get", {}));
  assert.equal(d.push(f.subarray(0, 3)), null);
  const r = d.push(f.subarray(3));
  assert.ok(r !== null);
});

test("exitCode map", () => {
  assert.equal(exitCode("INVALID_INPUT"), 64);
  assert.equal(exitCode("UNSUPPORTED_HOST"), 65);
  assert.equal(exitCode("UNAUTHORIZED"), 69);
  assert.equal(exitCode("BUSY"), 75);
  assert.equal(exitCode("AUDIT_FAULT"), 70);
  assert.equal(exitCode("INCOMPLETE", true), 76);
});

test("hosted surfaces throw NOT_IMPLEMENTED", () => {
  assert.throws(() => new FleetConsole().enroll(), HostedUnsupportedError);
  assert.throws(() => new FleetConsole().remoteKill("trr_x"), HostedUnsupportedError);
  assert.throws(() => new CloudControl().sync(), HostedUnsupportedError);
  try {
    new FleetConsole().enroll();
  } catch (e) {
    assert.match((e as Error).message, /TRELLIS_SPEC/);
  }
});
