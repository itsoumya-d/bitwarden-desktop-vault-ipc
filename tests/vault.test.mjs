import test from "node:test";
import assert from "node:assert/strict";
import { deriveMasterKey, stretchMasterKey, encryptItem, decryptItem } from "../dist/kdf.js";
import { DesktopIpcBroker, redactForLog } from "../dist/ipc.js";
import { parseAutotype, autotypePreview } from "../dist/autotype.js";

const email = "user@example.com";
const password = "correct horse battery staple";
const key = deriveMasterKey(password, email, { algorithm: "pbkdf2-sha256", iterations: 100_000, salt: Buffer.alloc(0) });
const request = (over = {}) => ({ id: "req-1", channel: "vault:list", sender: { frameId: 0, url: "app://bitwarden" }, payload: {}, ...over });

test("derives a deterministic 32-byte master key", () => {
  const again = deriveMasterKey(password, email, { algorithm: "pbkdf2-sha256", iterations: 100_000, salt: Buffer.alloc(0) });
  assert.equal(key.length, 32);
  assert.deepEqual(key, again);
});
test("normalizes email casing", () => {
  assert.deepEqual(deriveMasterKey(password, "USER@EXAMPLE.COM", { algorithm: "pbkdf2-sha256", iterations: 100_000, salt: Buffer.alloc(0) }), key);
});
test("rejects empty password", () => assert.throws(() => deriveMasterKey("", email, { algorithm: "pbkdf2-sha256", iterations: 100_000, salt: Buffer.alloc(0) })));
test("rejects invalid email", () => assert.throws(() => deriveMasterKey(password, "nope", { algorithm: "pbkdf2-sha256", iterations: 100_000, salt: Buffer.alloc(0) })));
test("rejects weak KDF configuration", () => assert.throws(() => deriveMasterKey(password, email, { algorithm: "pbkdf2-sha256", iterations: 10, salt: Buffer.alloc(0) })));
test("stretches to 32 bytes", () => assert.equal(stretchMasterKey(key).length, 32));
test("rejects a short key", () => assert.throws(() => stretchMasterKey(Buffer.alloc(16))));
test("encrypts and decrypts a vault item", () => {
  const item = encryptItem(JSON.stringify({ username: "ada", password: "secret" }), key);
  assert.equal(decryptItem(item, key), JSON.stringify({ username: "ada", password: "secret" }));
});
test("uses a fresh IV per item", () => {
  assert.notEqual(encryptItem("a", key).iv, encryptItem("a", key).iv);
});
test("rejects tampered ciphertext", () => {
  const item = encryptItem("a", key); item.ciphertext = Buffer.from("tampered").toString("base64");
  assert.throws(() => decryptItem(item, key));
});
test("tracks key version", () => assert.equal(encryptItem("a", key, 3).keyVersion, 3));
test("allows a trusted vault:list request", () => {
  const broker = new DesktopIpcBroker();
  assert.deepEqual(broker.authorize(request()), { allowed: true, reason: "ok" });
});
test("blocks unknown channels", () => {
  const broker = new DesktopIpcBroker();
  assert.equal(broker.authorize(request({ channel: "vault:export" })).reason, "channel not allowed");
});
test("blocks untrusted origins", () => {
  const broker = new DesktopIpcBroker();
  assert.equal(broker.authorize(request({ sender: { frameId: 0, url: "https://evil.example" } })).reason, "untrusted sender");
});
test("blocks subframes", () => {
  const broker = new DesktopIpcBroker();
  assert.equal(broker.authorize(request({ sender: { frameId: 7, url: "app://bitwarden" } })).reason, "untrusted frame");
});
test("blocks replayed request IDs", () => {
  const broker = new DesktopIpcBroker();
  broker.authorize(request());
  assert.equal(broker.authorize(request()).reason, "replayed request");
});
test("executes only after authorization and redacts secrets", () => {
  const broker = new DesktopIpcBroker();
  const out = broker.execute(request(), () => JSON.stringify({ password: "secret", ok: true }));
  assert.equal(out.ok, true);
  assert.equal(out.result, JSON.stringify({ password: "[redacted]", ok: true }));
});
test("audit log records allow/deny", () => {
  const broker = new DesktopIpcBroker();
  broker.authorize(request());
  broker.authorize(request({ id: "req-2", channel: "vault:export" }));
  assert.equal(broker.auditLog().length, 2);
  assert.equal(broker.auditLog()[1].allowed, false);
});
test("redacts sensitive keys", () => assert.equal(redactForLog('{"token":"abc","ok":true}'), '{"token":"[redacted]","ok":true}'));
test("parses autotype fields and keys", () => {
  const steps = parseAutotype("{username}{tab}{password}{enter}", { username: "ada", password: "secret" });
  assert.equal(autotypePreview(steps), "ada[TAB]secret[ENTER]");
});
test("rejects empty autotype", () => assert.throws(() => parseAutotype(" ", {})));
test("rejects unknown autotype fields", () => assert.throws(() => parseAutotype("{missing}", {})));
