import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { actionHash, bindingHash, canonical, pinnedApprovers, TwoF, TwoFError, verifyReceipt } from "./index.js";

const vectors = JSON.parse(readFileSync(new URL("../vectors.json", import.meta.url), "utf8"));
const r = vectors.receipt;
const keys = { [r.server_kid]: r.server_public_key };
const code = (expected) => (error) => error instanceof TwoFError && error.code === expected;

test("canonical form matches the Rust implementation", () => {
  for (const { input, output } of vectors.canonical) assert.equal(canonical(JSON.parse(input)), output);
});

test("floats and unsafe integers are rejected", () => {
  assert.throws(() => canonical({ a: 1.5 }), code("invalid"));
  assert.throws(() => canonical({ a: 2 ** 53 }), code("invalid"));
  assert.throws(() => canonical({ a: NaN }), code("invalid"));
});

test("action and binding hashes match the Rust implementation", () => {
  for (const { action, canonical: text, hash } of vectors.actions) {
    assert.equal(canonical(action), text);
    assert.equal(actionHash(action), hash);
  }
  assert.equal(bindingHash(vectors.binding.binding).toString("base64url"), vectors.binding.hash);
});

test("a valid receipt verifies for its action only", () => {
  const payload = verifyReceipt(r.token, keys, r.action, r.valid_at);
  assert.equal(payload.challenge, "ch_test");
  assert.throws(() => verifyReceipt(r.token, keys, r.other_action, r.valid_at), code("action_mismatch"));
  assert.throws(() => verifyReceipt(r.token, keys, { ...r.action, amount: "1500.26" }, r.valid_at), code("action_mismatch"));
  assert.throws(() => verifyReceipt(r.token, keys, { ...r.action, destination: "0xevil" }, r.valid_at), code("action_mismatch"));
});

test("expired, forged and malformed receipts are refused", () => {
  assert.throws(() => verifyReceipt(r.token, keys, r.action, r.expired_at), code("expired"));
  assert.throws(() => verifyReceipt(r.token, keys, r.action, 1_000), code("not_yet_valid"));
  assert.throws(() => verifyReceipt(r.token, {}, r.action, r.valid_at), code("unknown_key"));
  assert.throws(() => verifyReceipt(r.token, { [r.server_kid]: r.approver_public_key }, r.action, r.valid_at), code("bad_signature"));

  const [body, signature] = r.token.split(".");
  const edited = JSON.parse(Buffer.from(body, "base64url").toString());
  edited.expires_at = 9_999_999_999;
  const spliced = Buffer.from(JSON.stringify(edited)).toString("base64url") + "." + signature;
  assert.throws(() => verifyReceipt(spliced, keys, r.action, r.valid_at), code("bad_signature"));
  for (const junk of ["", ".", "abc", "a.b.c", "!!.??", null, 42]) {
    assert.throws(() => verifyReceipt(junk, keys, r.action, r.valid_at), TwoFError);
  }
  // A key id that only exists on Object.prototype is not a pinned key.
  const proto = JSON.parse(Buffer.from(body, "base64url").toString());
  proto.kid = "toString";
  const sneaky = Buffer.from(JSON.stringify(proto)).toString("base64url") + "." + signature;
  assert.throws(() => verifyReceipt(sneaky, keys, r.action, r.valid_at), code("unknown_key"));
});

test("pinned approvers are verified without trusting the server", () => {
  const payload = verifyReceipt(r.token, keys, r.action, r.valid_at);
  assert.deepEqual(pinnedApprovers(payload, { [r.approver]: r.approver_public_key }), ["alice"]);
  assert.deepEqual(pinnedApprovers(payload, { [r.approver]: r.server_public_key }), []);
  assert.deepEqual(pinnedApprovers(payload, {}), []);
  assert.deepEqual(pinnedApprovers({ ...payload, challenge: "ch_other" }, { [r.approver]: r.approver_public_key }), []);
});

test("authorize waits, verifies the receipt, and reports refusals", async () => {
  const calls = [];
  const respond = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });
  const script = [
    respond({ id: "ch_test", state: "pending", approve_url: "http://x/approve/ch_test", receipt: null }),
    respond({ id: "ch_test", state: "pending", receipt: null }),
    respond({ id: "ch_test", state: "approved", receipt: r.token }),
  ];
  const fetchMock = async (url, init) => { calls.push({ url, init }); return script.shift(); };
  const client = new TwoF({ url: "http://x/", apiKey: "2f_k", publicKeys: keys, fetch: fetchMock });

  const realNow = Date.now;
  Date.now = () => r.valid_at * 1000;
  try {
    let seen = null;
    const result = await client.authorize(r.action, { idempotencyKey: "k1", onPending: (c) => { seen = c.approve_url; } });
    assert.equal(result.authorized, true);
    assert.equal(result.payload.id, "rc_test");
    assert.equal(seen, "http://x/approve/ch_test");
    assert.equal(calls[0].url, "http://x/v1/challenges");
    assert.equal(calls[0].init.headers.Authorization, "Bearer 2f_k");
    assert.match(calls[1].url, /\/v1\/challenges\/ch_test\?wait=\d+$/);

    // The server returns a receipt for a different action: never authorized.
    script.push(respond({ id: "ch_x", state: "allowed", receipt: r.token }));
    await assert.rejects(client.authorize(r.other_action, { idempotencyKey: "k2" }), code("action_mismatch"));

    script.push(respond({ id: "ch_y", state: "rejected", receipt: null }));
    assert.equal((await client.authorize(r.action, { idempotencyKey: "k3" })).authorized, false);

    script.push(respond({ error: { code: "unauthorized", message: "missing or invalid API key" } }, 401));
    await assert.rejects(client.authorize(r.action, { idempotencyKey: "k4" }), code("unauthorized"));
  } finally {
    Date.now = realNow;
  }
});
