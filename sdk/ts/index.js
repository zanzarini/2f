// 2F client for Node.js 18+ and other runtimes with `fetch` and `node:crypto`.
// No dependencies. Types are in index.d.ts.

import { createHash, createPublicKey, verify as cryptoVerify, timingSafeEqual } from "node:crypto";

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");
const CLOCK_SKEW = 60;

export class TwoFError extends Error {
  /** @param {string} code @param {string} message */
  constructor(code, message) {
    super(message);
    this.name = "TwoFError";
    this.code = code;
  }
}

/** Canonical JSON: RFC 8785 without floating point numbers. */
export function canonical(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new TwoFError("invalid", "floating point numbers are not allowed; send amounts as decimal strings");
    if (Math.abs(value) > MAX_SAFE) throw new TwoFError("invalid", "integer outside the safe range");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (typeof value === "object") {
    // JavaScript compares strings by UTF-16 code units, which is what RFC 8785 asks for.
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  throw new TwoFError("invalid", "unsupported value in JSON: " + typeof value);
}

const taggedHash = (tag, text) => createHash("sha256").update(tag + "\n").update(text, "utf8").digest();
const fromB64 = (text) => {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new TwoFError("malformed", "invalid base64url");
  return Buffer.from(text, "base64url");
};
const ed25519Key = (hex) => {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex)) throw new TwoFError("invalid", "public key must be 32 bytes of hex");
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
};
const ed25519Verify = (hex, message, signature) => {
  try { return signature.length === 64 && cryptoVerify(null, message, ed25519Key(hex), signature); } catch { return false; }
};

/** SHA-256 hash (hex) that identifies an action. */
export function actionHash(action) {
  return taggedHash("2F-ACTION-v1", canonical(action)).toString("hex");
}

/** The 32 bytes approvers sign for a receipt payload or a binding. */
export function bindingHash(binding) {
  return taggedHash("2F-BINDING-v1", canonical(binding));
}

/**
 * Verifies a receipt for exactly `action`. Throws TwoFError on any failure.
 * `publicKeys` maps key id to hex public key. `now` is unix seconds.
 */
export function verifyReceipt(token, publicKeys, action, now = Math.floor(Date.now() / 1000)) {
  if (typeof token !== "string") throw new TwoFError("malformed", "receipt is malformed");
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new TwoFError("malformed", "receipt is malformed");
  const payloadBytes = fromB64(parts[0]);
  const signature = fromB64(parts[1]);
  let payload;
  try { payload = JSON.parse(payloadBytes.toString("utf8")); } catch { throw new TwoFError("malformed", "receipt is malformed"); }
  if (payload === null || typeof payload !== "object" || payload.v !== 1) throw new TwoFError("malformed", "receipt is malformed");
  const key = Object.prototype.hasOwnProperty.call(publicKeys, payload.kid) ? publicKeys[payload.kid] : undefined;
  if (!key) throw new TwoFError("unknown_key", "receipt was signed by an unknown key");
  const message = Buffer.concat([Buffer.from("2F-RECEIPT-v1\n"), payloadBytes]);
  if (!ed25519Verify(key, message, signature)) throw new TwoFError("bad_signature", "receipt signature is invalid");
  // A signed payload with fields of the wrong type must not slip through
  // comparisons that are false for anything that is not a number.
  if (!Number.isSafeInteger(payload.expires_at) || !Number.isSafeInteger(payload.issued_at) || typeof payload.action_hash !== "string") {
    throw new TwoFError("malformed", "receipt is malformed");
  }
  if (now > payload.expires_at) throw new TwoFError("expired", "receipt has expired");
  if (payload.issued_at > now + CLOCK_SKEW) throw new TwoFError("not_yet_valid", "receipt is not valid yet");
  const expected = Buffer.from(actionHash(action), "utf8");
  const got = Buffer.from(String(payload.action_hash), "utf8");
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) {
    throw new TwoFError("action_mismatch", "receipt was issued for a different action");
  }
  return payload;
}

/**
 * Names of approvers whose signature verifies against a key you pinned.
 * This holds even if the 2F server itself is compromised.
 * `pinned` maps approver id to hex Ed25519 public key.
 */
export function pinnedApprovers(payload, pinned) {
  const hash = bindingHash({
    v: 1, project: payload.project, challenge: payload.challenge,
    action_hash: payload.action_hash, expires_at: payload.binding_expires_at,
  });
  const names = new Set();
  for (const approval of payload.approvals || []) {
    if (approval.kind !== "ed25519" && approval.kind !== "cosigner") continue;
    if (!Object.prototype.hasOwnProperty.call(pinned, approval.approver)) continue;
    let signature;
    try { signature = fromB64(approval.sig); } catch { continue; }
    if (ed25519Verify(pinned[approval.approver], hash, signature)) names.add(approval.approver);
  }
  return [...names];
}

export class TwoF {
  /**
   * @param {{ url: string, apiKey: string, publicKeys: Record<string, string>, fetch?: typeof fetch }} options
   * `publicKeys` comes from `twof pubkey` on the server. Pin it in your
   * configuration; do not fetch it from the server at runtime.
   */
  constructor({ url, apiKey, publicKeys, fetch: fetchImpl }) {
    if (!url || !apiKey || !publicKeys) throw new TwoFError("invalid", "url, apiKey and publicKeys are required");
    this.url = url.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.publicKeys = publicKeys;
    this.fetch = fetchImpl || globalThis.fetch;
  }

  async request(method, path, body) {
    const response = await this.fetch(this.url + path, {
      method,
      headers: { Authorization: "Bearer " + this.apiKey, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? canonical(body) : undefined,
    });
    let data = null;
    try { data = await response.json(); } catch { /* not JSON */ }
    if (!response.ok) {
      const error = (data && data.error) || {};
      throw new TwoFError(error.code || "http_" + response.status, error.message || "request failed");
    }
    return data;
  }

  /** Creates a challenge. Returns immediately with its state. */
  createChallenge(action, idempotencyKey) {
    return this.request("POST", "/v1/challenges", { action, idempotency_key: idempotencyKey });
  }

  getChallenge(id, waitSeconds = 0) {
    return this.request("GET", "/v1/challenges/" + encodeURIComponent(id) + (waitSeconds ? "?wait=" + waitSeconds : ""));
  }

  /**
   * Asks for authorization and waits for the outcome.
   * Resolves to `{ authorized, state, receipt, payload, challenge }`.
   * When `authorized` is true the receipt was verified for exactly `action`.
   * `onPending` is called once with the challenge (it carries `approve_url`).
   */
  async authorize(action, { idempotencyKey, timeoutSeconds = 300, onPending } = {}) {
    if (!idempotencyKey) throw new TwoFError("invalid", "idempotencyKey is required");
    let challenge = await this.createChallenge(action, idempotencyKey);
    if (challenge.state === "pending" && onPending) await onPending(challenge);
    const deadline = Date.now() + timeoutSeconds * 1000;
    while (challenge.state === "pending" && Date.now() < deadline) {
      const wait = Math.max(1, Math.min(25, Math.ceil((deadline - Date.now()) / 1000)));
      challenge = await this.getChallenge(challenge.id, wait);
    }
    if (challenge.state !== "allowed" && challenge.state !== "approved") {
      return { authorized: false, state: challenge.state, receipt: null, payload: null, challenge };
    }
    const payload = verifyReceipt(challenge.receipt, this.publicKeys, action);
    return { authorized: true, state: challenge.state, receipt: challenge.receipt, payload, challenge };
  }

  /** Marks a receipt as used. Throws with code "conflict" if it was used before. */
  consume(receipt) {
    return this.request("POST", "/v1/receipts/consume", { receipt });
  }
}
