# Protocol v1

## Canonical JSON

All hashes are computed over canonical JSON: RFC 8785 (JCS) restricted to
values without floating point numbers.

- Object keys sorted by UTF-16 code units, no whitespace.
- Strings escaped exactly as ECMAScript `JSON.stringify`.
- Numbers must be integers with absolute value at most 2^53 - 1. Anything else
  is rejected. Monetary amounts are decimal strings (`"1500.25"`).
- Duplicate keys are rejected at parse time.

## Action

```json
{
  "type": "withdraw",
  "amount": "1500.25",
  "asset": "USDT",
  "destination": "0xabc...",
  "meta": { "order": "A-991" }
}
```

`type` is required. `amount`, `asset`, `destination` and `meta` are optional.
Unknown top level fields are rejected. `amount` is a plain non negative
decimal without sign, exponent, separators or leading zeros. Control
characters, invisible characters and text direction overrides are rejected in
every field.

`action_hash = SHA-256("2F-ACTION-v1\n" || canonical(action))`, hex encoded.

## Binding

What approvers sign.

```json
{ "v": 1, "project": "<id>", "challenge": "<id>", "action_hash": "<hex>", "expires_at": 1767225600 }
```

`binding_hash = SHA-256("2F-BINDING-v1\n" || canonical(binding))` (32 bytes).

- Ed25519 device approver: signature over the 32 byte `binding_hash`.
- Passkey approver: the WebAuthn challenge is the 32 byte `binding_hash`.
- Co-signer: receives action and binding, returns an Ed25519 signature over
  `binding_hash`.

## Policy

```json
{
  "version": 1,
  "lists": { "treasury": ["0xabc...", "0xdef..."] },
  "rules": [
    { "name": "small to known wallets",
      "when": { "type": ["withdraw"], "asset": ["USDT"], "amount_max": "100",
                "destination_in": ["treasury"],
                "velocity": { "window_secs": 86400, "max_total": "1000" } },
      "then": { "decision": "allow" } },
    { "name": "everything else needs a human",
      "when": {},
      "then": { "decision": "require",
                "requirements": [ { "count": 1, "min_strength": "strong" } ] } }
  ]
}
```

Rules are evaluated in order and the first match decides. No match means
`deny`. A condition on a field the action does not carry does not match.
`velocity` matches when the sum of amounts already authorized for the same
project and asset in the window, plus this amount, is at most `max_total`.

A requirement is satisfied by `count` (1 to 16) distinct approvers whose
strength is at least `min_strength`, optionally restricted by `kinds` and
`approvers`. A rule may carry up to 8 requirements, and one approver fills one
place across all of them: `[{"count":1,"kinds":["passkey"]},{"count":1,"kinds":["cosigner"]}]`
needs two different approvers. A `cosigner` is counted only by a requirement
whose `kinds` lists it; a requirement without `kinds` means people.

A project may have a limited number of challenges waiting for approval at once
(20 by default). Beyond it, `POST /v1/challenges` answers `429` for actions
that would need approval; actions the rules allow or deny are unaffected.

A policy is refused when a `then` block carries anything its decision does not
use, or when an `allow` rule looks at amounts (`amount_min`, `amount_max`,
`velocity`) without an `asset` condition.

## Receipt

`base64url(payload) "." base64url(signature)`, where `payload` is the canonical
JSON below and `signature` is Ed25519 over `"2F-RECEIPT-v1\n" || payload`.

```json
{
  "v": 1, "id": "<receipt id>", "project": "<id>", "challenge": "<id>",
  "action_hash": "<hex>", "decision": "allow | approved", "rule": "<rule name>",
  "approvals": [ { "approver": "<id>", "kind": "ed25519", "strength": "strong", "sig": "<base64url>" } ],
  "binding_expires_at": 1767225600,
  "issued_at": 1767225000, "expires_at": 1767225300, "kid": "<key id>"
}
```

The executing side must:

1. verify the signature with the server public key for `kid`;
2. check `expires_at`;
3. recompute `action_hash` from the action it is about to execute and compare;
4. make sure the receipt is used once (call `POST /v1/receipts/consume`, or
   track receipt ids locally).

Optionally it verifies each approval signature against pinned approver public
keys, which keeps approvals unforgeable even if the 2F server is compromised.

## HTTP API

All client calls carry `Authorization: Bearer <api key>`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/challenges` | Create. Body `{ "action": {...}, "idempotency_key": "..." }`. |
| GET | `/v1/challenges/{id}` | Status. `?wait=25` long-polls. |
| POST | `/v1/challenges/{id}/approvals` | Submit an approver signature. |
| POST | `/v1/receipts/consume` | Mark a receipt used. Fails the second time. |
| GET | `/v1/keys` | Server public keys (no auth). Clients should pin keys, not fetch them. |
| GET | `/v1/approvals/{id}` | What an approver needs: the action, the binding and the hashes to sign (no auth; the id is 128 random bits). |
| GET, POST | `/v1/enrollments/{token}` | Passkey registration through a one time link. |
| GET | `/approve/{id}`, `/enroll/{token}` | The built in approval and enrollment page. |

An approval body is either `{ "credential", "signature", "decision" }` for
Ed25519 keys, or `{ "passkey": { "id", "authenticator_data", "client_data_json",
"signature" }, "decision" }` for WebAuthn. `decision` is `approve` (default) or
`reject`; a refusal signs `SHA-256("2F-REJECT-v1
" || canonical(binding))`.

## Webhooks

`POST` to the configured URL with body
`{ "event", "ts", "project", "data" }` in canonical JSON and headers
`x-2f-signature` (base64url Ed25519 over `"2F-WEBHOOK-v1
" || body`) and
`x-2f-key`. Receivers must verify the signature and refuse events older than
300 seconds. Receipts are never sent in webhooks.

Challenge states: `pending`, `allowed`, `approved`, `denied`, `rejected`,
`expired`.

## Audit log

Append only. Each entry:

`hash = SHA-256("2F-AUDIT-v1\n" || canonical({ "seq", "ts", "kind", "data", "prev" }))`

`prev` is the hash of the previous entry (64 zeros for the first). Signed
checkpoints `{ "seq", "hash", "ts" }` are emitted periodically.
