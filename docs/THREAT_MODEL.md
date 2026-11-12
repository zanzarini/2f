# Threat model

2F sits between a system that wants to execute a transaction (the client) and
the execution itself. The client asks 2F "may I do exactly this?", and only
executes when it holds a valid receipt for exactly that action.

Nothing here is "unbreakable". This document states what an attacker can and
cannot do in each compromise scenario, so the claims can be checked. Each row
of the table has tests behind it; the file is named in the last column.

## Assets

- Approver private keys (passkeys, device keys, co-signer keys). Never leave
  their owner.
- Server signing key. Lives outside the database (key file or `TWOF_KEY`).
- Project API keys. Only their SHA-256 is stored.
- The audit log.

## Attackers and outcomes

| Scenario | What the attacker can do | What still holds | Tests |
|---|---|---|---|
| Stolen client API key | Create challenges and read their status | Cannot approve. Anything outside the auto-allow rules still needs an approver signature. Damage is bounded by the policy limits and velocity caps. Approvers cannot be buried in requests until one slips through: a project has a small limit of approvals waiting at once (`--max-pending`, 20 by default). | `flow.rs` |
| A careless or hostile network path to the server | Read or redirect what the client sends | The SDKs refuse plain HTTP except to the local machine, so the API key is not sent in the clear, and they do not follow redirects, which would carry the key elsewhere. | SDK tests |
| The same authorization acted on twice | Retry after a crash, or replay a response | `authorize` in the SDKs marks the receipt as used before returning. A second attempt with the same idempotency key gets "conflict" instead of a second go-ahead. | SDK tests, `flow.rs` |
| Database copy leaked (read) | Read public keys, API key hashes, history | Cannot approve (no private keys), cannot call the API (hashes only), cannot issue receipts (the signing key is not there). | `flow.rs` |
| Database write access | Insert, edit or delete rows | Cannot grant themselves power. Credentials, API keys, policies, enrollment links, notification settings and every challenge (its state, requirements and deadline) are sealed with the server key; a row without a valid seal is ignored or refused, and an edited policy fails closed to "deny everything". A planted approval does not count: each stored signature is verified again when the quorum is counted. The approver is never shown an action other than the one whose hash is signed. A decided challenge or a used receipt cannot be put back while the server runs. Notifications planted or redirected in the queue are not sent. The audit log cannot be extended (every entry is signed), and `twof audit verify` reports rows that no longer match it: grants, policies, challenge states, used receipts. | `tamper.rs`, `channels.rs` |
| Network attacker or tampering client | Replay or alter requests | Receipts bind the hash of the canonical action; changing amount or destination invalidates them. Receipts expire in minutes and are consumed once. Approvals are bound to one challenge. | `flow.rs`, core |
| Phishing an approver | Show a fake page | Passkeys are bound to the real origin, so a look-alike site cannot obtain a usable signature. The signature covers the action hash, so approving A cannot be reused for B. | `passkey.rs` |
| Misleading the approver's screen | Send text that displays as something else | Invisible and text reordering characters are rejected in every field shown. Free form notes are displayed apart from amount and destination. | core `action` |
| Stolen approver device, or a rogue approver | Approve as that person | Rules can require several distinct people or an independent co-signer. One person fills one place: someone holding two kinds of credential does not satisfy "a person and the vault" alone. A co-signer machine never counts as "one approver": it fills, and can veto, only requirements that name it. Disabling an approver revokes their credentials and their approvals on pending challenges stop counting. | `tamper.rs`, core `policy` |
| A policy written carelessly | Rely on a rule that allows more than intended | Policies are refused when they contain an unknown field, an outcome with parts that do not belong to it (`allow` with `requirements`), or an `allow` rule that limits amounts without naming the asset. | core `policy` |
| Cloned passkey | Use a copy of an authenticator | A signature counter that fails to grow is refused. | `passkey.rs` |
| Weak channel compromised (Telegram account) | Read notifications | Telegram only carries the link. It never approves. | `channels.rs` |
| Compromised 2F server (code execution and signing key) | Issue receipts | This defeats the receipt on its own. Three things still stand. Clients that pin approver public keys verify the device key and co-signer signatures inside the receipt themselves. An independent co-signer on another machine refuses anything its own policy rejects, including a binding that does not match the action shown to it, and keeps its own running total, so many small requests do not get past its velocity limit. The terminal approver (`twof device approve`) and the approval page recompute the hash from the action they display and refuse a mismatch. | `channels.rs`, `device.rs`, SDK tests |

## Design rules that follow

1. Fail closed. No matching rule means deny. A parsing ambiguity means reject.
   A row with a bad seal does not exist.
2. One canonical encoding. Actions are hashed from a strict canonical JSON
   form (RFC 8785 without floating point numbers). Amounts are decimal
   strings. Duplicate keys are rejected.
3. Domain separation. Every signed or hashed structure carries its own tag
   (`2F-ACTION-v1`, `2F-BINDING-v1`, `2F-REJECT-v1`, `2F-RECEIPT-v1`,
   `2F-AUDIT-v1`, `2F-AUDIT-SIG-v1`, `2F-CHECKPOINT-v1`, `2F-SEAL-v1`,
   `2F-WEBHOOK-v1`).
4. Approvers sign the binding, not a random nonce: project, challenge, action
   hash and expiry.
5. No shared secrets for strong factors. The server stores public keys only.
6. Administration is local. Enrolling approvers, changing policies and
   creating API keys happen through the CLI on the machine, never over HTTP.
7. No recovery by email or SMS.
8. Standard primitives only: Ed25519, ECDSA P-256 (WebAuthn), SHA-256.
9. Authentication before parsing. Unauthenticated callers learn nothing from
   later checks.

## Known limits

Stated plainly so nobody relies on something that is not there.

- **Cutting the end off the audit log** is only detected against a checkpoint
  kept somewhere the server cannot write. Run `twof audit checkpoint` on a
  schedule and store the output elsewhere.
- **Putting back an old version of a row.** A seal proves this server wrote
  a row, not that it is the newest version. Someone with write access who
  saved a credential before it was revoked, or a policy before it was
  tightened, can restore it with its genuine seal. For challenges and receipts
  the running server remembers what it has seen decided or used and refuses
  the old version; for credentials and policies, which are changed from the
  command line, only `twof audit verify` reports it. Run it on a schedule.
- **History based limits.** Velocity caps are computed from stored
  challenges. Deleting rows resets them; the audit check shows the deletion.
- **Pinned approvers cover keys, not passkeys.** The SDKs verify device key
  and co-signer signatures inside a receipt. Passkey proofs are carried in the
  receipt but the SDKs do not verify them yet.
- **Enrollment links.** Whoever opens a registration link first registers
  their device. Links are single use, last 15 minutes and are logged; hand
  them over through a channel you trust.
- **The co-signer's memory.** Its running total lives in memory and starts
  from zero when its process restarts.
- **Key rotation** is not implemented. Seals and audit signatures are tied to
  the one server key.
- **The approver's own device.** Malware that changes what the screen shows
  before the person confirms is outside what a server can prevent.
- **A client that skips verification.** The receipt only protects a client
  that checks it before executing.
- **Denial of service** is limited to per address rate limiting and the
  limit of waiting approvals. Slow or stalled connections are not timed out by
  2F itself: run it behind a reverse proxy, which is needed for HTTPS anyway.
- **Rules match exactly.** `"usdt"` is not `"USDT"`, and an address in another
  letter case is another address. Write rules that allow what you know and
  send everything else to a person, rather than rules that deny what you
  fear: a deny rule is only as good as its spelling.
- **Real device coverage.** Passkey verification is tested against a software
  authenticator that follows the WebAuthn specification, not yet against a
  matrix of real phones and browsers.
