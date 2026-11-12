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
| Stolen client API key | Create challenges and read their status | Cannot approve. Anything outside the auto-allow rules still needs an approver signature. Damage is bounded by the policy limits and velocity caps. | `flow.rs` |
| Database copy leaked (read) | Read public keys, API key hashes, history | Cannot approve (no private keys), cannot call the API (hashes only), cannot issue receipts (the signing key is not there). | `flow.rs` |
| Database write access | Insert, edit or delete rows | Cannot grant themselves power: credentials, API keys and policies are sealed with the server key and ignored without a valid seal. An edited policy fails closed to "deny everything". Cannot extend the audit log: every entry is signed. Edits, deletions and extra grants are reported by `twof audit verify`. | `tamper.rs` |
| Network attacker or tampering client | Replay or alter requests | Receipts bind the hash of the canonical action; changing amount or destination invalidates them. Receipts expire in minutes and are consumed once. Approvals are bound to one challenge. | `flow.rs`, core |
| Phishing an approver | Show a fake page | Passkeys are bound to the real origin, so a look-alike site cannot obtain a usable signature. The signature covers the action hash, so approving A cannot be reused for B. | `passkey.rs` |
| Misleading the approver's screen | Send text that displays as something else | Invisible and text reordering characters are rejected in every field shown. Free form notes are displayed apart from amount and destination. | core `action` |
| Stolen approver device, or a rogue approver | Approve as that person | Rules can require several distinct people or an independent co-signer. Disabling an approver revokes their credentials and their approvals on pending challenges stop counting. | `tamper.rs` |
| Cloned passkey | Use a copy of an authenticator | A signature counter that fails to grow is refused. | `passkey.rs` |
| Weak channel compromised (Telegram account) | Read notifications | Telegram only carries the link. It never approves. | `channels.rs` |
| Compromised 2F server (code execution and signing key) | Issue receipts | This defeats the receipt on its own. Clients that pin approver public keys verify the approver signatures inside the receipt themselves, and an independent co-signer on another machine refuses to sign anything its own policy rejects, including a binding that does not match the action shown to it. | `channels.rs`, SDK tests |

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
- **Replaying an old seal.** An attacker with write access who saved a
  credential's seal before it was revoked can restore the row. `twof audit
  verify` reports it; the server alone does not, because it would need to
  replay the log on every approval.
- **History based limits.** Velocity caps are computed from stored
  challenges. Deleting rows resets them; the audit check shows the deletion.
- **Key rotation** is not implemented. Seals and audit signatures are tied to
  the one server key.
- **The approver's own device.** Malware that changes what the screen shows
  before the person confirms is outside what a server can prevent.
- **A client that skips verification.** The receipt only protects a client
  that checks it before executing.
- **Denial of service** is limited to per address rate limiting. Put the
  server behind a proxy that does more if you need it.
- **Real device coverage.** Passkey verification is tested against a software
  authenticator that follows the WebAuthn specification, not yet against a
  matrix of real phones and browsers.
