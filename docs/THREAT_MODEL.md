# Threat model

2F sits between a system that wants to execute a transaction (the client) and
the execution itself. The client asks 2F "may I do exactly this?", and only
executes when it holds a valid receipt for exactly that action.

Nothing here is "unbreakable". This document states what an attacker can and
cannot do in each compromise scenario, so the claims can be checked.

## Assets

- Approver private keys (passkeys, device Ed25519 keys). Never leave the device.
- Server receipt signing key. Lives outside the database.
- Project API keys. Only their SHA-256 is stored.
- The audit log.

## Attackers and outcomes

| Scenario | What the attacker gets | What still holds |
|---|---|---|
| Stolen client API key | Can create challenges and read their status | Cannot approve. Actions outside the auto-allow rules still need an approver signature. Damage is bounded by the policy limits and velocity caps. |
| Database copy leaked | Public keys, API key hashes, history | Cannot approve (no private keys), cannot call the API (hashes only), cannot issue receipts (signing key is not in the database). |
| Network attacker / tampering client | Can replay or alter requests | Receipts bind the SHA-256 of the canonical action. Changing amount or destination invalidates the receipt. Receipts expire quickly and are single use. |
| Phishing an approver | Can show a fake page | Passkeys are origin bound, so a fake domain cannot obtain a signature. The signature covers the action hash, so approving A cannot be reused for B. |
| Weak channel compromised (Telegram account, TOTP secret) | Can answer that channel | Weak channels only satisfy a requirement when the policy explicitly accepts `weak` strength. By default they only notify. |
| Database write access | Can insert rows | Approvals are verified from signatures against enrolled public keys at issue time, and the audit chain makes edits and deletions detectable. Enrolling a new approver key by writing rows is the residual risk: see below. |
| Full server compromise (code execution + signing key) | Can issue receipts | This defeats the receipt. Mitigations: clients may pin approver public keys and verify the approver signatures carried in the receipt themselves (`verify_with_pinned_approvers`), and may require an independent co-signer running on another machine. |

## Design rules that follow

1. Fail closed. No matching rule means deny. Any parsing ambiguity means reject.
2. One canonical encoding. Actions are hashed from a strict canonical JSON
   form (RFC 8785 subset without floating point numbers). Amounts are decimal
   strings.
3. Domain separation. Every signed or hashed structure is prefixed with a
   distinct tag (`2F-ACTION-v1`, `2F-BINDING-v1`, `2F-RECEIPT-v1`,
   `2F-AUDIT-v1`), so a signature for one purpose cannot be replayed as another.
4. Approvers sign the binding, not a random nonce. The binding contains the
   project, challenge id, action hash and expiry.
5. No shared secrets for strong factors. The server stores public keys only.
6. Enrollment is itself a protected action. After bootstrap, adding an
   approver requires approval from an existing strong approver.
7. No recovery by email or SMS. Recovery is by quorum of remaining approvers
   or by an operator with local access to the machine (CLI), which is logged.
8. Standard primitives only: Ed25519, ECDSA P-256 (WebAuthn), SHA-256.

## Out of scope

- Malware on the approver's device that alters what the screen shows.
- A client that does not verify the receipt before executing.
- Denial of service beyond basic rate limiting.
