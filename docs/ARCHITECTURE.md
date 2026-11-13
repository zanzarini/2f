# Architecture

Structure and behaviour of 2F. Wire formats are specified in
[PROTOCOL.md](PROTOCOL.md); the purpose of each defence is given in
[THREAT_MODEL.md](THREAT_MODEL.md).

- [1. Overview](#1-overview)
- [2. Approval sequence](#2-approval-sequence)
- [3. Challenge lifecycle](#3-challenge-lifecycle)
- [4. Signatures](#4-signatures)
- [5. Policy evaluation](#5-policy-evaluation)
- [6. Server internals](#6-server-internals)
- [7. Performance](#7-performance)
- [8. Trust boundaries](#8-trust-boundaries)

## 1. Overview

The calling system does not execute on its own authority. It submits the
action to 2F and executes only when it holds a receipt for that exact action.

```mermaid
flowchart LR
    subgraph yours["Your side"]
        bot["Bot, backend<br/>or AI agent"]
        exec["Execution<br/>(exchange, bank, chain)"]
    end
    subgraph twof["2F server"]
        api["HTTP API"]
        rules{"Rules"}
        log[("Audit log")]
    end
    subgraph approvers["Approvers"]
        phone["Person with<br/>a passkey"]
        cli["Device key"]
        vault["Independent<br/>co-signer"]
    end

    bot -- "1. may I do exactly this?" --> api
    api --> rules
    rules -- "allow" --> receipt(["Signed receipt"])
    rules -- "require" --> approvers
    approvers -- "signature over<br/>the exact action" --> receipt
    rules -- "deny" --> stop(["Refused"])
    receipt -- "2. verified locally" --> bot
    bot -- "3. execute" --> exec
    api -.-> log
```

## 2. Approval sequence

A withdrawal to an address the rules do not know, approved by a person.

```mermaid
sequenceDiagram
    autonumber
    participant C as Your system
    participant S as 2F server
    participant A as Approver's device

    C->>S: POST /v1/challenges { action, idempotency_key }
    S->>S: canonical JSON, hash, evaluate rules
    S-->>C: pending, approve_url
    S-)A: notification (Telegram, webhook, or your own)
    A->>S: open approval page
    S-->>A: the action and the hash to sign
    Note over A: The person reads amount and destination,<br/>then confirms with fingerprint, face or PIN
    A->>S: signature over the binding hash
    S->>S: verify against the sealed credential,<br/>count distinct approvers
    S-->>C: approved, receipt (long poll returns at once)
    C->>C: verify receipt signature, expiry<br/>and that it covers this exact action
    C->>S: POST /v1/receipts/consume
    S-->>C: consumed (second attempt: 409)
    C->>C: execute
```

## 3. Challenge lifecycle

```mermaid
stateDiagram-v2
    [*] --> allowed: a rule allows
    [*] --> denied: a rule denies, or no rule matches
    [*] --> pending: a rule requires approval
    pending --> approved: every requirement met
    pending --> rejected: any eligible approver refuses
    pending --> expired: deadline passes
    allowed --> [*]: receipt issued
    approved --> [*]: receipt issued
    denied --> [*]
    rejected --> [*]
    expired --> [*]
```

Only `allowed` and `approved` produce a receipt. A refusal is final: a later
approval does not revive the challenge.

## 4. Signatures

Every signature covers a hash that leads back to the exact action. Each
structure has its own tag, so a signature made for one purpose is never valid
for another.

```mermaid
flowchart TD
    action["Action<br/>type, amount, asset, destination, meta"]
    ah["action_hash<br/>SHA-256('2F-ACTION-v1' + canonical JSON)"]
    binding["Binding<br/>project, challenge, action_hash, expires_at"]
    bh["binding_hash<br/>SHA-256('2F-BINDING-v1' + ...)"]
    rh["reject_hash<br/>SHA-256('2F-REJECT-v1' + ...)"]
    receipt["Receipt<br/>action_hash, approvals with their signatures,<br/>validity, key id"]

    action --> ah --> binding
    binding --> bh
    binding --> rh
    bh -- "signed by each approver<br/>(passkey: as the WebAuthn challenge)" --> approvals["Approvals"]
    rh -- "signed to refuse" --> refusal["Refusal"]
    approvals --> receipt
    ah --> receipt
    receipt -- "signed by the server key<br/>'2F-RECEIPT-v1'" --> token(["Receipt token"])
```

Because the approver signatures travel inside the receipt, a client that pins
approver public keys can check them itself. That holds even if the 2F server
is fully compromised.

## 5. Policy evaluation

```mermaid
flowchart TD
    start(["Action arrives"]) --> first{"Next rule:<br/>do all its conditions match?"}
    first -- "no" --> more{"More rules?"}
    more -- "yes" --> first
    more -- "no" --> deny(["Deny"])
    first -- "yes" --> outcome{"Outcome"}
    outcome -- "allow" --> allow(["Receipt now"])
    outcome -- "deny" --> deny
    outcome -- "require" --> wait(["Wait for approvers"])
```

Conditions fail closed. A condition on a field the action does not carry does
not match; a velocity limit whose history cannot be read does not match; a
policy whose seal does not verify is treated as "deny everything".

## 6. Server internals

```mermaid
flowchart TB
    subgraph cli["twof (CLI)"]
        admin["Administration<br/>projects, keys, policies, approvers"]
        serve["serve"]
        cosign["cosign"]
    end
    subgraph server["crates/server"]
        http["http.rs<br/>strict parsing, auth first,<br/>rate limit, security headers"]
        service["service.rs<br/>every operation"]
        store["store.rs<br/>writer thread + reader pool"]
        delivery["delivery.rs<br/>webhooks, Telegram, retries"]
        cos["cosigner.rs"]
    end
    subgraph core["crates/core (no IO)"]
        canonical["canonical"]
        policy["policy"]
        receiptm["receipt"]
        passkey["passkey"]
        auditm["audit"]
        seal["seal"]
    end
    db[("SQLite file")]
    web["web/<br/>approval page"]

    serve --> http --> service --> store --> db
    admin --> service
    cosign --> cos
    service --> core
    delivery --> service
    http --> web
```

`crates/core` has no network, no clock and no disk. Everything that decides
whether an action is authorized lives there and is tested in isolation. The
SDKs in `sdk/` reimplement only the client half (canonical form, hashes,
receipt verification) and are pinned to the core by shared test vectors.

## 7. Performance

A durable commit costs one disk sync, on the order of milliseconds. One sync
per request would limit the server to a few hundred writes per second, so the
writer commits in groups.

```mermaid
sequenceDiagram
    participant R1 as Request 1
    participant R2 as Request 2
    participant R3 as Request 3
    participant W as Writer thread
    participant D as Disk

    R1->>W: operation
    W->>D: BEGIN, run 1, COMMIT (sync)
    R2->>W: operation (queued while syncing)
    R3->>W: operation (queued while syncing)
    D-->>W: durable
    W-->>R1: result
    W->>D: BEGIN, run 2, run 3, COMMIT (one sync for both)
    D-->>W: durable
    W-->>R2: result
    W-->>R3: result
```

- One writer thread owns the only writing connection. Operations never race,
  so single use receipts, velocity limits and the audit chain need no locks.
- Each operation runs in its own savepoint. One refusing does not undo the
  others in its batch.
- No response is sent before the data is on disk (`synchronous=FULL`).
- Reads use a pool of read only connections and never wait for a sync.
- Clients waiting for an approval are woken by the commit that decides it,
  instead of polling.

Measured with `cargo test --release -p twof-server --test bench -- --ignored
--nocapture`, 8 threads, database on disk, on a laptop:

| Operation | Throughput |
|---|---|
| Authenticate an API key | about 240,000 per second |
| Read a pending challenge | about 450,000 per second |
| Create, allow by rule and issue a receipt (durable) | about 3,900 per second |
| Create, approve with a signature and issue a receipt (durable) | about 1,500 per second |

These are in-process figures for the service layer. HTTP adds overhead, and
write throughput depends on the storage device.

## 8. Trust boundaries

```mermaid
flowchart LR
    subgraph never["Never leaves its owner"]
        k1["Approver private keys<br/>(phone, device, co-signer)"]
        k2["Server signing key<br/>(file or secret, not in the database)"]
    end
    subgraph database["Database file"]
        d1["Public keys"]
        d2["API key hashes"]
        d3["Policies"]
        d4["Signed audit log"]
    end
    k2 -- "seals" --> d1
    k2 -- "seals" --> d2
    k2 -- "seals" --> d3
    k2 -- "signs every entry" --> d4
```

The database holds nothing that lets its reader act, and nothing its writer
can use to grant themselves power: credentials, API keys, policies, enrollment
links, notification settings and every challenge are sealed with the server
key and refused when the seal does not verify. Stored approvals are verified
again, signature by signature, whenever a quorum is counted.

The tables are where grants are looked up, but the signed log is what decides
them. The server follows the log entry by entry, checking that each one
continues the last and carries its signature, and keeps in memory what the log
says is in force. A row that the log does not support is ignored, however
genuine its seal; a log that is cut, altered or extended by someone else stops
the server.

```mermaid
flowchart LR
    cli["CLI: grant, revoke,<br/>set policy"] -- "signed entry" --> log[("Audit log")]
    log -- "followed entry by entry,<br/>each one verified" --> ledger["In memory:<br/>what is in force"]
    table[("Tables")] -- "row found" --> check{"Sealed, and<br/>in force per the log?"}
    ledger --> check
    check -- "yes" --> use(["Used"])
    check -- "no" --> ignore(["Ignored"])
```
