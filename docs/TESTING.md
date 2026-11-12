# How 2F is tested

No amount of testing proves the absence of flaws. What it can do is make each
claim cheap to check and expensive to break by accident. These are the layers,
from the narrowest to the widest, and how to run each.

| Layer | What it answers | Where | Run |
|---|---|---|---|
| Unit and property tests | Does each piece do what it says, for any input? | `crates/core/src/*` | `cargo test -p twof-core` |
| Attack tests | Does each row of the threat model hold against the attack it describes? | `crates/server/tests/flow.rs`, `passkey.rs`, `channels.rs`, `http.rs` | `cargo test -p twof-server` |
| Tamper tests | What can someone do with write access to the database file? | `crates/server/tests/tamper.rs` | same |
| Random model | Does the server agree with an independent, simpler model of the rules, over random sequences of operations? | `crates/server/tests/model.rs` | same; long run with `-- --ignored` |
| Random adversary | Can random writes into the database, an API key and an insider's device together produce a receipt the rules and real signatures do not support? | `crates/server/tests/adversary.rs` | same; long run with `-- --ignored` |
| Live server | Do the guarantees hold over real sockets with many clients at once? | `crates/server/tests/live.rs`, `scripts/e2e.sh` | `bash scripts/e2e.sh` |
| Cross language | Do Rust, TypeScript and Python agree on canonical form and hashes for thousands of random inputs? | `sdk/vectors.json`, `scripts/crosscheck.sh` | `bash scripts/crosscheck.sh` |
| Random garbage | Does any malformed request produce a server error? | `crates/server/tests/http.rs` | `cargo test -p twof-server --test http` |
| Mutation testing | Do the tests notice when a safety check is removed? | `scripts/mutate.py`, `scripts/mutate_sdk.py` | see below |

## The random model

`model.rs` holds a second, much smaller implementation of the approval rules:
who may fill which place is written out by hand, and a quorum is decided by
trying every assignment. Each random operation (ask, approve, refuse, forge,
wait, use a receipt, revoke someone) is sent to the real server and the answer
is compared with what the model expects. The two share no code. The test also
counts how often each outcome was reached, so a run that never got to an
approval cannot pass for one that checked approvals.

## The random adversary

`adversary.rs` checks safety only. The attacker rewrites requirements and
states, plants approvals and credentials, restores revoked rows with their
genuine seals, swaps policies, cuts and extends the log. The service is allowed
to fail. After every step, every receipt found anywhere is examined: it must be
for an action somebody really asked for, allowed by a rule that allows it or
approved by enough approvers who really signed that exact request.

## Mutation testing

A test suite that always passes proves little. `scripts/mutate.py` copies the
repository, removes one safety check at a time (about seventy of them), and
runs the tests against each mutant. A mutant that survives is a check that no
test defends: either a test is missing or the check is redundant.

```bash
python3 scripts/mutate.py .          # Rust; takes a while
python3 scripts/mutate_sdk.py ts . /tmp/sdkmut-ts
python3 scripts/mutate_sdk.py py . /tmp/sdkmut-py
```

Known survivors, and why they are left:

- **Receipt of another project consumed.** The project is checked twice, in
  code and in the SQL statement; removing one leaves the other.
- **Floats in the Python client.** Removing the explicit check lets the value
  fall through to the generic "unsupported value" refusal.

## What none of this covers

Passkeys on real phones and browsers, the Telegram delivery, the Docker image,
and anyone other than the author trying to break it.
