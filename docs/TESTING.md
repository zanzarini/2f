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
| Known attacks | Does each publicly catalogued way around a second factor fail here? | `crates/server/tests/known.rs` | `cargo test -p twof-server --test known` |
| Thread storm | Do the rules hold when twelve threads ask, approve, refuse, read and spend at once? | `crates/server/tests/storm.rs` | same; long run with `-- --ignored` |
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

## The catalogue of known attacks

`known.rs` goes through the public lists of how second factors get bypassed:
the OWASP Transaction Authorization Cheat Sheet (TA), the multi-factor chapter
of the OWASP Web Security Testing Guide, and the HackTricks collection of 2FA
bypasses (HT).

| Known attack | Source | Test |
|---|---|---|
| Calling the next step directly, skipping the approval | HT direct endpoint access, TA 2.5, TA 2.8 | `skipping_the_approval_step_gets_nothing` |
| Extra parameters, headers or flags that switch the check off or pick a weaker method | TA 2.1, TA 2.2, HT client-side flag | `extra_parameters_and_headers_do_not_switch_the_check_off` |
| Guessing, forcing errors, locking the real approver out | TA 2.1, TA 2.4, HT brute force | `guessing_and_errors_never_end_in_approval_nor_lock_the_approver_out` |
| Weak public keys and malleable signatures | known Ed25519 pitfalls | `a_weak_public_key_approves_nothing` and the test above |
| Racing one code or one vote from many connections | HT race condition, TA 1.5 | `many_hands_at_once_get_one_use_and_one_vote` |
| The right answer still accepted while rate limited; forged client address | HT rate limit, HT IP impersonation | `a_blocked_client_is_blocked_for_the_right_answer_too` |
| Older API versions, hidden admin routes, changing the request or the approver's device through the API | HT older versions, TA 1.2, TA 1.3, TA 2.6 | `there_is_no_other_door` |
| Another site driving or reading the approval | HT CSRF, clickjacking, CORS | `another_site_cannot_drive_or_read_the_approval` |
| Editing the answer, reusing it, "alg none", a foreign signing key | HT response manipulation, HT token reuse | `a_receipt_cannot_be_reshaped_and_is_spent_once` |
| An answer made for another request, another account, or after the decision | HT unused tokens, HT session manipulation, TA 2.5 | `an_answer_belongs_to_one_request_and_stays_what_it_was` |
| Secrets shown on the approval page, predictable identifiers | HT exposure of token, HT information disclosure | `nothing_secret_is_shown_and_nothing_is_guessable` |

Entries about SMS and e-mail codes, SIM swapping, password reset, backup
codes, sessions and "remember me" cookies do not apply: none of those exist in
2F. Two entries are outside what any test here can show. Whoever executes the
transaction must demand the receipt (TA 2.8 on the integrator's side), and an
approver who signs without reading can still be worn down by repeated
requests; the pending limit and the full action on screen reduce that, they do
not remove it.

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

## Leaving it running

`scripts/soak.sh` runs the random model, the random adversary, the thread
storm, the known attacks, the garbage test, the live server test and the cross
language check in an endless loop,
with new random seeds on every pass and several workers side by side. It
writes one line per run to `soak/summary.log` and keeps the full output of
anything that fails, together with its seed, in `soak/failures/`.

```bash
bash scripts/soak.sh soak 12      # 12 workers (default: all cores but four), until a file named soak/STOP exists
bash scripts/soak-report.sh soak  # totals so far
```

A failure can be replayed with the seed from its line:
`TWOF_SOAK_SEED=<seed> TWOF_SOAK_ROUNDS=<rounds> cargo test --release -p twof-server --test adversary -- --ignored`.

## What none of this covers

Passkeys on real phones and browsers, the Telegram delivery, the Docker image,
and anyone other than the author trying to break it.
