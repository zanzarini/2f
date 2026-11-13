# Contributing

## Before submitting a change

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/e2e.sh
(cd sdk/ts && node --test)
(cd sdk/python && python -m unittest)
```

CI runs the same commands.

## Guidelines

- **A claim needs a test.** If a change adds a defence, add the test that
  attacks it. If it changes a row of `docs/THREAT_MODEL.md`, update the row.
- **The model test must agree.** `crates/server/tests/model.rs` runs random
  operations against an independent model of the rules. A change in behaviour
  means changing the model on purpose, in the same commit.
- **Fail closed.** Input that cannot be parsed, read or verified is refused.
- **No new cryptography.** Ed25519, ECDSA P-256 and SHA-256, through audited
  crates. New signed structures get their own domain tag.
- **`crates/core` stays pure.** No network, no clock, no disk.
- **Wire format changes touch three places.** The Rust core, both SDKs, and
  `sdk/vectors.json` (regenerate with
  `TWOF_WRITE_VECTORS=1 cargo test -p twof-core --test vectors`).
- **`unsafe` is forbidden** in every crate.

## Layout

See the repository map in the [README](README.md#repository-layout) and the
diagrams in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Reporting security problems

Do not use public issues. See [SECURITY.md](SECURITY.md).
