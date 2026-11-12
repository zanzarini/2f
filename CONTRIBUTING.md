# Contributing

## Before you send a change

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/e2e.sh
(cd sdk/ts && node --test)
(cd sdk/python && python -m unittest)
```

CI runs the same commands.

## Ground rules

- **A claim needs a test.** If a change adds a defence, add the test that
  attacks it. If it changes a row of `docs/THREAT_MODEL.md`, update the row.
- **Fail closed.** When something cannot be parsed, read or verified, the
  answer is no.
- **No new cryptography.** Ed25519, ECDSA P-256 and SHA-256, through audited
  crates. New signed structures get their own domain tag.
- **`crates/core` stays pure.** No network, no clock, no disk.
- **Wire format changes touch three places.** The Rust core, both SDKs, and
  `sdk/vectors.json` (regenerate with
  `TWOF_WRITE_VECTORS=1 cargo test -p twof-core --test vectors`).
- **`unsafe` is forbidden** in every crate.

## Layout

See the repository map in the [README](README.md#repository-map) and the
diagrams in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Reporting security problems

Not in a public issue, please. See [SECURITY.md](SECURITY.md).
