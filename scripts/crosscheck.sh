#!/usr/bin/env bash
# Generates a few thousand random values and actions with the Rust core and
# checks that the TypeScript and Python SDKs produce the same canonical text
# and the same hashes for every one of them.
set -euo pipefail
cd "$(dirname "$0")/.."

TWOF_WRITE_CORPUS=1 cargo test -q -p twof-core --test corpus >/dev/null
if command -v node >/dev/null; then node sdk/ts/crosscheck.mjs; else echo "node not found: TypeScript not checked"; fi
if python3 -c "import cryptography" 2>/dev/null; then
  (cd sdk/python && python3 crosscheck.py)
else
  echo "python cryptography package not found: Python not checked"
fi
