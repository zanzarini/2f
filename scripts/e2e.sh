#!/usr/bin/env bash
# End to end check against a real server process: CLI setup, HTTP API,
# approval with a device key, single use receipts, audit verification.
# Usage: scripts/e2e.sh [path to twof binary]
set -euo pipefail

BIN="${1:-${CARGO_TARGET_DIR:-target}/debug/twof}"
PORT="${TWOF_E2E_PORT:-18722}"
URL="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
export TWOF_DB="$WORK/twof.db" TWOF_KEY_FILE="$WORK/twof.key"
SERVER_PID=""
COSIGN_PID=""
trap 'kill $SERVER_PID $COSIGN_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

field() { python3 -c "import json,sys; v=json.load(sys.stdin)$1; print(v if v is not None else '')"; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
expect() { if [ "$2" != "$3" ]; then echo "FAIL $1: expected $2, got $3"; exit 1; fi; echo "ok   $1"; }

"$BIN" init >/dev/null
PROJECT="$("$BIN" project create exchange)"
cat > "$WORK/policy.json" <<'JSON'
{ "version": 1,
  "lists": { "treasury": ["0xaaa"] },
  "rules": [
    { "name": "payouts need the vault",
      "when": { "type": ["payout"] },
      "then": { "decision": "require", "requirements": [ { "count": 1, "kinds": ["cosigner"] } ] } },
    { "name": "small to treasury",
      "when": { "type": ["withdraw"], "asset": ["USDT"], "amount_max": "100", "destination_in": ["treasury"] },
      "then": { "decision": "allow" } },
    { "name": "withdraw needs one person",
      "when": { "type": ["withdraw"] },
      "then": { "decision": "require", "requirements": [ { "count": 1 } ] } } ] }
JSON
"$BIN" policy set "$PROJECT" "$WORK/policy.json" >/dev/null
KEY="$("$BIN" apikey create "$PROJECT" 2>/dev/null)"
PUB="$("$BIN" device keygen "$WORK/alice.key")"
"$BIN" approver add "$PROJECT" alice >/dev/null
CRED="$("$BIN" credential add "$PROJECT" alice "$PUB")"

"$BIN" serve --listen "127.0.0.1:$PORT" --public-url "$URL" >/dev/null &
SERVER_PID=$!
for _ in $(seq 50); do curl -sf "$URL/healthz" >/dev/null && break; sleep 0.1; done

AUTH=(-H "Authorization: Bearer $KEY")
create() { curl -s "${AUTH[@]}" -d "$1" "$URL/v1/challenges"; }

expect "no API key is refused" 401 "$(status -d '{}' "$URL/v1/challenges")"
expect "wrong API key is refused" 401 "$(status -H 'Authorization: Bearer 2f_wrong' -d '{}' "$URL/v1/challenges")"
expect "duplicate JSON keys are refused" 400 "$(status "${AUTH[@]}" -d '{"idempotency_key":"d","action":{"type":"withdraw","destination":"0xaaa","destination":"0xevil"}}' "$URL/v1/challenges")"
expect "numeric amounts are refused" 400 "$(status "${AUTH[@]}" -d '{"idempotency_key":"n","action":{"type":"withdraw","amount":50.5}}' "$URL/v1/challenges")"
expect "unknown challenge is not found" 404 "$(status "$URL/v1/approvals/ch_nope")"

SMALL="$(create '{"idempotency_key":"a1","action":{"type":"withdraw","amount":"50","asset":"USDT","destination":"0xaaa"}}')"
expect "small known transfer is allowed" allowed "$(echo "$SMALL" | field "['state']")"
RECEIPT="$(echo "$SMALL" | field "['receipt']")"
expect "receipt is consumed once" 200 "$(status "${AUTH[@]}" -d "{\"receipt\":\"$RECEIPT\"}" "$URL/v1/receipts/consume")"
expect "receipt cannot be reused" 409 "$(status "${AUTH[@]}" -d "{\"receipt\":\"$RECEIPT\"}" "$URL/v1/receipts/consume")"

BIG="$(create '{"idempotency_key":"a2","action":{"type":"withdraw","amount":"5000","asset":"USDT","destination":"0xnew"}}')"
expect "unknown destination waits for a person" pending "$(echo "$BIG" | field "['state']")"
ID="$(echo "$BIG" | field "['id']")"
VIEW="$(curl -s "$URL/v1/approvals/$ID")"
expect "approver sees the real amount" 5000 "$(echo "$VIEW" | field "['action']['amount']")"
HASH="$(echo "$VIEW" | field "['binding_hash']")"

"$BIN" device keygen "$WORK/mallory.key" >/dev/null
BAD_SIG="$("$BIN" device sign "$WORK/mallory.key" "$HASH")"
expect "signature from an unknown key is refused" 403 "$(status -d "{\"credential\":\"$CRED\",\"signature\":\"$BAD_SIG\"}" "$URL/v1/challenges/$ID/approvals")"

SIG="$("$BIN" device sign "$WORK/alice.key" "$HASH")"
DONE="$(curl -s -d "{\"credential\":\"$CRED\",\"signature\":\"$SIG\"}" "$URL/v1/challenges/$ID/approvals")"
expect "alice's signature approves" approved "$(echo "$DONE" | field "['state']")"
expect "approver response carries no receipt" "" "$(echo "$DONE" | field ".get('receipt')")"
FINAL="$(curl -s "${AUTH[@]}" "$URL/v1/challenges/$ID?wait=5")"
expect "client sees it approved" approved "$(echo "$FINAL" | field "['state']")"
RECEIPT2="$(echo "$FINAL" | field "['receipt']")"
expect "approved receipt is consumed" 200 "$(status "${AUTH[@]}" -d "{\"receipt\":\"$RECEIPT2\"}" "$URL/v1/receipts/consume")"
expect "second approval is a conflict" 409 "$(status -d "{\"credential\":\"$CRED\",\"signature\":\"$SIG\"}" "$URL/v1/challenges/$ID/approvals")"
expect "response is not cacheable" 1 "$(curl -sI "$URL/v1/keys" | grep -ci 'cache-control: no-store')"

# A terminal approver that computes the hash itself from the action it shows.
TERM_ID="$(create '{"idempotency_key":"t1","action":{"type":"withdraw","amount":"321","asset":"USDT","destination":"0xterm"}}' | field "['id']")"
SHOWN="$("$BIN" device approve "$WORK/alice.key" "$CRED" "$TERM_ID" --server-url "$URL" --yes)"
expect "terminal approver shows the real amount" 1 "$(echo "$SHOWN" | grep -c 'amount:      321 USDT')"
expect "terminal approver approves" 1 "$(echo "$SHOWN" | grep -c 'challenge is now approved')"
REF_ID="$(create '{"idempotency_key":"t2","action":{"type":"withdraw","amount":"322","asset":"USDT","destination":"0xterm"}}' | field "['id']")"
expect "terminal approver can refuse" 1 "$("$BIN" device approve "$WORK/alice.key" "$CRED" "$REF_ID" --server-url "$URL" --reject --yes | grep -c 'challenge is now rejected')"
expect "terminal approver needs a confirmation" 0 "$(echo no | "$BIN" device approve "$WORK/alice.key" "$CRED" "$TERM_ID" --server-url "$URL" 2>/dev/null | grep -c 'challenge is now')"

# The Python client against the live server, if its dependency is installed.
if python3 -c "import cryptography" 2>/dev/null; then
  KID="$("$BIN" pubkey | awk '/kid/ { print $2 }')"
  PUBKEY="$("$BIN" pubkey | awk '/public key/ { print $3 }')"
  SDK_OUT="$(PYTHONPATH="$(dirname "$0")/../sdk/python" python3 - "$URL" "$KEY" "$KID" "$PUBKEY" <<'PY'
import sys, twof
url, key, kid, pub = sys.argv[1:]
client = twof.TwoF(url, key, {kid: pub})
action = {"type": "withdraw", "amount": "7", "asset": "USDT", "destination": "0xaaa"}
result = client.authorize(action, "sdk-1")
client.consume(result.receipt)
try:
    client.consume(result.receipt)
    print("reused")
except twof.TwoFError as error:
    print(result.authorized, result.payload["decision"], error.code)
PY
)"
  expect "python client authorizes, verifies and consumes once" "True allow conflict" "$SDK_OUT"
fi

# Independent co-signer: its own key, its own policy, reached by signed webhook.
VAULT_PUB="$("$BIN" device keygen "$WORK/vault.key")"
"$BIN" approver add "$PROJECT" vault >/dev/null
VAULT_CRED="$("$BIN" credential add "$PROJECT" vault "$VAULT_PUB" --cosigner)"
cat > "$WORK/vault-policy.json" <<'JSON'
{ "version": 1, "rules": [
  { "name": "small payouts", "when": { "type": ["payout"], "asset": ["USDT"], "amount_max": "100", "velocity": { "window_secs": 3600, "max_total": "120" } }, "then": { "decision": "allow" } } ] }
JSON
SERVER_PUB="$("$BIN" pubkey | awk '/public key/ { print $3 }')"
VAULT_PORT=$((PORT + 1))
"$BIN" cosign --device-key "$WORK/vault.key" --credential "$VAULT_CRED" --policy "$WORK/vault-policy.json" \
  --server-url "$URL" --server-public-key "$SERVER_PUB" --listen "127.0.0.1:$VAULT_PORT" >/dev/null &
COSIGN_PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$VAULT_PORT/" && break; sleep 0.1; done
"$BIN" webhook "$PROJECT" "http://127.0.0.1:$VAULT_PORT/webhook" >/dev/null
expect "unsigned webhook is refused by the co-signer" 401 "$(status -d '{}' "http://127.0.0.1:$VAULT_PORT/webhook")"
expect "forged webhook is refused by the co-signer" 403 "$(status -H 'x-2f-signature: AAAA' -d '{}' "http://127.0.0.1:$VAULT_PORT/webhook")"

PAY="$(create '{"idempotency_key":"p1","action":{"type":"payout","amount":"50","asset":"USDT","destination":"0xcustomer"}}')"
expect "payout waits for the co-signer" pending "$(echo "$PAY" | field "['state']")"
PAY_ID="$(echo "$PAY" | field "['id']")"
expect "co-signer approves within its policy" approved "$(curl -s "${AUTH[@]}" "$URL/v1/challenges/$PAY_ID?wait=15" | field "['state']")"
BIGPAY_ID="$(create '{"idempotency_key":"p2","action":{"type":"payout","amount":"500","asset":"USDT","destination":"0xcustomer"}}' | field "['id']")"
SECOND_ID="$(create '{"idempotency_key":"p3","action":{"type":"payout","amount":"80","asset":"USDT","destination":"0xcustomer"}}' | field "['id']")"
expect "co-signer keeps its own running total" rejected "$(curl -s "${AUTH[@]}" "$URL/v1/challenges/$SECOND_ID?wait=15" | field "['state']")"
expect "co-signer vetoes outside its policy" rejected "$(curl -s "${AUTH[@]}" "$URL/v1/challenges/$BIGPAY_ID?wait=15" | field "['state']")"

kill "$SERVER_PID" "$COSIGN_PID"; wait "$SERVER_PID" "$COSIGN_PID" 2>/dev/null || true; SERVER_PID=""; COSIGN_PID=""
"$BIN" audit verify | grep -q "audit log intact" && echo "ok   audit log verifies"
"$BIN" audit checkpoint >/dev/null
python3 - "$TWOF_DB" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute("UPDATE audit SET data = replace(data, '5000', '5') WHERE data LIKE '%5000%'")
db.commit()
PY
if "$BIN" audit verify >/dev/null 2>&1; then echo "FAIL edited audit log went unnoticed"; exit 1; fi
echo "ok   edited audit log is detected"
echo "ALL PASSED"
