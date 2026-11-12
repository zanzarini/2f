#!/usr/bin/env bash
# Starts a throwaway 2F server with one project, and prints a passkey
# enrollment link and an approval link to open in a browser.
# Usage: scripts/demo.sh [path to twof binary]
set -euo pipefail

BIN="${1:-${CARGO_TARGET_DIR:-target}/debug/twof}"
PORT="${TWOF_DEMO_PORT:-8722}"
export TWOF_PUBLIC_URL="http://localhost:$PORT"
WORK="$(mktemp -d)"
export TWOF_DB="$WORK/twof.db" TWOF_KEY_FILE="$WORK/twof.key"
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

"$BIN" init >/dev/null
PROJECT="$("$BIN" project create "Demo Exchange")"
cat > "$WORK/policy.json" <<'JSON'
{ "version": 1, "rules": [
  { "name": "everything needs a passkey", "when": {},
    "then": { "decision": "require", "requirements": [ { "count": 1, "kinds": ["passkey"] } ] } } ] }
JSON
"$BIN" policy set "$PROJECT" "$WORK/policy.json" >/dev/null
KEY="$("$BIN" apikey create "$PROJECT" 2>/dev/null)"
"$BIN" approver add "$PROJECT" owner --name "Owner" >/dev/null
ENROLL="$("$BIN" credential invite "$PROJECT" owner)"

"$BIN" serve --listen "0.0.0.0:$PORT" --challenge-ttl 900 2>/dev/null &
SERVER_PID=$!
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 0.1; done

APPROVE="$(curl -s -H "Authorization: Bearer $KEY" \
  -d '{"idempotency_key":"demo-1","action":{"type":"withdraw","amount":"2500.00","asset":"USDT","destination":"TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE","meta":{"order":"A-1042","network":"TRON"}}}' \
  "http://127.0.0.1:$PORT/v1/challenges" | python3 -c "import json,sys; print(json.load(sys.stdin)['approve_url'])")"

echo "1. Register your device:  $ENROLL"
echo "2. Approve the withdraw:  $APPROVE"
echo "Server running on port $PORT. Ctrl+C to stop."
wait "$SERVER_PID"
