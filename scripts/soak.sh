#!/usr/bin/env bash
# Endless test run. Every pass uses new random seeds, so it keeps exploring
# instead of repeating itself. Results go to a folder; nothing needs watching.
#
#   bash scripts/soak.sh [output folder] [workers]
#
# Stop it by creating a file named STOP in the output folder; each worker
# finishes the suite it is on and exits. Read the results with
# scripts/soak-report.sh.
set -u
cd "$(dirname "$0")/.."
OUT="${1:-soak}"
WORKERS="${2:-$(( $(nproc) > 4 ? $(nproc) - 4 : 1 ))}"
MODEL_ROUNDS="${SOAK_MODEL_ROUNDS:-300}"
ADVERSARY_ROUNDS="${SOAK_ADVERSARY_ROUNDS:-600}"
STORM_ROUNDS="${SOAK_STORM_ROUNDS:-40}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
mkdir -p "$OUT/failures"
rm -f "$OUT/STOP"

log() { echo "$(date -u +%FT%TZ) $*" >> "$OUT/summary.log"; }

# Build everything once, so the workers only run.
if ! cargo test --release --workspace --no-run > "$OUT/build.log" 2>&1 \
  || ! cargo build --release -p twof-cli >> "$OUT/build.log" 2>&1; then
  log "event=build_failed"
  exit 1
fi

# The test programs are run directly: several copies of cargo would wait on
# each other for the build folder.
PROGRAMS=$(cargo test --release --workspace --no-run --message-format=json 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if message.get("executable") and message.get("profile", {}).get("test"):
        print(message["target"]["name"], message["executable"])
')
program() { echo "$PROGRAMS" | awk -v name="$1" '$1 == name { print $2 }' | tail -1; }
MODEL=$(program model)
ADVERSARY=$(program adversary)
STORM=$(program storm)
HTTP=$(program http)
LIVE=$(program live)
TAMPER=$(program tamper)
KNOWN=$(program known)
CORPUS=$(program corpus)
for found in "$MODEL" "$ADVERSARY" "$STORM" "$HTTP" "$LIVE" "$TAMPER" "$KNOWN" "$CORPUS"; do
  [ -x "$found" ] || { log "event=build_failed reason=missing_test_program"; exit 1; }
done
log "event=start commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) workers=$WORKERS cores=$(nproc) model_rounds=$MODEL_ROUNDS adversary_rounds=$ADVERSARY_ROUNDS storm_rounds=$STORM_ROUNDS"

# run <worker> <pass> <seed> <suite> <operations> <command...>
# <operations> is how many individual operations the suite performs.
run() {
  local worker=$1 pass=$2 seed=$3 suite=$4 operations=$5
  shift 5
  local output="$OUT/last-$suite-w$worker.log" started result detail
  started=$(date +%s)
  if "$@" > "$output" 2>&1; then
    result=ok
  else
    result=FAIL
    cp "$output" "$OUT/failures/$(date -u +%Y%m%dT%H%M%SZ)-$suite-w$worker-seed$seed.log"
  fi
  # The long runs print one line of counters; keep it with the result.
  detail=$(grep -E "^(allowed|receipts|storm) " "$output" | tail -1 | tr ' ' '_')
  log "worker=$worker pass=$pass seed=$seed suite=$suite result=$result secs=$(( $(date +%s) - started )) ops=$operations counts=${detail:--}"
}

worker() {
  local worker=$1 pass=0 seed
  while [ ! -e "$OUT/STOP" ]; do
    pass=$((pass + 1))
    seed=$(od -An -N7 -tu8 /dev/urandom | tr -d ' ')
    export TWOF_SOAK_SEED=$seed
    TWOF_SOAK_ROUNDS=$MODEL_ROUNDS run "$worker" "$pass" "$seed" model $((MODEL_ROUNDS * 1500)) \
      "$MODEL" --ignored --nocapture
    [ -e "$OUT/STOP" ] && break
    TWOF_SOAK_ROUNDS=$ADVERSARY_ROUNDS run "$worker" "$pass" "$seed" adversary $((ADVERSARY_ROUNDS * 90)) \
      "$ADVERSARY" --ignored --nocapture
    [ -e "$OUT/STOP" ] && break
    # Many threads on one server: where timing bugs live.
    TWOF_SOAK_ROUNDS=$STORM_ROUNDS run "$worker" "$pass" "$seed" storm $((STORM_ROUNDS * 12 * 400)) \
      "$STORM" --ignored --nocapture
    run "$worker" "$pass" "$seed" race 9000 "$TAMPER" readers_racing concurrent_writers
    # The publicly known ways around a second factor, with new guesses and
    # new forged receipts on every pass.
    run "$worker" "$pass" "$seed" known 4000 "$KNOWN"
    run "$worker" "$pass" "$seed" garbage 1500 "$HTTP" random_garbage
    run "$worker" "$pass" "$seed" live 130 "$LIVE"
    # The suites below use fixed ports or shared files: one worker only.
    if [ "$worker" -eq 1 ]; then
      TWOF_WRITE_CORPUS=1 run "$worker" "$pass" "$seed" languages 4500 \
        bash -c "'$CORPUS' && cd sdk/python && python3 crosscheck.py"
      if [ $((pass % 5)) -eq 0 ]; then
        ( unset TWOF_SOAK_SEED; run "$worker" "$pass" "$seed" everything 0 cargo test --release -q --workspace )
        run "$worker" "$pass" "$seed" endtoend 30 bash scripts/e2e.sh "$CARGO_TARGET_DIR/release/twof"
      fi
      # Databases left behind by a test that died.
      find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'twof-*' -mmin +60 -delete 2>/dev/null
    fi
  done
  log "worker=$worker event=stopped passes=$pass"
}

for id in $(seq "$WORKERS"); do
  worker "$id" &
done
wait
log "event=stop"
