#!/usr/bin/env bash
# Summarises what scripts/soak.sh has collected so far.
#   bash scripts/soak-report.sh [output folder]
set -u
cd "$(dirname "$0")/.."
OUT="${1:-soak}"
LOG="$OUT/summary.log"
[ -f "$LOG" ] || { echo "no results in $OUT yet"; exit 1; }

echo "from $(head -1 "$LOG" | cut -d' ' -f1) to $(tail -1 "$LOG" | cut -d' ' -f1)"
grep -E "event=(start|stop|build_failed)" "$LOG" | tail -4
echo
echo "suite          runs   failed    operations   machine time"
awk '/ suite=/ {
       delete field
       for (i = 1; i <= NF; i++) { split($i, kv, "="); field[kv[1]] = kv[2] }
       s = field["suite"]
       runs[s]++; all_runs++
       if (field["result"] != "ok") { failed[s]++; all_failed++ }
       secs[s] += field["secs"]; all_secs += field["secs"]
       ops[s] += field["ops"]; all_ops += field["ops"]
     }
     END {
       for (s in runs) printf "%-12s %6d   %6d   %12d   %8.1f h\n", s, runs[s], failed[s] + 0, ops[s], secs[s] / 3600 | "sort"
       close("sort")
       printf "%-12s %6d   %6d   %12d   %8.1f h\n", "TOTAL", all_runs, all_failed + 0, all_ops, all_secs / 3600
     }' "$LOG"
echo
echo "what happened inside the random runs:"
# Add up the counters the long runs print (allowed_1_approved_2_... pairs).
awk '/ suite=(model|adversary) / {
       for (i = 1; i <= NF; i++) if ($i ~ /^counts=/) {
         n = split(substr($i, 8), part, "_")
         label = ""
         for (j = 1; j <= n; j++) {
           if (part[j] ~ /^[0-9]+$/) { total[label] += part[j]; label = "" }
           else label = (label == "" ? part[j] : label " " part[j])
         }
       }
     }
     END { for (l in total) printf "  %-28s %15d\n", l, total[l] }' "$LOG" | sort
echo
failures=$(ls "$OUT/failures" 2>/dev/null | wc -l)
echo "failure reports saved: $failures"
[ "$failures" -gt 0 ] && ls -1 "$OUT/failures" | tail -20
exit 0
