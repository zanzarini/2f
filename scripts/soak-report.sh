#!/usr/bin/env bash
# Summarises what scripts/soak.sh has collected so far.
#   bash scripts/soak-report.sh [output folder]
set -u
cd "$(dirname "$0")/.."
OUT="${1:-soak}"
LOG="$OUT/summary.log"
[ -f "$LOG" ] || { echo "no results in $OUT yet"; exit 1; }

first=$(head -1 "$LOG" | cut -d' ' -f1)
last=$(tail -1 "$LOG" | cut -d' ' -f1)
echo "from $first to $last"
grep -E "event=(start|stop|build_failed)" "$LOG" | tail -3
echo
echo "suite        runs   failed   time spent"
awk '/ suite=/ {
       for (i = 1; i <= NF; i++) { split($i, kv, "="); field[kv[1]] = kv[2] }
       runs[field["suite"]]++
       if (field["result"] != "ok") failed[field["suite"]]++
       secs[field["suite"]] += field["secs"]
     }
     END {
       for (s in runs) printf "%-12s %5d   %6d   %5.1f h\n", s, runs[s], failed[s] + 0, secs[s] / 3600
     }' "$LOG" | sort
echo
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
     END { for (l in total) printf "%-28s %15d\n", l, total[l] }' "$LOG" | sort
echo
failures=$(ls "$OUT/failures" 2>/dev/null | wc -l)
echo "failure reports saved: $failures"
[ "$failures" -gt 0 ] && ls -1 "$OUT/failures" | tail -20
exit 0
