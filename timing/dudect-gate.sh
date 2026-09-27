#!/usr/bin/env bash
# Run a dudect-bencher binary and gate on its results:
#   dudect-gate.sh <bench-binary> <bench-name>...
#
# Every bench runs once. A bench whose |max t| exceeds FAIL_T is rerun on its
# own (--filter) and fails only if a majority of MAX_RUNS runs exceed FAIL_T.
# Why: fixed-vs-random on a shared runner once gave |t| = 16 for code that gave
# 2-5 on other runs and locally, while a leaky decaps gives |t| near 1000; a
# real leak reproduces on rerun, a transient disturbance of the runner rarely
# does. A first run within FAIL_T is accepted without reruns.
#
# FAIL_T is dudect's own "test failed" level (t_threshold_moderate in
# dudect.h); the classic 4.5 level is only a warning because max t is the
# maximum over 101 cropped t-tests on a shared, noisy runner.
#
# A run that exits non-zero, does not complete, or has no parsable result for
# a bench fails the gate.
set -euo pipefail
# awk's decimal parsing follows LC_NUMERIC; LC_ALL is set because an inherited
# LC_ALL would override LC_NUMERIC=C.
export LC_ALL=C

WARN_T=4.5
FAIL_T=10
MAX_RUNS=3

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <bench-binary> <bench-name>..." >&2
  exit 2
fi

bin=$1
shift

first=$(mktemp)
rerun=$(mktemp)
trap 'rm -f "$first" "$rerun"' EXIT

# run_bin <output-file> <arg>...: returns non-zero if the binary failed or did
# not complete.
run_bin() {
  local out=$1
  shift
  if ! "$bin" "$@" | tee "$out"; then
    echo "::error::dudect: '$bin${*:+ $*}' exited with an error"
    return 1
  fi
  if ! grep -q '^dudect benches complete' "$out"; then
    echo "::error::dudect: '$bin${*:+ $*}' did not complete"
    return 1
  fi
}

# parse_result <output-file> <bench>: sets T and N; returns non-zero if the
# result is absent or unparsable. Spacing and the sign of n are not fixed,
# since the format is dudect-bencher's and not ours.
parse_result() {
  local out=$1 bench=$2 line
  line=$(grep -E "^bench +${bench} +\.\.\. *: *n *==" "$out" | tail -n 1 || true)
  if [ -z "$line" ]; then
    echo "::error::dudect: no result for ${bench}"
    return 1
  fi
  N=$(sed -E 's/.*[[:space:]:]n[[:space:]]*==[[:space:]]*\+?([0-9]+(\.[0-9]+)?)M.*/\1/' <<<"$line")
  T=$(sed -E 's/.*max t[[:space:]]*=[[:space:]]*([+-]?[0-9]+(\.[0-9]+)?)[[:space:]]*,.*/\1/' <<<"$line")
  if ! [[ "$T" =~ ^[+-]?[0-9]+(\.[0-9]+)?$ && "$N" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "::error::dudect: cannot parse result for ${bench}: ${line}"
    return 1
  fi
}

abs_above() {
  awk -v t="$1" -v l="$2" 'BEGIN { a = (t < 0) ? -t : t; exit !(a > l) }'
}

status=0
if ! run_bin "$first"; then
  status=1
fi

need=$((MAX_RUNS / 2 + 1))
for bench in "$@"; do
  if ! parse_result "$first" "$bench"; then
    status=1
    continue
  fi
  if ! abs_above "$T" "$FAIL_T"; then
    if abs_above "$T" "$WARN_T"; then
      echo "::warning::${bench}: max t = ${T} (n = ${N}M), above ${WARN_T} but within ${FAIL_T}"
    else
      echo "::notice::${bench}: max t = ${T} (n = ${N}M), |t| <= ${WARN_T}"
    fi
    continue
  fi

  echo "::warning::${bench}: max t = ${T} (n = ${N}M) exceeds ${FAIL_T}; rerunning to confirm"
  ts=$T
  above=1
  runs=1
  broken=0
  while [ "$above" -lt "$need" ] && [ $((runs - above)) -lt "$need" ]; do
    runs=$((runs + 1))
    if ! run_bin "$rerun" --filter "$bench" || ! parse_result "$rerun" "$bench"; then
      broken=1
      break
    fi
    ts="$ts, $T"
    if abs_above "$T" "$FAIL_T"; then
      above=$((above + 1))
    fi
  done

  if [ "$broken" -eq 1 ]; then
    status=1
  elif [ "$above" -ge "$need" ]; then
    echo "::error::${bench}: timing leak, max t = ${ts}; |t| > ${FAIL_T} in ${above} of ${runs} runs"
    status=1
  else
    echo "::warning::${bench}: max t = ${ts}; |t| > ${FAIL_T} in ${above} of ${runs} runs, not confirmed"
  fi
done

exit "$status"
