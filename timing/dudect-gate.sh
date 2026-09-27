#!/usr/bin/env bash
# Evaluate dudect-bencher output: dudect-gate.sh <output-file> <bench-name>...
#
# Fails when a listed bench has no result, the run did not complete, or
# |max t| exceeds FAIL_T. FAIL_T is dudect's own "test failed" level
# (t_threshold_moderate in dudect.h); the classic 4.5 level is only a warning
# because max t is the maximum over 101 cropped t-tests on a shared, noisy
# runner, which occasionally exceeds 4.5 for constant-time code.
set -euo pipefail
# awk's decimal parsing follows LC_NUMERIC; LC_ALL is set because an inherited
# LC_ALL would override LC_NUMERIC=C.
export LC_ALL=C

WARN_T=4.5
FAIL_T=10

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <dudect-output-file> <bench-name>..." >&2
  exit 2
fi

log=$1
shift

status=0

if ! grep -q '^dudect benches complete' "$log"; then
  echo "::error::dudect run did not complete"
  status=1
fi

for bench in "$@"; do
  line=$(grep -E "^bench ${bench} +\.\.\. : n == " "$log" | tail -n 1 || true)
  if [ -z "$line" ]; then
    echo "::error::dudect: no result for ${bench}"
    status=1
    continue
  fi

  n=$(sed -E 's/.* n == \+?([0-9]+\.[0-9]+)M,.*/\1/' <<<"$line")
  t=$(sed -E 's/.* max t = ([+-]?[0-9]+\.[0-9]+),.*/\1/' <<<"$line")
  if ! [[ "$t" =~ ^[+-]?[0-9]+\.[0-9]+$ && "$n" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "::error::dudect: cannot parse result for ${bench}: ${line}"
    status=1
    continue
  fi

  verdict=$(awk -v t="$t" -v w="$WARN_T" -v f="$FAIL_T" 'BEGIN {
    a = (t < 0) ? -t : t
    if (a > f) print "fail"; else if (a > w) print "warn"; else print "pass"
  }')

  case "$verdict" in
    pass)
      echo "::notice::${bench}: max t = ${t} (t-test n = ${n}M), |t| <= ${WARN_T}"
      ;;
    warn)
      echo "::warning::${bench}: max t = ${t} (t-test n = ${n}M), above ${WARN_T} but within ${FAIL_T}"
      ;;
    *)
      echo "::error::${bench}: timing leak, max t = ${t} (t-test n = ${n}M), |t| > ${FAIL_T}"
      status=1
      ;;
  esac
done

exit "$status"
