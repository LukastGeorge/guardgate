#!/usr/bin/env bash
# Test cho scripts/zap-gate.sh: cổng chặn DAST phải FAIL khi có alert High VÀ khi report thiếu/hỏng
# (scanner crash không được làm pipeline xanh — Review Focus #3).
set -uo pipefail
cd "$(dirname "$0")/../.."
DATA=scripts/testdata
failures=0

expect() {
  local name=$1 expected=$2 file=$3
  bash scripts/zap-gate.sh "$file" >/dev/null 2>&1
  local actual=$?
  if [[ $actual -eq $expected ]]; then
    echo "  ok  $name (exit $actual)"
  else
    echo "FAIL: $name — expected exit $expected, got $actual"
    failures=$((failures + 1))
  fi
}

expect "report without High alerts passes"     0 "$DATA/zap-clean.json"
expect "report with a High alert fails"        1 "$DATA/zap-high.json"
expect "empty report fails"                    1 "$DATA/zap-empty.json"
expect "missing report fails"                  1 "$DATA/does-not-exist.json"
expect "report without any site fails"         1 "$DATA/zap-nosite.json"

[[ $failures -eq 0 ]] && echo "zap-gate tests passed" || { echo "$failures zap-gate test(s) failed"; exit 1; }
