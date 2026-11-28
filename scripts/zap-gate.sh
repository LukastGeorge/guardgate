#!/usr/bin/env bash
# Cổng chặn DAST: đọc report JSON của OWASP ZAP và FAIL nếu có alert mức High (riskcode 3).
# Dùng: bash scripts/zap-gate.sh zap-report.json
#
# Không tin vào exit code của zap-baseline.py: report thiếu, rỗng, sai định dạng hoặc không có site nào
# (ZAP không truy cập được mục tiêu) đều là FAIL — một lần quét không chạy không được tính là "sạch".
set -euo pipefail

REPORT=${1:?usage: zap-gate.sh <zap-report.json>}
fail() { echo "FAIL: $*"; exit 1; }

[[ -s "$REPORT" ]] || fail "ZAP report '$REPORT' is missing or empty"
jq -e . "$REPORT" >/dev/null 2>&1 || fail "ZAP report '$REPORT' is not valid JSON"
jq -e '(.site | type) == "array" and (.site | length) > 0' "$REPORT" >/dev/null 2>&1 \
  || fail "ZAP report contains no scanned site (target unreachable?)"

echo "ZAP alerts by risk:"
jq -r '.site[].alerts[]? | "  \(.riskdesc)\t\(.name)"' "$REPORT" | sort -u

high=$(jq '[.site[].alerts[]? | select(.riskcode == "3")] | length' "$REPORT")
if [[ "$high" -gt 0 ]]; then
  fail "$high High-risk ZAP alert(s)"
fi
echo "ZAP gate passed: no High-risk alerts"
