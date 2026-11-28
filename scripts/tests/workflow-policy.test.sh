#!/usr/bin/env bash
# Kiểm tra các bất biến bảo mật của .github/workflows/ci.yml mà không cần chạy pipeline
# (job publish/staging chỉ chạy trên main nên không thể "chạy thử" trên nhánh tính năng).
# Final review GĐ4: findings #1, #3, #4, #7.
set -uo pipefail
cd "$(dirname "$0")/../.."
WF=.github/workflows/ci.yml
failures=0
check() { if eval "$2"; then echo "  ok  $1"; else echo "FAIL: $1"; failures=$((failures + 1)); fi; }

# Nội dung của một job: từ dòng "  <job>:" tới job kế tiếp
job() { awk -v j="  $1:" '$0 == j {on=1; print; next} on && /^  [a-z][a-z-]*:$/ {exit} on {print}' "$WF"; }
line_of() { grep -nF -- "$2" <<<"$1" | head -1 | cut -d: -f1; }

publish=$(job publish)
staging=$(job staging-dast)
trivyfs=$(job trivy-fs)

# #1: image được ký/deploy phải là image đã qua cổng Trivy (exit-code 1) — quét TRƯỚC khi ký
scan_line=$(grep -nE 'exit-code: "1"' <<<"$publish" | head -1 | cut -d: -f1)
sign_line=$(line_of "$publish" 'cosign sign')
check "publish scans the pushed image with a blocking Trivy gate" '[[ -n "$scan_line" ]]'
check "publish scans BEFORE signing" '[[ -n "$scan_line" && -n "$sign_line" && $scan_line -lt $sign_line ]]'
check "publish scan uses the risk-acceptance ignore file" 'grep -q "trivyignores: .trivyignore.yaml" <<<"$publish"'

# #1/#7: :latest chỉ được gắn SAU khi ký + attest thành công (không bao giờ trỏ vào image chưa ký)
latest_line=$(line_of "$publish" '"${IMAGE}:latest"')   # lệnh gắn tag thật, không phải comment
attest_line=$(line_of "$publish" 'cosign attest')
check ":latest is not pushed by the initial build" '! grep -A30 "Build and push" <<<"$publish" | grep -q "IMAGE }}:latest"'
check ":latest is tagged after cosign attest" '[[ -n "$latest_line" && -n "$attest_line" && $latest_line -gt $attest_line ]]'

# #7: run trên main không bị một push sau huỷ giữa chừng lúc đang publish
check "cancel-in-progress excludes main" 'grep -qE "cancel-in-progress: .*refs/heads/main" "$WF"'

# #3: SARIF mode của trivy-action bỏ severity filter nếu không bật limit-severities-for-sarif
check "trivy-fs keeps the HIGH/CRITICAL threshold in SARIF mode" 'grep -q "limit-severities-for-sarif: true" <<<"$trivyfs"'

# #4: kiểm tra cổng không được "pass" khi công cụ kiểm tra không tồn tại
check "port exposure check does not depend on nc" '! grep -q "nc -z" <<<"$staging"'
check "port exposure check uses bash /dev/tcp" 'grep -q "/dev/tcp/127.0.0.1" <<<"$staging"'

[[ $failures -eq 0 ]] && echo "workflow policy tests passed" || { echo "$failures policy violation(s)"; exit 1; }
