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

# ---- GĐ5: chart Helm + staging trên k3d ----
helm_job=$(job helm)
image_job=$(job image)
check "helm job runs the chart policy test" 'grep -q "scripts/tests/helm-policy.test.sh" <<<"$helm_job"'
check "helm job proves the policy test rejects bad values" 'grep -q "helm-bad-values.yaml" <<<"$helm_job"'
check "helm job runs a blocking trivy config scan" 'grep -q "config" <<<"$helm_job" && grep -qE -- "--exit-code 1" <<<"$helm_job"'
check "helm binary is verified against a pinned SHA256" 'grep -qE "[0-9a-f]{64}  +[^ ]*helm" <<<"$helm_job" && grep -q "sha256sum -c" <<<"$helm_job"'
check "image builds wait for the helm gate" 'grep -E "needs: \[.*\bhelm\b.*\]" <<<"$image_job" >/dev/null'

# Staging = k3d + Helm (không còn docker compose), k3d binary có checksum pin
check "staging deploys with scripts/k8s/up.sh" 'grep -q "scripts/k8s/up.sh" <<<"$staging"'
check "staging no longer uses docker compose" '! grep -qE "docker compose .* up" <<<"$staging"'
check "k3d binary is verified against a pinned SHA256" 'grep -qE "[0-9a-f]{64}  *\.tools/k3d" <<<"$staging" && grep -q "sha256sum -c" <<<"$staging"'

# GĐ4 minor #5 (TOCTOU): deploy ĐÚNG digest mà cosign đã verify, không deploy lại theo tag
verify_line=$(line_of "$staging" 'cosign verify')
deploy_line=$(line_of "$staging" 'scripts/k8s/up.sh')
check "cosign verify runs before deploy" '[[ -n "$verify_line" && -n "$deploy_line" && $verify_line -lt $deploy_line ]]'
check "verified digest is taken from cosign output" 'grep -q "docker-manifest-digest" <<<"$staging"'
check "deploy pins every app by the verified digest" 'grep -q "GG_IMAGE_DIGESTS" <<<"$staging"'
check "staging runs the runtime network policy test" 'grep -q "scripts/tests/k8s-netpol.test.sh" <<<"$staging"'
check "staging tears the cluster down" 'grep -q "scripts/k8s/down.sh" <<<"$staging"'

[[ $failures -eq 0 ]] && echo "workflow policy tests passed" || { echo "$failures policy violation(s)"; exit 1; }
