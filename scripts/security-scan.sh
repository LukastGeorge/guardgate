#!/usr/bin/env bash
# Chạy bộ quét bảo mật GIỐNG HỆT CI trên máy dev, trước khi push.
# Dùng: bash scripts/security-scan.sh [THƯ_MỤC]     (mặc định: thư mục hiện tại)
# Exit khác 0 nếu bất kỳ công cụ nào tìm thấy vấn đề HOẶC tự crash (không có "|| true").
# Yêu cầu: Docker. Version image được pin để kết quả lặp lại được.
set -uo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash trên Windows

SEMGREP_IMAGE=semgrep/semgrep:1.140.0@sha256:4372a1de903521f9f10f877b6caf15d150d17e1ca592582682c8d02b77cbd4f6
GITLEAKS_IMAGE=zricethezav/gitleaks:v8.28.0@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854
TRIVY_IMAGE=aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb  # đã verify chữ ký cosign; xem ghi chú sự cố Trivy 2026 trong README

TARGET=$(cd "${1:-.}" && { pwd -W 2>/dev/null || pwd; })
status=0

run() {
  local name=$1
  shift
  echo "==> $name"
  "$@"
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "    ok: $name"
  else
    echo "FAIL: $name (exit $rc)"
    status=1
  fi
}

# SAST: chỉ chặn finding mức ERROR (các mức thấp hơn vẫn được in ra để xem)
run "semgrep (SAST)" docker run --rm -v "$TARGET:/src:ro" "$SEMGREP_IMAGE" \
  semgrep scan --config p/java --config p/owasp-top-ten --config p/secrets \
  --metrics=off --error --severity ERROR --quiet /src

# Secret trong TOÀN BỘ lịch sử git (không chỉ file hiện tại); wrapper chặn "xanh giả" khi quét 0 commit
run "gitleaks (secrets in git history)" env GITLEAKS_IMAGE="$GITLEAKS_IMAGE" \
  bash "$(dirname "$0")/run-gitleaks.sh" "$TARGET"

# Secret trong file, cấu hình Dockerfile/compose sai, dependency khai báo trực tiếp.
# --offline-scan: không tải pom cha từ Maven Central (từng bị 429 rate limit). Cổng chặn dependency CHÍNH XÁC
# là quét IMAGE (jar thật) trong CI: quét pom bỏ sót CVE của dependency bắc cầu do BOM quản lý.
run "trivy (dependencies, secrets, misconfig)" docker run --rm -v "$TARGET:/src:ro" \
  -v guardgate-trivy-cache:/root/.cache "$TRIVY_IMAGE" \
  fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 \
  --ignorefile /src/.trivyignore.yaml --skip-files .env --skip-dirs .superpowers --offline-scan --quiet /src

# Điều kiện của các CVE đang được chấp nhận rủi ro (.trivyignore.yaml) phải còn đúng
run "risk acceptance preconditions" bash "$(dirname "$0")/check-risk-acceptance.sh" "${1:-.}"

if [[ $status -eq 0 ]]; then
  echo "SECURITY SCAN PASSED"
else
  echo "SECURITY SCAN FAILED"
fi
exit $status
