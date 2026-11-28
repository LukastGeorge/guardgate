#!/usr/bin/env bash
# Kiểm tra ĐIỀU KIỆN của các mục chấp nhận rủi ro trong .trivyignore.yaml vẫn còn đúng.
# Nếu code bắt đầu dùng tính năng bị ảnh hưởng bởi CVE đang được bỏ qua, lý do bỏ qua không còn hợp lệ → FAIL.
# Dùng: bash scripts/check-risk-acceptance.sh [THƯ_MỤC]
set -euo pipefail

ROOT=${1:-.}
status=0

forbid() {
  local cve=$1 pattern=$2
  local hits
  hits=$(grep -rnE --include='*.java' --include='*.yml' --include='*.yaml' --include='*.properties' \
           "$pattern" "$ROOT"/*/src/main 2>/dev/null || true)
  if [[ -n "$hits" ]]; then
    echo "FAIL: $cve is risk-accepted on the assumption that '$pattern' is not used, but found:"
    echo "$hits"
    status=1
  else
    echo "  ok  $cve: no usage of /$pattern/"
  fi
}

forbid CVE-2026-47884 'XsltView|XsltViewResolver'
forbid CVE-2026-47890 'SseEmitter|ServerSentEvent|TEXT_EVENT_STREAM|text/event-stream|FragmentsRendering'
forbid CVE-2026-47892 'RouterFunction|RouterFunctions|coRouter'

exit $status
