#!/usr/bin/env bash
# Chạy Gitleaks trên TOÀN BỘ lịch sử git và KHÔNG cho phép "xanh giả".
# Dùng: bash scripts/run-gitleaks.sh [THƯ_MỤC_REPO]
#
# Gitleaks trả exit 0 cả khi git lỗi và nó quét được 0 commit (đã gặp thật: worktree/đường dẫn Windows,
# "dubious ownership" khi container chạy root). Wrapper này coi các trường hợp đó là FAIL.
# Exit: 0 sạch; 1 có leak; 2 quét không hoàn chỉnh.
set -uo pipefail
export MSYS_NO_PATHCONV=1

TARGET=$(cd "${1:-.}" && { pwd -W 2>/dev/null || pwd; })
IMAGE=${GITLEAKS_IMAGE:-zricethezav/gitleaks:v8.28.0}

output=$(docker run --rm -v "$TARGET:/repo:ro" \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
  "$IMAGE" git /repo --redact --no-banner --exit-code 1 2>&1)
rc=$?
printf '%s\n' "$output"

if [[ $rc -ne 0 ]]; then
  exit "$rc"   # leak tìm thấy (hoặc gitleaks tự crash)
fi
if grep -q 'ERR' <<<"$output"; then
  echo "FAIL: gitleaks reported an error, the scan is incomplete"
  exit 2
fi
commits=$(grep -oE '[0-9]+ commits? scanned' <<<"$output" | grep -oE '^[0-9]+' || true)
if [[ -z "$commits" || "$commits" -eq 0 ]]; then
  echo "FAIL: gitleaks scanned 0 commits (not a git repository, or git failed)"
  exit 2
fi
echo "gitleaks: $commits commits scanned, no leaks"
