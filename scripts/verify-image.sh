#!/usr/bin/env bash
# Kiểm tra một image GuardGate có đạt chuẩn bảo mật container không (CI dùng lại sau khi build).
# Dùng: bash scripts/verify-image.sh <image>
# Exit 0 khi đạt; in "FAIL: <lý do>" và exit 1 khi không đạt.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash trên Windows: không tự đổi "/app" thành đường dẫn Windows

IMAGE=${1:?usage: verify-image.sh <image>}
fail() { echo "FAIL: $*"; exit 1; }

docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "image '$IMAGE' not found"

# 1. Không chạy bằng root
user=$(docker image inspect -f '{{.Config.User}}' "$IMAGE")
[[ "$user" == "10001:10001" ]] || fail "image USER is '$user', expected 10001:10001"
uid=$(docker run --rm --entrypoint id "$IMAGE" -u)
[[ "$uid" == "10001" ]] || fail "container runs as uid $uid"

# 2. Có healthcheck để Docker/compose biết khi nào app sẵn sàng
[[ -n "$(docker image inspect -f '{{if .Config.Healthcheck}}yes{{end}}' "$IMAGE")" ]] \
  || fail "no HEALTHCHECK declared"

# 3. Không có secret, source hay công cụ build trong image
leaked=$(docker run --rm --entrypoint sh "$IMAGE" -c \
  'find /app \( -name ".env" -o -name ".env.*" -o -name "*.pem" -o -name "*.key" -o -name "*.p12" \
     -o -name "*.java" -o -name "pom.xml" -o -name "mvnw" \) 2>/dev/null | head -5')
[[ -z "$leaked" ]] || fail "forbidden files in /app: $leaked"
if docker run --rm --entrypoint sh "$IMAGE" -c 'command -v mvn || command -v javac' >/dev/null 2>&1; then
  fail "build tools (mvn/javac) present in runtime image"
fi

# 4. Ứng dụng nằm dưới dạng layer đã tách (không phải fat jar) và không ghi được bởi user chạy app
docker run --rm --entrypoint sh "$IMAGE" -c 'test -d /app/BOOT-INF/lib && test ! -w /app && test ! -w /app/BOOT-INF/lib' \
  || fail "/app is missing layered layout or is writable by the runtime user"

echo "OK: $IMAGE"
