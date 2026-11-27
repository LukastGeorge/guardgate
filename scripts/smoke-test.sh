#!/usr/bin/env bash
# Smoke test end-to-end QUA GATEWAY: chứng minh các lớp bảo vệ hoạt động trên hệ thống đang chạy thật.
# Dùng: bash scripts/smoke-test.sh [BASE_URL]      (mặc định http://localhost:8080)
# Yêu cầu: curl, jq. Exit 0 khi mọi bước pass; khác 0 kèm "FAIL: <bước>".
# Lưu ý: rate limit login là ~10 request/phút/IP → chạy lại ngay lập tức có thể bị 429 ở bước đăng ký.
set -euo pipefail

BASE_URL=${1:-${BASE_URL:-http://localhost:8080}}
EMAIL="smoke-$(date +%s)-$RANDOM@example.com"
PASSWORD="Smoke-Test-Password-1"
PASSED=0

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "FAIL: missing tool '$tool'"; exit 2; }
done

# check <tên bước> <mã HTTP mong đợi> <tham số curl...>
# Ghi body vào $BODY để bước sau dùng (vd. lấy token).
check() {
  local name=$1 expected=$2
  shift 2
  local response status
  response=$(curl -sS -w $'\n%{http_code}' "$@") || { echo "FAIL: $name (curl error)"; exit 1; }
  status=${response##*$'\n'}
  BODY=${response%$'\n'*}
  if [[ "$status" != "$expected" ]]; then
    echo "FAIL: $name — expected HTTP $expected, got $status"
    echo "      body: ${BODY:0:300}"
    exit 1
  fi
  PASSED=$((PASSED + 1))
  printf '  ok  %-55s %s\n' "$name" "$status"
}

json() { printf '{"email":"%s","password":"%s"}' "$1" "$2"; }

echo "Smoke test against $BASE_URL"

check "register new user"                      201 -X POST "$BASE_URL/api/auth/register" \
      -H 'Content-Type: application/json' -d "$(json "$EMAIL" "$PASSWORD")"
check "login"                                  200 -X POST "$BASE_URL/api/auth/login" \
      -H 'Content-Type: application/json' -d "$(json "$EMAIL" "$PASSWORD")"
ACCESS=$(jq -r .accessToken <<<"$BODY")
REFRESH=$(jq -r .refreshToken <<<"$BODY")
[[ "$ACCESS" != "null" && -n "$ACCESS" ]] || { echo "FAIL: login returned no access token"; exit 1; }

check "USER calls demo user endpoint"          200 "$BASE_URL/api/demo/user" -H "Authorization: Bearer $ACCESS"
check "USER is forbidden on demo admin"        403 "$BASE_URL/api/demo/admin" -H "Authorization: Bearer $ACCESS"
check "USER is forbidden on auth admin API"    403 "$BASE_URL/api/admin/audit-logs" -H "Authorization: Bearer $ACCESS"
check "no token is rejected"                   401 "$BASE_URL/api/users/me"
check "public demo endpoint needs no token"    200 "$BASE_URL/api/demo/public"
# Có token hợp lệ mà vẫn 404 => gateway thực sự không có route tới JWKS/actuator của service phía sau
# (không token thì nhận 401 trước cả bước định tuyến: deny by default)
check "auth-service JWKS is not routed"        404 "$BASE_URL/.well-known/jwks.json" -H "Authorization: Bearer $ACCESS"
check "logout"                                 204 -X POST "$BASE_URL/api/auth/logout" \
      -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
      -d "{\"refreshToken\":\"$REFRESH\"}"
check "old access token is revoked"            401 "$BASE_URL/api/demo/user" -H "Authorization: Bearer $ACCESS"
check "old refresh token is revoked"           401 -X POST "$BASE_URL/api/auth/refresh" \
      -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}"

# 11 lần login sai liên tiếp: lần cuối phải bị gateway chặn (429), không tới auth-service
for _ in $(seq 1 10); do
  curl -sS -o /dev/null -X POST "$BASE_URL/api/auth/login" \
       -H 'Content-Type: application/json' -d "$(json "$EMAIL" "Wrong-Password-123")"
done
check "11th login attempt is rate limited"     429 -X POST "$BASE_URL/api/auth/login" \
      -H 'Content-Type: application/json' -d "$(json "$EMAIL" "Wrong-Password-123")"
check "spoofed X-Forwarded-For does not help"  429 -X POST "$BASE_URL/api/auth/login" \
      -H 'X-Forwarded-For: 9.9.9.9' -H 'Content-Type: application/json' \
      -d "$(json "$EMAIL" "Wrong-Password-123")"

# OAuth2 GitHub (chỉ khi auth-service bật profile "github"): redirect_uri phải trỏ về GATEWAY (H4)
location=$(curl -sS -o /dev/null -w '%{redirect_url}' "$BASE_URL/oauth2/authorization/github")
if [[ "$location" == https://github.com/* ]]; then
  if [[ "$location" == *"redirect_uri=${BASE_URL}/login/oauth2/code/github"* ]]; then
    PASSED=$((PASSED + 1))
    printf '  ok  %-55s %s\n' "OAuth2 redirect_uri points at the gateway" "302"
  else
    echo "FAIL: OAuth2 redirect_uri does not point at $BASE_URL: $location" | sed -E 's/(client_id|state)=[^&]*/\1=.../g'
    exit 1
  fi
else
  echo "  --  OAuth2 GitHub profile not enabled, redirect_uri check skipped"
fi

echo "ALL CHECKS PASSED ($PASSED)"
