#!/usr/bin/env bash
# Least privilege cho secret trong docker compose: mỗi container chỉ nhận đúng biến nó cần.
# Gateway (hướng Internet) không bao giờ được giữ khoá ký JWT hay mật khẩu DB; auth-service không giữ
# mật khẩu superuser Postgres. (Final review GĐ4, finding #2: env_file: .env đưa MỌI secret vào mọi container.)
set -uo pipefail
cd "$(dirname "$0")/../.."
failures=0

# Dùng .env giả để test không phụ thuộc (và không đọc) secret thật trên máy
tmp=$(mktemp -d)
bash scripts/ci-staging-env.sh > "$tmp/.env"
config=$(docker compose --env-file "$tmp/.env" -f docker-compose.yml config --format json 2>/dev/null)
rm -rf "$tmp"
[[ -n "$config" ]] || { echo "FAIL: docker compose config failed"; exit 1; }

env_keys() { jq -r --arg s "$1" '.services[$s].environment // {} | keys[]' <<<"$config"; }

must_not_have() {
  local service=$1; shift
  local keys; keys=$(env_keys "$service")
  for var in "$@"; do
    if grep -qx "$var" <<<"$keys"; then
      echo "FAIL: $service must not receive $var"; failures=$((failures + 1))
    fi
  done
}
must_have() {
  local service=$1; shift
  local keys; keys=$(env_keys "$service")
  for var in "$@"; do
    grep -qx "$var" <<<"$keys" || { echo "FAIL: $service is missing $var"; failures=$((failures + 1)); }
  done
}

must_not_have gateway JWT_PRIVATE_KEY POSTGRES_ADMIN_PASSWORD AUTH_DB_PASSWORD BOOTSTRAP_ADMIN_PASSWORD GITHUB_CLIENT_SECRET
must_not_have demo-service JWT_PRIVATE_KEY POSTGRES_ADMIN_PASSWORD AUTH_DB_PASSWORD BOOTSTRAP_ADMIN_PASSWORD REDIS_PASSWORD
must_not_have auth-service POSTGRES_ADMIN_PASSWORD
must_have gateway REDIS_PASSWORD JWT_JWK_SET_URI
must_have auth-service JWT_PRIVATE_KEY AUTH_DB_PASSWORD REDIS_PASSWORD BOOTSTRAP_ADMIN_PASSWORD

[[ $failures -eq 0 ]] && echo "compose secret isolation tests passed" || { echo "$failures problem(s)"; exit 1; }
