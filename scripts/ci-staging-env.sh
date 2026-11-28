#!/usr/bin/env bash
# Sinh file .env cho môi trường staging dùng một lần (CI): lấy khung từ .env.example, thay MỌI mật khẩu
# bằng giá trị ngẫu nhiên và tạo khoá ký JWT RSA 2048 mới. Không secret nào được lưu hay tái sử dụng.
# Dùng: bash scripts/ci-staging-env.sh > .env
set -euo pipefail
cd "$(dirname "$0")/.."

random_secret() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32; }

# PKCS#8 (bắt buộc bước pkcs8 -topk8: genpkey -outform DER của OpenSSL 3 xuất PKCS#1, xem bài học L2.2)
jwt_key=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -outform DER | openssl base64 -A)

while IFS= read -r line; do
  case "$line" in
    \#*|"") printf '%s\n' "$line" ;;
    *PASSWORD=*)          printf '%s=%s\n' "${line%%=*}" "$(random_secret)" ;;
    JWT_PRIVATE_KEY=*)    printf 'JWT_PRIVATE_KEY=%s\n' "$jwt_key" ;;
    BOOTSTRAP_ADMIN_EMAIL=*) printf 'BOOTSTRAP_ADMIN_EMAIL=admin@staging.invalid\n' ;;
    POSTGRES_PORT=*)      printf 'POSTGRES_PORT=5432\n' ;;
    *)                    printf '%s\n' "$line" ;;
  esac
done < .env.example
