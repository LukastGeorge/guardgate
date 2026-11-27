#!/bin/sh
# Chạy MỘT LẦN khi volume Postgres còn trống (docker-entrypoint-initdb.d).
# Tạo database + user riêng cho auth-service theo nguyên tắc least privilege:
# auth-service chỉ sở hữu DB của nó, không phải superuser.
set -eu

# Dùng biến psql (-v) + :'var' / :"var" để psql tự escape giá trị,
# tránh SQL injection ngay cả khi mật khẩu chứa ký tự đặc biệt.
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname postgres \
     -v app_db="$AUTH_DB_NAME" \
     -v app_user="$AUTH_DB_USER" \
     -v app_password="$AUTH_DB_PASSWORD" <<'EOSQL'
CREATE ROLE :"app_user" WITH LOGIN PASSWORD :'app_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE DATABASE :"app_db" OWNER :"app_user";
REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"app_db" TO :"app_user";
EOSQL

echo "Created database '$AUTH_DB_NAME' owned by '$AUTH_DB_USER'"
