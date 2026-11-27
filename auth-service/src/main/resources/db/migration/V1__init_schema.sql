-- Schema ban đầu của auth-service. Flyway chạy migration theo thứ tự version, mỗi file
-- chỉ chạy một lần và được checksum: KHÔNG sửa file đã chạy, hãy tạo V2__... mới.

CREATE TABLE users (
    id                    UUID         PRIMARY KEY,
    email                 VARCHAR(254) NOT NULL,
    password_hash         VARCHAR(255),                -- NULL với tài khoản chỉ đăng nhập qua GitHub
    role                  VARCHAR(16)  NOT NULL,
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_login_attempts INTEGER      NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    github_id             BIGINT,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uk_users_email UNIQUE (email),
    CONSTRAINT uk_users_github_id UNIQUE (github_id),
    CONSTRAINT ck_users_email_lowercase CHECK (email = lower(email)),
    CONSTRAINT ck_users_role CHECK (role IN ('USER', 'ADMIN')),
    CONSTRAINT ck_users_failed_attempts CHECK (failed_login_attempts >= 0)
);

-- Refresh token: chỉ lưu SHA-256 của token, không lưu token gốc.
-- family_id gom các token sinh ra từ cùng một lần đăng nhập (phục vụ phát hiện reuse).
CREATE TABLE refresh_tokens (
    id          UUID        PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL,
    family_id   UUID        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ,
    replaced_by UUID,
    CONSTRAINT uk_refresh_tokens_hash UNIQUE (token_hash)
);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens (expires_at);

-- Audit log: không có FK tới users để log vẫn còn khi user bị xoá.
CREATE TABLE audit_logs (
    id          BIGSERIAL    PRIMARY KEY,
    event_type  VARCHAR(64)  NOT NULL,
    user_id     UUID,
    email       VARCHAR(254),
    ip_address  VARCHAR(45),
    user_agent  VARCHAR(512),
    success     BOOLEAN      NOT NULL,
    details     VARCHAR(1000),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_user ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
