package com.guardgate.auth.user;

/**
 * Chính sách mật khẩu theo NIST SP 800-63B: ưu tiên ĐỘ DÀI thay vì bắt buộc ký tự đặc biệt.
 * MAX_LENGTH = 64 vì BCrypt chỉ dùng 72 byte đầu (ký tự Unicode có thể chiếm tới 4 byte,
 * nhưng 64 ký tự ASCII/Latin phổ biến vẫn nằm trong giới hạn; đồng thời chặn DoS bằng chuỗi cực dài).
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 64;

    private PasswordPolicy() {
    }
}
