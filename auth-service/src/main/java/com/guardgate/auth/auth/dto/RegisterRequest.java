package com.guardgate.auth.auth.dto;

import com.guardgate.auth.user.MaxUtf8Bytes;
import com.guardgate.auth.user.PasswordPolicy;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Chỉ có email + password: client gửi thêm "role":"ADMIN" cũng bị bỏ qua (chống mass assignment).
 */
public record RegisterRequest(
        @NotBlank @Email(regexp = ".+@.+\\..+") @Size(max = 254) String email,
        @NotBlank @Size(min = PasswordPolicy.MIN_LENGTH, max = PasswordPolicy.MAX_LENGTH)
        @MaxUtf8Bytes(PasswordPolicy.MAX_BYTES) String password) {

    @Override
    public String toString() {
        return "RegisterRequest[email=%s, password=***]".formatted(email);
    }
}
