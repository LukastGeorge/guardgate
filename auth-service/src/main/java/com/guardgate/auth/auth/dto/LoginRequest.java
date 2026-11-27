package com.guardgate.auth.auth.dto;

import com.guardgate.auth.user.PasswordPolicy;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank @Size(max = 254) String email,
        @NotBlank @Size(max = PasswordPolicy.MAX_LENGTH) String password) {

    @Override
    public String toString() {
        return "LoginRequest[email=%s, password=***]".formatted(email);
    }
}
