package com.guardgate.auth.auth.dto;

import jakarta.validation.constraints.Size;

/** refreshToken là tuỳ chọn: nếu có, cả "family" của nó cũng bị thu hồi. */
public record LogoutRequest(@Size(max = 128) String refreshToken) {

    @Override
    public String toString() {
        return "LogoutRequest[refreshToken=***]";
    }
}
