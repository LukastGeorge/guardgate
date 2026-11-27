package com.guardgate.auth.user;

import java.time.Instant;
import java.util.UUID;

/** DTO trả ra ngoài: chỉ chọn field an toàn, không bao giờ serialize entity trực tiếp. */
public record UserResponse(UUID id, String email, Role role, Instant createdAt) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getRole(), user.getCreatedAt());
    }
}
