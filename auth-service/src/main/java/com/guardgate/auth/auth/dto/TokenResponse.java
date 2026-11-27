package com.guardgate.auth.auth.dto;

/**
 * @param expiresIn số giây access token còn hiệu lực
 */
public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {

    public static TokenResponse bearer(String accessToken, String refreshToken, long expiresIn) {
        return new TokenResponse(accessToken, refreshToken, "Bearer", expiresIn);
    }

    @Override
    public String toString() {
        return "TokenResponse[tokenType=%s, expiresIn=%d]".formatted(tokenType, expiresIn);
    }
}
