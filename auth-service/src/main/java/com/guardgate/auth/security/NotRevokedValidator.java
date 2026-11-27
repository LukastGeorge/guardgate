package com.guardgate.auth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Từ chối JWT có jti nằm trong denylist. Nếu Redis lỗi thì từ chối luôn (fail-closed):
 * ưu tiên an toàn hơn tính sẵn sàng, vì token đã logout không được phép dùng lại.
 */
public class NotRevokedValidator implements OAuth2TokenValidator<Jwt> {

    private static final Logger log = LoggerFactory.getLogger(NotRevokedValidator.class);

    private final AccessTokenDenylist denylist;

    public NotRevokedValidator(AccessTokenDenylist denylist) {
        this.denylist = denylist;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String jti = jwt.getId();
        if (jti == null || jti.isBlank()) {
            return failure("Token has no jti");
        }
        try {
            return denylist.isRevoked(jti) ? failure("Token has been revoked") : OAuth2TokenValidatorResult.success();
        } catch (RuntimeException e) {
            log.error("Token revocation check failed, rejecting token (fail-closed)", e);
            return failure("Token revocation status unavailable");
        }
    }

    private static OAuth2TokenValidatorResult failure(String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, description, null));
    }
}
