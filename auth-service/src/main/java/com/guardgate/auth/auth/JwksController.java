package com.guardgate.auth.auth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Công bố PUBLIC key (định dạng JWKS, RFC 7517) để gateway/service khác xác thực JWT.
 * toPublicJWK() loại bỏ toàn bộ thành phần private (d, p, q...).
 */
@RestController
public class JwksController {

    private final Map<String, Object> jwks;

    public JwksController(RSAKey jwtSigningKey) {
        this.jwks = new JWKSet(jwtSigningKey.toPublicJWK()).toJSONObject();
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return jwks;
    }
}
