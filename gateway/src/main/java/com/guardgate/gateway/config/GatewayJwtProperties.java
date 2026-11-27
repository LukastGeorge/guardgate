package com.guardgate.gateway.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * @param jwkSetUri URL JWKS của auth-service (chỉ chứa public key)
 * @param issuer    giá trị claim "iss" bắt buộc
 * @param audience  giá trị phải có trong claim "aud"
 */
@Validated
@ConfigurationProperties(prefix = "guardgate.gateway.jwt")
public record GatewayJwtProperties(@NotBlank String jwkSetUri, @NotBlank String issuer, @NotBlank String audience) {
}
