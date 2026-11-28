package com.guardgate.demo.security;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "guardgate.demo.jwt")
public record DemoJwtProperties(@NotBlank String jwkSetUri, @NotBlank String issuer, @NotBlank String audience) {
}
