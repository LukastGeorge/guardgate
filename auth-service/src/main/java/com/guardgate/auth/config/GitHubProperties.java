package com.guardgate.auth.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "guardgate.github")
public record GitHubProperties(@NotBlank String apiBaseUrl) {
}
