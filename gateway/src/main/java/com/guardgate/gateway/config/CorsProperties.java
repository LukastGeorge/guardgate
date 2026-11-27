package com.guardgate.gateway.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param allowedOrigins danh sách origin được phép (CORS_ALLOWED_ORIGINS, phân cách dấu phẩy).
 *                       Rỗng = không cho origin nào (deny by default).
 */
@ConfigurationProperties(prefix = "guardgate.gateway.cors")
public record CorsProperties(List<String> allowedOrigins) {

    public CorsProperties {
        allowedOrigins = allowedOrigins == null
                ? List.of()
                : allowedOrigins.stream().map(String::trim).filter(origin -> !origin.isEmpty()).toList();
    }
}
