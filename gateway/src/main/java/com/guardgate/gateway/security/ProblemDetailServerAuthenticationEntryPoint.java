package com.guardgate.gateway.security;

import com.guardgate.gateway.web.ProblemResponses;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** 401 dạng problem+json; không nói lý do cụ thể (hết hạn, sai chữ ký, bị thu hồi...) cho client. */
@Component
public class ProblemDetailServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        String challenge = ex instanceof InvalidBearerTokenException ? "Bearer error=\"invalid_token\"" : "Bearer";
        exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, challenge);
        return ProblemResponses.write(exchange, HttpStatus.UNAUTHORIZED, "Authentication is required");
    }
}
