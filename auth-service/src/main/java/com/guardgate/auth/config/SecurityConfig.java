package com.guardgate.auth.config;

import com.guardgate.auth.oauth2.GitHubOAuth2UserService;
import com.guardgate.auth.oauth2.OAuth2LoginFailureHandler;
import com.guardgate.auth.oauth2.OAuth2LoginSuccessHandler;
import com.guardgate.auth.security.ProblemDetailAccessDeniedHandler;
import com.guardgate.auth.security.ProblemDetailAuthenticationEntryPoint;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Hai SecurityFilterChain tách biệt:
 * <ol>
 *   <li>OAuth2 login (/oauth2/**, /login/oauth2/**): cần session ngắn hạn để lưu "state".</li>
 *   <li>REST API (mọi thứ còn lại): STATELESS, chỉ chấp nhận Bearer JWT, không session, không cookie.</li>
 * </ol>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final String[] PUBLIC_POST_ENDPOINTS = {
            "/api/auth/register", "/api/auth/login", "/api/auth/refresh"
    };

    private final ProblemDetailAuthenticationEntryPoint authenticationEntryPoint;
    private final ProblemDetailAccessDeniedHandler accessDeniedHandler;

    public SecurityConfig(ProblemDetailAuthenticationEntryPoint authenticationEntryPoint,
                          ProblemDetailAccessDeniedHandler accessDeniedHandler) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain oauth2LoginChain(HttpSecurity http,
                                                ObjectProvider<ClientRegistrationRepository> clientRegistrations,
                                                GitHubOAuth2UserService gitHubUserService,
                                                OAuth2LoginSuccessHandler successHandler,
                                                OAuth2LoginFailureHandler failureHandler) throws Exception {
        http.securityMatcher("/oauth2/**", "/login/oauth2/**");
        applySecurityHeaders(http);
        http.exceptionHandling(e -> e
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler));

        if (clientRegistrations.getIfAvailable() == null) {
            // Profile "github" chưa bật => tắt hẳn các endpoint OAuth2
            http.authorizeHttpRequests(auth -> auth.anyRequest().denyAll());
            return http.build();
        }

        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                // Không lưu Authentication vào session; token được trả ngay trong success handler
                .securityContext(ctx -> ctx.securityContextRepository(new RequestAttributeSecurityContextRepository()))
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(gitHubUserService))
                        .successHandler(successHandler)
                        .failureHandler(failureHandler));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain apiChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter)
            throws Exception {
        applySecurityHeaders(http);
        http
                // CSRF chỉ khai thác được khi trình duyệt TỰ gửi kèm credential (cookie).
                // API này nhận token qua header Authorization nên CSRF không áp dụng.
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(cache -> cache.disable())
                // Không cấu hình CORS ở đây: trình duyệt chỉ nói chuyện với gateway (giai đoạn 3),
                // không có header CORS => request cross-origin trực tiếp tới service này bị chặn.
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, PUBLIC_POST_ENDPOINTS).permitAll()
                        .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
                        .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        // Deny-by-default: endpoint mới thêm vào mà quên cấu hình sẽ yêu cầu đăng nhập
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler));
        return http.build();
    }

    /**
     * Security headers (OWASP A05). Spring Security mặc định đã có X-Content-Type-Options, Cache-Control: no-store,
     * HSTS (chỉ gửi qua HTTPS); bổ sung CSP chặt cho API JSON, chống clickjacking và không lộ Referer.
     */
    private static void applySecurityHeaders(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000))
                .contentTypeOptions(Customizer.withDefaults()));
    }
}
