package com.guardgate.auth.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.guardgate.auth.audit.AuditEventType;
import com.guardgate.auth.audit.AuditService;
import com.guardgate.auth.auth.TokenService;
import com.guardgate.auth.auth.dto.TokenResponse;
import com.guardgate.auth.security.ProblemDetailResponseWriter;
import com.guardgate.auth.user.User;
import com.guardgate.auth.user.UserRepository;
import com.guardgate.auth.web.ClientInfo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Clock;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Đăng nhập GitHub thành công => cấp cặp token GuardGate (giống login thường) và huỷ session.
 * Session chỉ tồn tại trong vài giây của luồng OAuth2 (để lưu tham số "state" chống CSRF).
 */
@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository users;
    private final TokenService tokenService;
    private final AuditService audit;
    private final ProblemDetailResponseWriter problemWriter;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public OAuth2LoginSuccessHandler(UserRepository users, TokenService tokenService, AuditService audit,
                                     ProblemDetailResponseWriter problemWriter, ObjectMapper objectMapper,
                                     Clock clock) {
        this.users = users;
        this.tokenService = tokenService;
        this.audit = audit;
        this.problemWriter = problemWriter;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        invalidateSession(request);
        ClientInfo client = ClientInfo.from(request);
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
        String userId = principal.getAttribute(GitHubOAuth2UserService.USER_ID_ATTRIBUTE);
        User user = userId == null ? null : users.findById(UUID.fromString(userId)).orElse(null);

        if (user == null || !user.isEnabled() || user.isLockedAt(clock.instant())) {
            audit.record(AuditEventType.OAUTH2_LOGIN_FAILURE, user == null ? null : user.getId(), null, client,
                    false, "account unavailable");
            problemWriter.write(request, response, HttpStatus.UNAUTHORIZED, "Account is not available");
            return;
        }

        TokenResponse tokens = tokenService.issueFor(user);
        audit.record(AuditEventType.OAUTH2_LOGIN_SUCCESS, user.getId(), user.getEmail(), client, true, "github");
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        objectMapper.writeValue(response.getOutputStream(), tokens);
    }

    private static void invalidateSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }
}
