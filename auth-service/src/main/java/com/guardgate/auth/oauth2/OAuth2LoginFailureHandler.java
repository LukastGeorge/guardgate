package com.guardgate.auth.oauth2;

import com.guardgate.auth.audit.AuditEventType;
import com.guardgate.auth.audit.AuditService;
import com.guardgate.auth.security.ProblemDetailResponseWriter;
import com.guardgate.auth.web.ClientInfo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {

    private final AuditService audit;
    private final ProblemDetailResponseWriter problemWriter;

    public OAuth2LoginFailureHandler(AuditService audit, ProblemDetailResponseWriter problemWriter) {
        this.audit = audit;
        this.problemWriter = problemWriter;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        String errorCode = exception instanceof OAuth2AuthenticationException oauth2
                ? oauth2.getError().getErrorCode()
                : "authentication_failed";
        audit.record(AuditEventType.OAUTH2_LOGIN_FAILURE, null, null, ClientInfo.from(request), false,
                "error=" + errorCode);
        String detail = "account_exists".equals(errorCode)
                ? "An account with this email already exists; sign in with your password"
                : "GitHub login failed";
        problemWriter.write(request, response, HttpStatus.UNAUTHORIZED, detail);
    }
}
