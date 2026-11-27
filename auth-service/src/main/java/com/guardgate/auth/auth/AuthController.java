package com.guardgate.auth.auth;

import com.guardgate.auth.auth.dto.LoginRequest;
import com.guardgate.auth.auth.dto.LogoutRequest;
import com.guardgate.auth.auth.dto.RefreshRequest;
import com.guardgate.auth.auth.dto.RegisterRequest;
import com.guardgate.auth.auth.dto.TokenResponse;
import com.guardgate.auth.user.UserResponse;
import com.guardgate.auth.web.ClientInfo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request,
                                                 HttpServletRequest http) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request, ClientInfo.from(http)));
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        return authService.login(request, ClientInfo.from(http));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest http) {
        return authService.refresh(request.refreshToken(), ClientInfo.from(http));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt,
                                       @Valid @RequestBody(required = false) LogoutRequest request,
                                       HttpServletRequest http) {
        authService.logout(jwt, request == null ? null : request.refreshToken(), ClientInfo.from(http));
        return ResponseEntity.noContent().build();
    }
}
