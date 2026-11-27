package com.guardgate.auth.auth;

import com.guardgate.auth.web.ApiException;
import org.springframework.http.HttpStatus;

public class InvalidRefreshTokenException extends ApiException {

    public InvalidRefreshTokenException() {
        super(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
    }
}
