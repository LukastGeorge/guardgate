package com.guardgate.auth.auth;

import com.guardgate.auth.web.ApiException;
import org.springframework.http.HttpStatus;

public class InvalidPasswordException extends ApiException {

    public InvalidPasswordException(String clientMessage) {
        super(HttpStatus.BAD_REQUEST, clientMessage);
    }
}
