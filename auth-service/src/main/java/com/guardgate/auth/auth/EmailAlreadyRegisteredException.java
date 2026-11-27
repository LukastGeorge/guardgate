package com.guardgate.auth.auth;

import com.guardgate.auth.web.ApiException;
import org.springframework.http.HttpStatus;

public class EmailAlreadyRegisteredException extends ApiException {

    public EmailAlreadyRegisteredException() {
        super(HttpStatus.CONFLICT, "Email is already registered");
    }
}
