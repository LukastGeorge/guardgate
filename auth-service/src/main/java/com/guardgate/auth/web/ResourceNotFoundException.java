package com.guardgate.auth.web;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends ApiException {

    public ResourceNotFoundException(String clientMessage) {
        super(HttpStatus.NOT_FOUND, clientMessage);
    }
}
