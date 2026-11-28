package com.guardgate.auth.user;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.nio.charset.StandardCharsets;

public class MaxUtf8BytesValidator implements ConstraintValidator<MaxUtf8Bytes, String> {

    private int maxBytes;

    /** Dùng bởi Bean Validation, sau đó gọi initialize(). */
    public MaxUtf8BytesValidator() {
    }

    MaxUtf8BytesValidator(int maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    public void initialize(MaxUtf8Bytes annotation) {
        this.maxBytes = annotation.value();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value == null || value.getBytes(StandardCharsets.UTF_8).length <= maxBytes;
    }
}
