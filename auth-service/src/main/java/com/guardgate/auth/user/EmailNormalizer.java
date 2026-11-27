package com.guardgate.auth.user;

import java.util.Locale;

/** "  Alice@Example.COM " và "alice@example.com" phải là cùng một tài khoản. */
public final class EmailNormalizer {

    private EmailNormalizer() {
    }

    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
