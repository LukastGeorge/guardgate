package com.guardgate.auth.support;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Sinh khoá RSA ngẫu nhiên cho test: không có khoá thật nào nằm trong repo. */
public final class TestKeys {

    private static final KeyPair RSA_2048 = generate("RSA", 2048);

    private TestKeys() {
    }

    public static KeyPair rsa2048() {
        return RSA_2048;
    }

    public static String base64Pkcs8(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    public static KeyPair generate(String algorithm, int size) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            generator.initialize(size);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
