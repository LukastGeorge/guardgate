package com.guardgate.auth.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Nạp khoá RSA từ biến môi trường. Chấp nhận:
 * <ul>
 *   <li>Base64 của khoá PKCS#8 dạng DER (một dòng, tiện đặt trong .env / K8s Secret)</li>
 *   <li>Chuỗi PEM "-----BEGIN PRIVATE KEY-----" (kể cả khi xuống dòng được ghi là "\n")</li>
 * </ul>
 * Public key được suy ra từ private key, nên chỉ cần quản lý MỘT secret.
 * Thông báo lỗi không bao giờ chứa nội dung khoá.
 */
public final class RsaKeyLoader {

    static final int MIN_KEY_SIZE_BITS = 2048;

    private RsaKeyLoader() {
    }

    public static RSAKey load(String encodedKey) {
        if (encodedKey == null || encodedKey.isBlank()) {
            throw new IllegalStateException("JWT private key is empty");
        }
        String base64 = encodedKey
                .replace("\\n", "")
                .replaceAll("-----(BEGIN|END) [A-Z ]+-----", "")
                .replaceAll("\\s", "");

        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("JWT private key is not valid Base64");
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der));
            if (!(privateKey instanceof RSAPrivateCrtKey crtKey)) {
                throw new IllegalStateException("JWT private key must be an RSA (CRT) key");
            }
            int bits = crtKey.getModulus().bitLength();
            if (bits < MIN_KEY_SIZE_BITS) {
                throw new IllegalStateException(
                        "JWT private key is too short: %d bits (minimum %d)".formatted(bits, MIN_KEY_SIZE_BITS));
            }
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
                    new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent()));

            return new RSAKey.Builder(publicKey)
                    .privateKey(crtKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyIDFromThumbprint()
                    .build();
        } catch (GeneralSecurityException | JOSEException e) {
            throw new IllegalStateException("JWT private key is not a valid PKCS#8 RSA key"
                    + " (PKCS#1 keys must be converted: openssl pkcs8 -topk8 -nocrypt -outform DER)");
        }
    }
}
