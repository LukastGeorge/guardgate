package com.guardgate.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.guardgate.auth.support.TestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class RsaKeyLoaderTest {

    @Test
    void loadsBase64Pkcs8KeyAndDerivesPublicKey() throws Exception {
        KeyPair pair = TestKeys.rsa2048();

        RSAKey key = RsaKeyLoader.load(TestKeys.base64Pkcs8(pair));

        assertThat(key.isPrivate()).isTrue();
        assertThat(key.toRSAPublicKey()).isEqualTo(pair.getPublic());
        assertThat(key.getKeyID()).isNotBlank();
    }

    @Test
    void loadsPemWithEscapedNewlines() throws Exception {
        KeyPair pair = TestKeys.rsa2048();
        String body = TestKeys.base64Pkcs8(pair).replaceAll("(.{64})", "$1\\\\n");
        String pem = "-----BEGIN PRIVATE KEY-----\\n" + body + "\\n-----END PRIVATE KEY-----";

        RSAKey key = RsaKeyLoader.load(pem);

        assertThat(key.toRSAPublicKey()).isEqualTo(pair.getPublic());
    }

    @Test
    void rejectsKeysShorterThan2048Bits() {
        String weakKey = TestKeys.base64Pkcs8(TestKeys.generate("RSA", 1024));

        assertThatThrownBy(() -> RsaKeyLoader.load(weakKey))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("too short");
    }

    @Test
    void rejectsNonRsaKeys() {
        String ecKey = TestKeys.base64Pkcs8(TestKeys.generate("EC", 256));

        assertThatThrownBy(() -> RsaKeyLoader.load(ecKey))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not a valid PKCS#8 RSA key");
    }

    @Test
    void errorMessageNeverContainsKeyMaterial() {
        String garbage = "this-is-not-base64-%%%-secret-value";

        assertThatThrownBy(() -> RsaKeyLoader.load(garbage))
                .isInstanceOf(IllegalStateException.class)
                .message()
                .doesNotContain("secret-value");
    }
}
