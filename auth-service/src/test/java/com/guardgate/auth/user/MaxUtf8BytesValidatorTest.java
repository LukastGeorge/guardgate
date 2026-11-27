package com.guardgate.auth.user;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class MaxUtf8BytesValidatorTest {

    private final MaxUtf8BytesValidator validator = new MaxUtf8BytesValidator(72);

    @Test
    void acceptsExactly72AsciiBytes() {
        assertThat(validator.isValid("a".repeat(72), null)).isTrue();
    }

    @Test
    void rejectsMultiByteStringOver72Bytes() {
        // 19 emoji = 38 ký tự Java nhưng 76 byte UTF-8
        assertThat(validator.isValid("😀".repeat(19), null)).isFalse();
    }

    @Test
    void treatsNullAsValidSoNotBlankCanReportIt() {
        assertThat(validator.isValid(null, null)).isTrue();
    }
}
