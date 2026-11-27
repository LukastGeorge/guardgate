package com.guardgate.auth.auth;

import com.guardgate.auth.web.ApiException;
import org.springframework.http.HttpStatus;

/**
 * Dùng chung MỘT thông báo cho: sai mật khẩu, email không tồn tại, tài khoản bị khoá/vô hiệu hoá.
 * Nhờ vậy kẻ tấn công không phân biệt được email nào có tài khoản (chống user enumeration).
 */
public class InvalidCredentialsException extends ApiException {

    public InvalidCredentialsException() {
        super(HttpStatus.UNAUTHORIZED, "Invalid email or password");
    }
}
