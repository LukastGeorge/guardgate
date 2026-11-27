package com.guardgate.auth.oauth2;

import com.guardgate.auth.user.EmailNormalizer;
import com.guardgate.auth.user.User;
import com.guardgate.auth.user.UserRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OAuth2AccountService {

    private final UserRepository users;

    public OAuth2AccountService(UserRepository users) {
        this.users = users;
    }

    /**
     * Tìm tài khoản theo GitHub id; nếu chưa có thì tạo mới.
     *
     * <p>KHÔNG tự động liên kết vào tài khoản local đã tồn tại cùng email. Lý do: đăng ký local chưa
     * xác minh email, nên kẻ tấn công có thể đăng ký trước bằng email của nạn nhân rồi chờ nạn nhân
     * đăng nhập GitHub để "chiếm" tài khoản (pre-account takeover).
     */
    @Transactional
    public User findOrCreateGithubUser(long githubId, String verifiedEmail) {
        return users.findByGithubId(githubId).orElseGet(() -> {
            String email = EmailNormalizer.normalize(verifiedEmail);
            if (users.existsByEmail(email)) {
                throw new OAuth2AuthenticationException(new OAuth2Error("account_exists",
                        "An account with this email already exists; sign in with your password", null));
            }
            return users.save(User.github(email, githubId));
        });
    }
}
