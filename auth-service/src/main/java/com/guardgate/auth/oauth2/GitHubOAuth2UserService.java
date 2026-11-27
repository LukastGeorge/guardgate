package com.guardgate.auth.oauth2;

import com.guardgate.auth.config.GitHubProperties;
import com.guardgate.auth.user.User;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Sau khi GitHub xác thực xong: lấy thông tin user, lấy email CHÍNH + ĐÃ XÁC MINH qua /user/emails,
 * rồi ánh xạ sang tài khoản GuardGate.
 */
@Component
public class GitHubOAuth2UserService extends DefaultOAuth2UserService {

    public static final String USER_ID_ATTRIBUTE = "guardgate_user_id";

    private final RestClient restClient;
    private final OAuth2AccountService accounts;

    public GitHubOAuth2UserService(RestClient.Builder restClientBuilder, GitHubProperties properties,
                                   OAuth2AccountService accounts) {
        this.restClient = restClientBuilder.baseUrl(properties.apiBaseUrl()).build();
        this.accounts = accounts;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User githubUser = super.loadUser(userRequest);
        if (!(githubUser.getAttribute("id") instanceof Number githubId)) {
            throw error("invalid_user_info", "GitHub did not return a user id");
        }
        String email = fetchVerifiedPrimaryEmail(userRequest.getAccessToken().getTokenValue());
        User user = accounts.findOrCreateGithubUser(githubId.longValue(), email);

        Map<String, Object> attributes = new HashMap<>(githubUser.getAttributes());
        attributes.put(USER_ID_ATTRIBUTE, user.getId().toString());
        return new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())),
                attributes, "id");
    }

    String fetchVerifiedPrimaryEmail(String accessToken) {
        List<GitHubEmail> emails;
        try {
            emails = restClient.get()
                    .uri("/user/emails")
                    .headers(headers -> headers.setBearerAuth(accessToken))
                    .header("Accept", "application/vnd.github+json")
                    .retrieve()
                    .body(new ParameterizedTypeReference<>() {
                    });
        } catch (RestClientException e) {
            throw error("github_api_error", "Could not read e-mail addresses from GitHub");
        }
        if (emails == null) {
            throw error("verified_email_required", "GitHub account has no verified primary e-mail");
        }
        return emails.stream()
                .filter(e -> e.primary() && e.verified() && e.email() != null)
                .map(GitHubEmail::email)
                .findFirst()
                .orElseThrow(() -> error("verified_email_required", "GitHub account has no verified primary e-mail"));
    }

    private static OAuth2AuthenticationException error(String code, String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(code, description, null));
    }

    record GitHubEmail(String email, boolean primary, boolean verified) {
    }
}
