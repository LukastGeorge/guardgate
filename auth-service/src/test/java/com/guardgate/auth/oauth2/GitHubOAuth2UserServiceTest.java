package com.guardgate.auth.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.guardgate.auth.config.GitHubProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class GitHubOAuth2UserServiceTest {

    private static final String EMAILS_URL = "https://api.github.test/user/emails";

    private MockRestServiceServer github;
    private GitHubOAuth2UserService service;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        github = MockRestServiceServer.bindTo(builder).build();
        service = new GitHubOAuth2UserService(builder, new GitHubProperties("https://api.github.test"),
                Mockito.mock(OAuth2AccountService.class));
    }

    @Test
    void returnsVerifiedPrimaryEmailAndSendsBearerToken() {
        github.expect(requestTo(EMAILS_URL))
                .andExpect(header("Authorization", "Bearer gho_test"))
                .andRespond(withSuccess("""
                        [{"email":"secondary@example.com","primary":false,"verified":true},
                         {"email":"primary@example.com","primary":true,"verified":true}]
                        """, MediaType.APPLICATION_JSON));

        assertThat(service.fetchVerifiedPrimaryEmail("gho_test")).isEqualTo("primary@example.com");
        github.verify();
    }

    @Test
    void rejectsAccountWhosePrimaryEmailIsNotVerified() {
        github.expect(requestTo(EMAILS_URL)).andRespond(withSuccess("""
                [{"email":"primary@example.com","primary":true,"verified":false}]
                """, MediaType.APPLICATION_JSON));

        assertErrorCode(() -> service.fetchVerifiedPrimaryEmail("gho_test"), "verified_email_required");
    }

    @Test
    void mapsGithubApiFailureToOAuth2Error() {
        github.expect(requestTo(EMAILS_URL)).andRespond(withServerError());

        assertErrorCode(() -> service.fetchVerifiedPrimaryEmail("gho_test"), "github_api_error");
    }

    private static void assertErrorCode(Runnable call, String expectedCode) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(OAuth2AuthenticationException.class,
                e -> assertThat(e.getError().getErrorCode()).isEqualTo(expectedCode));
    }
}
