package com.guardgate.auth.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.guardgate.auth.user.Role;
import com.guardgate.auth.user.User;
import com.guardgate.auth.user.UserRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

@ExtendWith(MockitoExtension.class)
class OAuth2AccountServiceTest {

    @Mock
    private UserRepository users;
    @InjectMocks
    private OAuth2AccountService service;

    @Test
    void returnsExistingUserLinkedToGithubIdWithoutSaving() {
        User existing = User.github("bob@example.com", 42L);
        when(users.findByGithubId(42L)).thenReturn(Optional.of(existing));

        assertThat(service.findOrCreateGithubUser(42L, "bob@example.com")).isSameAs(existing);
        verify(users, never()).save(any());
    }

    @Test
    void createsNewUserWithNormalisedEmail() {
        when(users.findByGithubId(42L)).thenReturn(Optional.empty());
        when(users.existsByEmail("bob@example.com")).thenReturn(false);
        when(users.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.findOrCreateGithubUser(42L, "  Bob@Example.COM ");

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(users).save(saved.capture());
        assertThat(saved.getValue().getEmail()).isEqualTo("bob@example.com");
        assertThat(saved.getValue().getGithubId()).isEqualTo(42L);
        assertThat(saved.getValue().getRole()).isEqualTo(Role.USER);
        assertThat(saved.getValue().hasPassword()).isFalse();
    }

    @Test
    void refusesToLinkGithubAccountToExistingLocalAccount() {
        when(users.findByGithubId(42L)).thenReturn(Optional.empty());
        when(users.existsByEmail("bob@example.com")).thenReturn(true);

        assertThatThrownBy(() -> service.findOrCreateGithubUser(42L, "bob@example.com"))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
                        e -> assertThat(e.getError().getErrorCode()).isEqualTo("account_exists"));
        verify(users, never()).save(any());
    }
}
