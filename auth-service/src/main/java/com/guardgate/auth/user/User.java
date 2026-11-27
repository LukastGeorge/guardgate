package com.guardgate.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @Column(name = "password_hash")
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Role role;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "github_id", unique = true)
    private Long githubId;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected User() {
        // JPA
    }

    private User(String email, String passwordHash, Role role, Long githubId) {
        this.email = Objects.requireNonNull(email);
        this.passwordHash = passwordHash;
        this.role = Objects.requireNonNull(role);
        this.githubId = githubId;
    }

    public static User local(String normalizedEmail, String passwordHash, Role role) {
        return new User(normalizedEmail, Objects.requireNonNull(passwordHash), role, null);
    }

    public static User github(String normalizedEmail, long githubId) {
        return new User(normalizedEmail, null, Role.USER, githubId);
    }

    public boolean isLockedAt(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public boolean hasPassword() {
        return passwordHash != null;
    }

    public void changePasswordHash(String newHash) {
        this.passwordHash = Objects.requireNonNull(newHash);
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Role getRole() {
        return role;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Long getGithubId() {
        return githubId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public String toString() {
        // Không đưa passwordHash vào toString (tránh lọt vào log)
        return "User[id=%s, role=%s]".formatted(id, role);
    }
}
