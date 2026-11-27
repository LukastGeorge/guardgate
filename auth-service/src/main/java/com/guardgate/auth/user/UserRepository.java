package com.guardgate.auth.user;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    Optional<User> findByGithubId(Long githubId);

    boolean existsByEmail(String email);

    /*
     * Các thao tác đếm số lần đăng nhập sai dùng câu UPDATE nguyên tử thay vì
     * "đọc -> +1 -> ghi" trong Java: nếu kẻ tấn công bắn 20 request song song,
     * cách đọc-ghi sẽ bị race condition và đếm thiếu, khiến lockout vô dụng.
     */

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update User u set u.failedLoginAttempts = u.failedLoginAttempts + 1 where u.id = :id")
    int incrementFailedAttempts(UUID id);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            update User u set u.lockedUntil = :until, u.failedLoginAttempts = 0
            where u.id = :id and u.failedLoginAttempts >= :maxAttempts
            """)
    int lockIfThresholdReached(UUID id, int maxAttempts, Instant until);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update User u set u.failedLoginAttempts = 0, u.lockedUntil = null where u.id = :id")
    int resetLoginFailures(UUID id);
}
