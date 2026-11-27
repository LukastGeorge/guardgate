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

    /*
     * Cả hai câu đều có điều kiện "chưa bị khoá tại thời điểm now". Nếu thiếu điều kiện này, khi 20 request
     * sai đến cùng lúc, các request đã đọc user TRƯỚC khi bị khoá vẫn tiếp tục đếm, chạm ngưỡng lần nữa và
     * khoá lại tài khoản nhiều lần (kéo dài thời gian khoá, ghi trùng ACCOUNT_LOCKED). Postgres giữ khoá dòng
     * từ câu UPDATE đầu tới hết transaction nên các request xếp hàng và thấy trạng thái mới nhất.
     */

    /** @return 1 nếu đã đếm, 0 nếu tài khoản đang bị khoá (không đếm thêm) */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            update User u set u.failedLoginAttempts = u.failedLoginAttempts + 1
            where u.id = :id and (u.lockedUntil is null or u.lockedUntil <= :now)
            """)
    int incrementFailedAttempts(UUID id, Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            update User u set u.lockedUntil = :until, u.failedLoginAttempts = 0
            where u.id = :id and u.failedLoginAttempts >= :maxAttempts
              and (u.lockedUntil is null or u.lockedUntil <= :now)
            """)
    int lockIfThresholdReached(UUID id, int maxAttempts, Instant until, Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update User u set u.failedLoginAttempts = 0, u.lockedUntil = null where u.id = :id")
    int resetLoginFailures(UUID id);
}
