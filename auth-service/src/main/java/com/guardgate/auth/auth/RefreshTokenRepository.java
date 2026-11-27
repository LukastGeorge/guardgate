package com.guardgate.auth.auth;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * SELECT ... FOR UPDATE: hai request refresh song song với cùng một token sẽ xếp hàng,
     * request thứ hai thấy token đã bị rotate => bị coi là reuse. Không thể "nhân bản" token.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from RefreshToken t join fetch t.user where t.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashForUpdate(String tokenHash);

    @Query("select t from RefreshToken t join fetch t.user where t.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.revokedAt = :now where t.familyId = :familyId and t.revokedAt is null")
    int revokeFamily(UUID familyId, Instant now);

    @Modifying
    @Query("delete from RefreshToken t where t.expiresAt < :cutoff")
    int deleteExpiredBefore(Instant cutoff);
}
