package com.dinkybell.ecommerce.repositories;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.dinkybell.ecommerce.entities.RefreshToken;

/**
 * Repository for managing RefreshToken entities.
 * 
 * Provides methods to find, create, update and delete refresh tokens,
 * as well as custom queries for token management operations.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    /**
     * Find a refresh token by its token value.
     * 
     * @param token The token string to search for
     * @return An Optional containing the token if found, or empty if not found
     */
    Optional<RefreshToken> findByToken(String token);
    
    /**
     * Find all refresh tokens belonging to a specific user.
     * 
     * @param userId The user ID to search for
     * @return A list of refresh tokens belonging to the user
     */
    List<RefreshToken> findByUserId(Long userId);
    
    /**
     * Delete all expired or revoked tokens.
     * 
     * @param now The current timestamp
     * @return The number of tokens deleted
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now OR rt.revoked = true")
    int deleteExpiredOrRevokedTokens(@Param("now") Instant now);
    
    /**
     * Revoke all tokens for a specific user except one specified token.
     * 
     * @param userId The ID of the user whose tokens should be revoked
     * @param exceptTokenId The ID of the token that should not be revoked
     * @return The number of tokens revoked
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.userId = :userId AND rt.id != :exceptTokenId")
    int revokeAllUserTokensExcept(@Param("userId") Long userId, @Param("exceptTokenId") Long exceptTokenId);
    
    /**
     * Count active (non-expired, non-revoked) tokens for a user.
     * 
     * @param userId The ID of the user
     * @param now The current timestamp
     * @return The count of active tokens
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.userId = :userId AND rt.expiryDate >= :now AND rt.revoked = false")
    long countActiveTokensByUserId(@Param("userId") Long userId, @Param("now") Instant now);
    
    /**
     * Find the oldest active token for a user (for token rotation policies).
     * 
     * @param userId The ID of the user
     * @param now The current timestamp
     * @return An Optional containing the oldest token if found, or empty if not found
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.expiryDate >= :now AND rt.revoked = false ORDER BY rt.createdAt ASC")
    Optional<RefreshToken> findOldestActiveTokenByUserId(@Param("userId") Long userId, @Param("now") Instant now);
    
    /**
     * Find an active refresh token for a specific user and device.
     * This prevents creating duplicate tokens for the same device.
     * 
     * @param userId The ID of the user
     * @param deviceInfo The device information fingerprint
     * @param now The current timestamp
     * @return An Optional containing the active token for this device if found, or empty if not found
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.deviceInfo = :deviceInfo AND rt.expiryDate >= :now AND rt.revoked = false ORDER BY rt.createdAt DESC")
    Optional<RefreshToken> findActiveTokenByUserIdAndDevice(@Param("userId") Long userId, @Param("deviceInfo") String deviceInfo, @Param("now") Instant now);
}
