package com.dinkybell.ecommerce.authentication.repository;

import java.util.Date;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.dinkybell.ecommerce.authentication.entity.BlacklistedToken;

/**
 * Repository interface for managing blacklisted JWT tokens in the database.
 * 
 * This repository provides methods for checking if a token is blacklisted and cleaning up expired
 * tokens.
 */
@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, String> {

    /**
     * Checks if a token with the specified JWT ID exists in the blacklist.
     * 
     * @param jti The JWT ID to check
     * @return true if the token is blacklisted, false otherwise
     */
    boolean existsByJti(String jti);

    /**
     * Deletes all blacklisted tokens that have expired. This method is used for database cleanup.
     * 
     * @param now The current date/time
     * @return The number of tokens deleted
     */
    @Modifying
    @Query("DELETE FROM BlacklistedToken t WHERE t.expiryDate < :now")
    int deleteExpiredTokens(@Param("now") Date now);
}
