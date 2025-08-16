package com.dinkybell.ecommerce.services;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.dinkybell.ecommerce.entities.BlacklistedToken;
import com.dinkybell.ecommerce.repositories.BlacklistedTokenRepository;

/**
 * Service for managing blacklisted (invalidated) JWT tokens.
 * 
 * This service keeps track of tokens that have been invalidated through logout but have not yet
 * expired. It provides methods to blacklist tokens and check if a token is blacklisted. It also
 * automatically cleans up expired tokens from the blacklist to prevent database bloat.
 * 
 * This implementation uses a database to store blacklisted tokens, allowing for persistence across
 * application restarts and supporting clustered deployments with multiple instances.
 */
@Service
public class TokenBlacklistService {

    private static final Logger logger = LoggerFactory.getLogger(TokenBlacklistService.class);

    /**
     * Repository for database operations on blacklisted tokens.
     */
    @Autowired
    private BlacklistedTokenRepository tokenRepository;

    /**
     * Adds a token to the blacklist.
     * 
     * @param jti The JSON Token ID of the token to blacklist
     * @param expiryDate The expiration date of the token
     */
    @Transactional
    public void blacklistToken(String jti, Date expiryDate) {
        BlacklistedToken token = new BlacklistedToken();
        token.setJti(jti);
        token.setExpiryDate(expiryDate);
        tokenRepository.save(token);
        logger.debug("Token with JTI {} blacklisted until {}", jti, expiryDate);
    }

    /**
     * Checks if a token is blacklisted.
     * 
     * @param jti The JSON Token ID to check
     * @return true if the token is blacklisted, false otherwise
     */
    public boolean isBlacklisted(String jti) {
        return tokenRepository.existsByJti(jti);
    }

    /**
     * Scheduled task that removes expired tokens from the blacklist. Runs automatically every hour
     * to keep the blacklist table clean.
     */
    @Scheduled(fixedRate = 3600000) // 1 hour in milliseconds
    @Transactional
    public void cleanupExpiredTokens() {
        Date now = new Date();
        int deletedCount = tokenRepository.deleteExpiredTokens(now);
        if (deletedCount > 0) {
            logger.info("Removed {} expired tokens from the blacklist", deletedCount);
        }
    }
}
