package com.dinkybell.ecommerce.shared.config;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

/**
 * Custom Redis-based rate limiting service that works with Resilience4j.
 * This service handles Redis storage and management for rate limiting counters.
 * 
 * The service provides methods to check if a request is allowed, manage counters,
 * track time windows, and retrieve rate limiting information. It uses a Redis
 * key-value store with expiration for efficient and distributed rate limiting.
 * 
 * The implementation is resilient to Redis failures, falling back to allowing
 * requests if the Redis service is unavailable.
 */
@Service
@Slf4j
public class CustomRedisRateLimitService {
    private static final String RATE_LIMIT_PREFIX = "rate_limit:";
    
    private final RedisTemplate<String, String> redisTemplate;

    public CustomRedisRateLimitService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Checks if a request is allowed based on the rate limiting configuration.
     * 
     * This method performs the following operations:
     * 1. Constructs a Redis key using the provided identifier
     * 2. Retrieves the current count for this key
     * 3. Checks if the count exceeds the configured maximum
     * 4. If allowed, increments the counter and sets/extends expiry
     * 5. Returns whether the request should proceed
     * 
     * If Redis is unavailable, the method logs the error and allows the request
     * to proceed (fail-open approach).
     * 
     * @param key The rate limiting key (includes IP/user identification)
     * @param maxRequests Maximum number of requests allowed in the time window
     * @param windowSeconds Time window duration in seconds
     * @return true if request is allowed, false if rate limit exceeded
     */
    public boolean isAllowed(String key, int maxRequests, int windowSeconds) {
        try {
            String redisKey = RATE_LIMIT_PREFIX + key;
            
            // Get current count
            String currentCountStr = redisTemplate.opsForValue().get(redisKey);
            int currentCount = currentCountStr != null ? Integer.parseInt(currentCountStr) : 0;
            
            if (currentCount >= maxRequests) {
                log.warn("Rate limit exceeded for key: {}, current count: {}, max: {}", 
                           key, currentCount, maxRequests);
                return false;
            }
            
            // Increment counter
            if (currentCount == 0) {
                // First request in window - set with expiration
                redisTemplate.opsForValue().set(redisKey, "1", Duration.ofSeconds(windowSeconds));
            } else {
                // Increment existing counter
                redisTemplate.opsForValue().increment(redisKey);
                
                // Ensure expiration is set (defensive programming)
                Long ttl = redisTemplate.getExpire(redisKey);
                if (ttl == null || ttl == -1) {
                    redisTemplate.expire(redisKey, Duration.ofSeconds(windowSeconds));
                }
            }
            
            log.debug("Rate limit check passed for key: {}, count: {}/{}", 
                        key, currentCount + 1, maxRequests);
            return true;
            
        } catch (Exception e) {
            log.error("Error checking rate limit for key: {}", key, e);
            // Fail open - allow request if Redis is down
            return true;
        }
    }

    /**
     * Gets the current count for a rate limiting key.
     */
    public int getCurrentCount(String key) {
        try {
            String redisKey = RATE_LIMIT_PREFIX + key;
            String currentCountStr = redisTemplate.opsForValue().get(redisKey);
            return currentCountStr != null ? Integer.parseInt(currentCountStr) : 0;
        } catch (Exception e) {
            log.error("Error getting current count for key: {}", key, e);
            return 0;
        }
    }

    /**
     * Gets the remaining time until the rate limit window resets.
     */
    public long getTimeToReset(String key) {
        try {
            String redisKey = RATE_LIMIT_PREFIX + key;
            Long ttl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
            return ttl != null && ttl > 0 ? ttl : 0;
        } catch (Exception e) {
            log.error("Error getting TTL for key: {}", key, e);
            return 0;
        }
    }

    /**
     * Manually resets the rate limit for a given key.
     */
    public void resetLimit(String key) {
        try {
            String redisKey = RATE_LIMIT_PREFIX + key;
            redisTemplate.delete(redisKey);
            log.info("Rate limit reset for key: {}", key);
        } catch (Exception e) {
            log.error("Error resetting rate limit for key: {}", key, e);
        }
    }
}
