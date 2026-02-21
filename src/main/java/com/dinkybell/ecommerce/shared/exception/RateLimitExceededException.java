package com.dinkybell.ecommerce.shared.exception;

import lombok.Getter;

/**
 * Exception thrown when a rate limit is exceeded.
 * 
 * This exception is thrown by the custom rate limiting aspect when a user
 * exceeds the configured request limit for a specific operation. It includes
 * metadata about the rate limit violation such as the limiter name, time to
 * reset, and maximum allowed requests.
 */
@Getter
public class RateLimitExceededException extends RuntimeException {

    private final String limiterName;
    private final long retryAfterSeconds;
    private final int maxRequests;

    /**
     * Constructs a new RateLimitExceededException.
     *
     * @param limiterName The name of the rate limiter that was exceeded
     * @param retryAfterSeconds Number of seconds until the rate limit resets
     * @param maxRequests Maximum number of requests allowed in the time window
     */
    public RateLimitExceededException(String limiterName, long retryAfterSeconds, int maxRequests) {
        super(String.format("Rate limit exceeded for '%s'. Max %d requests allowed. Retry after %d seconds.", 
                           limiterName, maxRequests, retryAfterSeconds));
        this.limiterName = limiterName;
        this.retryAfterSeconds = retryAfterSeconds;
        this.maxRequests = maxRequests;
    }

    /**
     * Constructs a new RateLimitExceededException with a custom message.
     *
     * @param message Custom error message
     * @param limiterName The name of the rate limiter that was exceeded
     * @param retryAfterSeconds Number of seconds until the rate limit resets
     * @param maxRequests Maximum number of requests allowed in the time window
     */
    public RateLimitExceededException(String message, String limiterName, long retryAfterSeconds, int maxRequests) {
        super(message);
        this.limiterName = limiterName;
        this.retryAfterSeconds = retryAfterSeconds;
        this.maxRequests = maxRequests;
    }
}
