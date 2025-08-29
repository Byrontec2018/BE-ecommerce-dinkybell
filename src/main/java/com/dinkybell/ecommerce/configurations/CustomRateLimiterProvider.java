package com.dinkybell.ecommerce.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;

/**
 * Configuration class that creates custom rate limiters with our key resolver.
 * 
 * This provider creates and registers bean instances of Resilience4j RateLimiter
 * for each secured operation (login, registration, password reset, etc.). The beans
 * are configured with parameters from application.yml and registered in Spring's
 * application context.
 * 
 * These RateLimiter instances are used by the Spring AOP infrastructure to identify
 * rate-limited methods and apply the appropriate configuration.
 * 
 * Each rate limiter is instantiated with a specific name that corresponds to
 * configuration in application.yml and is referenced in @RateLimiter annotations.
 */
@Configuration
public class CustomRateLimiterProvider {

    private final RateLimiterRegistry rateLimiterRegistry;

    public CustomRateLimiterProvider(RateLimiterRegistry rateLimiterRegistry) {
        this.rateLimiterRegistry = rateLimiterRegistry;
    }

    /**
     * Creates a rate limiter for login operations with custom key resolution.
     * 
     * This bean is configured with the 'login' rate limiting parameters from application.yml:
     * - limitForPeriod: Maximum allowed login attempts in a time window
     * - limitRefreshPeriod: Duration of the time window (typically 300s/5 minutes)
     * 
     * @return Configured RateLimiter instance for login operations
     */
    @Bean
    public RateLimiter loginRateLimiter() {
        return rateLimiterRegistry.rateLimiter("login");
    }

    /**
     * Creates a rate limiter for registration operations with custom key resolution.
     */
    @Bean 
    public RateLimiter registerRateLimiter() {
        return rateLimiterRegistry.rateLimiter("register");
    }

    /**
     * Creates a rate limiter for password reset operations with custom key resolution.
     */
    @Bean
    public RateLimiter resetPasswordRateLimiter() {
        return rateLimiterRegistry.rateLimiter("resetPassword");
    }

    /**
     * Creates a rate limiter for password reset confirmation operations with custom key resolution.
     */
    @Bean
    public RateLimiter confirmResetPasswordRateLimiter() {
        return rateLimiterRegistry.rateLimiter("confirmResetPassword");
    }
}
