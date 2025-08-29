package com.dinkybell.ecommerce.configurations;

import java.lang.reflect.Method;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.dinkybell.ecommerce.services.CustomRedisRateLimitService;

import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;

/**
 * Custom aspect that replaces Resilience4j's default RateLimiter behaviour
 * with our Redis-based rate limiting implementation using custom key resolution.
 * 
 * This aspect intercepts all methods annotated with @RateLimiter and applies
 * IP-based and user-based rate limiting using Redis for persistence.
 * The implementation supports different limits for different operations and
 * provides fallback methods when limits are exceeded.
 */
@Aspect
@Component
public class CustomRateLimiterAspect {

    private static final Logger logger = LoggerFactory.getLogger(CustomRateLimiterAspect.class);
    
    private final CustomRedisRateLimitService rateLimitService;
    
    // Rate limiting configurations from application.properties
    @Value("${resilience4j.ratelimiter.instances.login.limitForPeriod:3}")
    private int loginLimitForPeriod;
    
    @Value("${resilience4j.ratelimiter.instances.login.limitRefreshPeriod:300s}")
    private String loginLimitRefreshPeriod;
    
    @Value("${resilience4j.ratelimiter.instances.register.limitForPeriod:2}")
    private int registerLimitForPeriod;
    
    @Value("${resilience4j.ratelimiter.instances.register.limitRefreshPeriod:600s}")
    private String registerLimitRefreshPeriod;
    
    @Value("${resilience4j.ratelimiter.instances.resetPassword.limitForPeriod:1}")
    private int resetPasswordLimitForPeriod;
    
    @Value("${resilience4j.ratelimiter.instances.resetPassword.limitRefreshPeriod:900s}")
    private String resetPasswordLimitRefreshPeriod;
    
    @Value("${resilience4j.ratelimiter.instances.confirmResetPassword.limitForPeriod:2}")
    private int confirmResetPasswordLimitForPeriod;
    
    @Value("${resilience4j.ratelimiter.instances.confirmResetPassword.limitRefreshPeriod:600s}")
    private String confirmResetPasswordLimitRefreshPeriod;

    public CustomRateLimiterAspect(CustomRedisRateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    /**
     * Intercepts methods annotated with @RateLimiter and applies custom Redis-based rate limiting.
     * 
     * This method is the core of the rate limiting functionality. It:
     * 1. Extracts the limiter name and fallback method from the annotation
     * 2. Generates a custom key using IP or username
     * 3. Retrieves the rate limiting configuration for the operation
     * 4. Checks if the request is allowed using Redis
     * 5. Either proceeds with the original method or calls the fallback
     *
     * @param joinPoint The join point representing the intercepted method
     * @param rateLimiterAnnotation The annotation instance with configuration
     * @return The result of the original method or fallback method
     * @throws Throwable If an error occurs during processing
     */
    @Around("@annotation(rateLimiterAnnotation)")
    public Object handleRateLimiting(ProceedingJoinPoint joinPoint, 
                                   RateLimiter rateLimiterAnnotation) throws Throwable {
        
        String limiterName = rateLimiterAnnotation.name();
        String fallbackMethod = rateLimiterAnnotation.fallbackMethod();
        
        logger.debug("Applying custom rate limiting for: {}", limiterName);
        
        // Generate custom key based on IP/user
        String customKey = RateLimiterKeyConfig.resolveKey(limiterName);
        logger.debug("Using rate limiting key: {}", customKey);
        
        // Get rate limiting configuration for this limiter
        RateLimitConfig config = getRateLimitConfig(limiterName);
        
        // Check if request is allowed using Redis
        boolean allowed = rateLimitService.isAllowed(customKey, config.getMaxRequests(), config.getWindowSeconds());
        
        if (!allowed) {
            logger.warn("Rate limit exceeded for key: {} on limiter: {}", customKey, limiterName);
            
            // Create RequestNotPermitted exception for fallback method
            RequestNotPermitted ex = RequestNotPermitted.createRequestNotPermitted(null);
            
            // Call the fallback method if specified
            if (!fallbackMethod.isEmpty()) {
                return invokeFallbackMethod(joinPoint, fallbackMethod, ex);
            }
            
            // If no fallback method, throw exception
            throw ex;
        }
        
        // Request allowed, proceed with normal execution
        return joinPoint.proceed();
    }
    
    /**
     * Gets rate limiting configuration based on limiter name.
     */
    private RateLimitConfig getRateLimitConfig(String limiterName) {
        switch (limiterName) {
            case "login":
                return new RateLimitConfig(loginLimitForPeriod, parseSeconds(loginLimitRefreshPeriod));
            case "register":
                return new RateLimitConfig(registerLimitForPeriod, parseSeconds(registerLimitRefreshPeriod));
            case "resetPassword":
                return new RateLimitConfig(resetPasswordLimitForPeriod, parseSeconds(resetPasswordLimitRefreshPeriod));
            case "confirmResetPassword":
                return new RateLimitConfig(confirmResetPasswordLimitForPeriod, parseSeconds(confirmResetPasswordLimitRefreshPeriod));
            default:
                logger.warn("Unknown limiter name: {}, using default config", limiterName);
                return new RateLimitConfig(10, 60); // Default: 10 requests per minute
        }
    }
    
    /**
     * Parses duration string (e.g., "300s") to seconds.
     */
    private int parseSeconds(String durationStr) {
        if (durationStr.endsWith("s")) {
            return Integer.parseInt(durationStr.substring(0, durationStr.length() - 1));
        }
        return Integer.parseInt(durationStr);
    }
    
    /**
     * Invokes the fallback method when rate limit is exceeded.
     */
    private Object invokeFallbackMethod(ProceedingJoinPoint joinPoint, String fallbackMethodName, RequestNotPermitted ex) {
        try {
            Object target = joinPoint.getTarget();
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            Method originalMethod = signature.getMethod();
            
            // Find fallback method with same parameters plus RequestNotPermitted
            Class<?>[] parameterTypes = originalMethod.getParameterTypes();
            Class<?>[] fallbackParameterTypes = new Class[parameterTypes.length + 1];
            System.arraycopy(parameterTypes, 0, fallbackParameterTypes, 0, parameterTypes.length);
            fallbackParameterTypes[parameterTypes.length] = RequestNotPermitted.class;
            
            Method fallbackMethod = target.getClass().getMethod(fallbackMethodName, fallbackParameterTypes);
            
            // Prepare arguments for fallback method
            Object[] args = joinPoint.getArgs();
            Object[] fallbackArgs = new Object[args.length + 1];
            System.arraycopy(args, 0, fallbackArgs, 0, args.length);
            fallbackArgs[args.length] = ex;
            
            logger.debug("Invoking fallback method: {}", fallbackMethodName);
            return fallbackMethod.invoke(target, fallbackArgs);
            
        } catch (Exception e) {
            logger.error("Failed to invoke fallback method: {}", fallbackMethodName, e);
            throw new RuntimeException("Rate limit exceeded and fallback method failed", e);
        }
    }
    
    /**
     * Simple configuration class for rate limiting parameters.
     */
    private static class RateLimitConfig {
        private final int maxRequests;
        private final int windowSeconds;
        
        public RateLimitConfig(int maxRequests, int windowSeconds) {
            this.maxRequests = maxRequests;
            this.windowSeconds = windowSeconds;
        }
        
        public int getMaxRequests() {
            return maxRequests;
        }
        
        public int getWindowSeconds() {
            return windowSeconds;
        }
    }
}
