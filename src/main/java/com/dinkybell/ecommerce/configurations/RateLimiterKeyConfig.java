package com.dinkybell.ecommerce.configurations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Configuration for custom rate limiter key resolution.
 * 
 * This class provides methods to generate unique keys for rate limiting based on:
 * - Operation type (login, registration, etc.)
 * - User identity (username for authenticated users)
 * - Client identity (IP address and User-Agent for anonymous users)
 * 
 * The key generation strategy ensures that rate limits are appropriately applied:
 * - Per user for authenticated users (preventing abuse of specific accounts)
 * - Per IP/browser for anonymous users (preventing distributed attacks)
 */
@Configuration
public class RateLimiterKeyConfig {

    private static final Logger logger = LoggerFactory.getLogger(RateLimiterKeyConfig.class);

    /**
     * Resolves the rate limiting key based on the current request context.
     * 
     * This method creates a composite key that consists of:
     * 1. The limiter name (e.g., "login", "register")
     * 2. User identity information:
     *    - For authenticated users: username
     *    - For anonymous users: IP address and User-Agent hash
     * 
     * The generated key follows these formats:
     * - Authenticated: "{limiterName}:user:{username}"
     * - Anonymous: "{limiterName}:ip:{clientIp}:ua:{userAgentHash}"
     * 
     * This approach ensures proper isolation between different rate-limited operations
     * whilst providing appropriate user identification.
     * 
     * @param limiterName The name of the rate limiter (e.g., "login", "register")
     * @return A unique key string for rate limiting
     */
    public static String resolveKey(String limiterName) {
        try {
            HttpServletRequest request = ((ServletRequestAttributes) 
                RequestContextHolder.currentRequestAttributes()).getRequest();
            
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            StringBuilder keyBuilder = new StringBuilder();
            keyBuilder.append(limiterName).append(":");
            
            if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
                // For authenticated users, use username
                keyBuilder.append("user:").append(auth.getName());
                logger.debug("Rate limiting key for authenticated user: {}", keyBuilder.toString());
            } else {
                // For anonymous users, use IP address + User-Agent hash for better identification
                String clientIp = getClientIp(request);
                String userAgent = request.getHeader("User-Agent");
                keyBuilder.append("ip:").append(clientIp);
                
                if (userAgent != null && !userAgent.isEmpty()) {
                    keyBuilder.append(":ua:").append(Math.abs(userAgent.hashCode()));
                }
                logger.debug("Rate limiting key for anonymous user: {}", keyBuilder.toString());
            }
            
            return keyBuilder.toString();
        } catch (Exception e) {
            // Fallback to simple limiter name if context is not available
            String fallbackKey = limiterName + ":fallback:" + System.currentTimeMillis();
            logger.warn("Could not resolve rate limiting key, using fallback: {}", fallbackKey, e);
            return fallbackKey;
        }
    }
    
    /**
     * Extracts client IP address from the request, considering proxy headers.
     */
    private static String getClientIp(HttpServletRequest request) {
        String[] headerCandidates = {
            "X-Forwarded-For",
            "Proxy-Client-IP", 
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR"
        };
        
        for (String header : headerCandidates) {
            String ipList = request.getHeader(header);
            if (ipList != null && !ipList.isEmpty() && !"unknown".equalsIgnoreCase(ipList)) {
                String ip = ipList.split(",")[0].trim();
                if (isValidIp(ip)) {
                    return ip;
                }
            }
        }
        
        return request.getRemoteAddr();
    }
    
    /**
     * Validates if an IP address is valid for rate limiting purposes.
     */
    private static boolean isValidIp(String ip) {
        return ip != null && !ip.isEmpty() && 
               !ip.equalsIgnoreCase("unknown") &&
               !ip.equalsIgnoreCase("0:0:0:0:0:0:0:1") && 
               !ip.equalsIgnoreCase("127.0.0.1");
    }
}
