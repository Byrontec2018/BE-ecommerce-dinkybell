package com.auth_service.shared.config;

/**
 * Security constants for public endpoints that don't require JWT authentication.
 * 
 * This class centralizes all public paths to ensure consistency between
 * SecurityConfig (authorization rules) and JwtAuthFilter (which paths to skip filtering).
 * 
 * By maintaining a single source of truth, we prevent bugs that occur when
 * paths are added in one place but forgotten in the other.
 */
public final class SecurityConstants {

    private SecurityConstants() {
        // Prevent instantiation
    }

    /**
     * Array of all public endpoint patterns that don't require JWT authentication.
     * 
     * These patterns should match exactly in:
     * - SecurityConfig.filterChain() for authorization rules
     * - JwtAuthFilter.shouldNotFilter() for filter bypass logic
     */
    public static final String[] PUBLIC_PATHS = {
        "/api/v1/auth/**",
        "/api/v1/public/**",
        "/actuator/health",
        "/swagger-ui.html",
        "/swagger-ui/**",
        "/v3/api-docs",
        "/v3/api-docs/**",
        "/v3/api-docs.yaml",
        "/users/public"
    };
}
