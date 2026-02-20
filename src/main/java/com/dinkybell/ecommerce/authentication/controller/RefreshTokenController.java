package com.dinkybell.ecommerce.authentication.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.dinkybell.ecommerce.authentication.exception.RefreshTokenException;
import com.dinkybell.ecommerce.authentication.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;

/**
 * REST Controller for refresh token operations.
 * 
 * This controller handles:
 * - Token refresh requests
 * - Token revocation (logout from current device)
 * - Revoking other sessions (logout from all other devices)
 * 
 * All endpoints follow OAuth 2.0 RFC 6750 standard, receiving refresh tokens
 * via Authorization header (Bearer token format).
 * 
 * All endpoints are rate-limited to prevent abuse.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class RefreshTokenController {
    
    private final RefreshTokenService refreshTokenService;
    
    /**
     * Refreshes an access token using a valid refresh token via Authorization header.
     * Follows OAuth 2.0 RFC 6750 standard.
     * Rate limited to prevent token refresh abuse.
     * 
     * @param authHeader The Authorization header containing "Bearer <token>"
     * @return ResponseEntity with APIResponseDTO containing new access token
     * @throws RefreshTokenException if the refresh token is invalid or expired
     */
    @RateLimiter(name = "refreshToken")
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestHeader(name = "Authorization", required = false) String refreshToken) {       
        return refreshTokenService.refreshAccessToken(refreshToken);
    }
    
    /**
     * Revokes a refresh token, effectively logging out from the current device.
     * Reads token from Authorization header following OAuth 2.0 standard.
     * Rate limited to prevent abuse of token revocation.
     * 
     * @param authHeader The Authorization header containing "Bearer <token>"
     * @return ResponseEntity with success message or error handled by GlobalExceptionHandler
     * @throws RefreshTokenException if the refresh token is invalid
     */
    @RateLimiter(name = "revokeToken")
    @PostMapping("/revoke-token")
    public ResponseEntity<?> revokeToken(@RequestHeader(name = "Authorization", required = false) String refreshToken) {        
        return refreshTokenService.revokeRefreshToken(refreshToken);
    }
    
    /**
     * Revokes all other refresh tokens for the user, keeping only the current session active.
     * This implements "log out from all other devices" functionality.
     * Reads token from Authorization header following OAuth 2.0 standard.
     * Rate limited to prevent abuse of session management.
     * 
     * @param refreshToken The Authorization header containing "Bearer <token>"
     * @return ResponseEntity with success message or error handled by GlobalExceptionHandler
     * @throws RefreshTokenException if the refresh token is invalid
     */
    @RateLimiter(name = "revokeOtherSessions")
    @PostMapping("/revoke-other-sessions")
    public ResponseEntity<?> revokeOtherSessions(@RequestHeader(name = "Authorization", required = false) String refreshToken) {
        log.info("Revoking other sessions with token: {}", refreshToken);
        return refreshTokenService.revokeOtherTokens(refreshToken);
    }

    
}