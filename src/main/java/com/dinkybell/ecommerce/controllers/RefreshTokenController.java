package com.dinkybell.ecommerce.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.dinkybell.ecommerce.dtos.RefreshTokenRequestDTO;
import com.dinkybell.ecommerce.exceptions.RefreshTokenException;
import com.dinkybell.ecommerce.services.RefreshTokenService;

import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

/**
 * REST Controller for refresh token operations.
 * 
 * This controller handles:
 * - Token refresh requests
 * - Token revocation (logout from current device)
 * - Revoking other sessions (logout from all other devices)
 * 
 * All endpoints are rate-limited to prevent abuse.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class RefreshTokenController {
    
    @Autowired
    private RefreshTokenService refreshTokenService;
    
    /**
     * Refreshes an access token using a valid refresh token.
     * Rate limited to prevent token refresh abuse.
     * 
     * @param request The refresh token request containing the token
     * @param httpRequest The HTTP request for device tracking
     * @return ResponseEntity with new access token or error message
     */
    @RateLimiter(name = "refreshToken", fallbackMethod = "refreshTokenFallback")
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO request,
                                        HttpServletRequest httpRequest) {
        try {
            return refreshTokenService.refreshAccessToken(request.getRefreshToken(), httpRequest);
        } catch (RefreshTokenException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    
    /**
     * Revokes a refresh token, effectively logging out from the current device.
     * 
     * @param request The refresh token request containing the token to revoke
     * @return ResponseEntity with success message or error
     */
    @PostMapping("/revoke-token")
    public ResponseEntity<?> revokeToken(@Valid @RequestBody RefreshTokenRequestDTO request) {
        try {
            refreshTokenService.revokeRefreshToken(request.getRefreshToken());
            return ResponseEntity.ok("Token successfully revoked");
        } catch (RefreshTokenException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    
    /**
     * Revokes all other refresh tokens for the user, keeping only the current session active.
     * This implements "log out from all other devices" functionality.
     * 
     * @param request The refresh token request containing the current token to keep
     * @return ResponseEntity with success message or error
     */
    @PostMapping("/revoke-other-sessions")
    public ResponseEntity<?> revokeOtherSessions(@Valid @RequestBody RefreshTokenRequestDTO request) {
        try {
            refreshTokenService.revokeOtherTokens(request.getRefreshToken());
            return ResponseEntity.ok("Other sessions successfully revoked");
        } catch (RefreshTokenException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    
    /**
     * Fallback method for rate limiting on token refresh.
     * Called when too many refresh requests are made within the time window.
     * 
     * @param request The original refresh token request
     * @param httpRequest The HTTP request
     * @param ex The rate limiting exception
     * @return ResponseEntity with rate limiting error message
     */
    public ResponseEntity<?> refreshTokenFallback(RefreshTokenRequestDTO request, 
                                                HttpServletRequest httpRequest, 
                                                Exception ex) {
        return ResponseEntity.status(429)
            .body("Too many token refresh attempts. Please try again later.");
    }
}