package com.dinkybell.ecommerce.authentication.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object for refresh token requests.
 * 
 * Used for endpoints that require a refresh token as input:
 * - Token refresh
 * - Token revocation
 * - Other session revocation
 */
public class RefreshTokenRequestDTO {
    
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
    
    /**
     * Default constructor for serialization frameworks.
     */
    public RefreshTokenRequestDTO() {}
    
    /**
     * Constructor with refresh token.
     * 
     * @param refreshToken The refresh token string
     */
    public RefreshTokenRequestDTO(String refreshToken) {
        this.refreshToken = refreshToken;
    }
    
    /**
     * Gets the refresh token.
     * 
     * @return The refresh token string
     */
    public String getRefreshToken() {
        return refreshToken;
    }
    
    /**
     * Sets the refresh token.
     * 
     * @param refreshToken The refresh token string
     */
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}