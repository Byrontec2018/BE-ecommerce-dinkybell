package com.dinkybell.ecommerce.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Data Transfer Object for refresh token requests.
 * 
 * Used for endpoints that require a refresh token as input:
 * - Token refresh
 * - Token revocation
 * - Other session revocation
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TokenRequestDTO {
    
    @NotBlank(message = "Token is required")
    private String token;
    
}