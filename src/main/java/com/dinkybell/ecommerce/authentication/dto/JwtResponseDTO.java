package com.dinkybell.ecommerce.authentication.dto;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Data Transfer Object for JWT authentication response.
 * 
 * This DTO encapsulates the JWT token and related information that is returned to the client after
 * successful authentication. It includes the access token, refresh token, token type (Bearer), 
 * the authenticated user's email, and the token's expiration time.
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class JwtResponseDTO {
    /**
     * The JWT token string to be used for authentication (access token).
     */
    private String token;
    
    /**
     * The refresh token used to obtain new access tokens when they expire.
     */
    private String refreshToken;

    /**
     * The token type, which is always "Bearer" for JWT authentication.
     */
    private String type = "Bearer";

    /**
     * The email address of the authenticated user.
     */
    private String email;

    /**
     * The expiration time of the token.
     */
    private LocalDateTime expirationTime;

    /**
     * Constructor that converts a Date expiration to LocalDateTime.
     * 
     * @param token The JWT token string
     * @param refreshToken The refresh token string
     * @param email The user's email address
     * @param expiration The token expiration as a Date object
     */
    public JwtResponseDTO(String token, String refreshToken, String email, Date expiration) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.email = email;
        this.expirationTime =
                LocalDateTime.ofInstant(expiration.toInstant(), 
                ZoneId.systemDefault()
            );

    }
    
    /**
     * Constructor that converts a Date expiration to LocalDateTime without refresh token.
     * 
     * @param token The JWT token string
     * @param email The user's email address
     * @param expiration The token expiration as a Date object
     */
    public JwtResponseDTO(String token, String email, Date expiration) {
        this.token = token;
        this.email = email;
        this.expirationTime =
                LocalDateTime.ofInstant(expiration.toInstant(), 
                ZoneId.systemDefault()
            );    
            
    }

}
