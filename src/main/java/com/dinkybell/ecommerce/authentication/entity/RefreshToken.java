package com.dinkybell.ecommerce.authentication.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Entity representing refresh tokens for JWT authentication.
 * 
 * This entity stores refresh tokens that allow users to request new access tokens
 * without re-authenticating. Each token is associated with a specific user and device,
 * has an expiry date, and can be revoked.
 * 
 * Rather than using a direct entity relationship with @ManyToOne, this implementation
 * uses a simple user_id reference for better performance and to avoid lazy loading issues.
 */
@Entity
@Table(name = "refresh_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    
    /**
     * The unique identifier for the refresh token.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    /**
     * The token value itself, which must be unique.
     */
    @Column(nullable = false, unique = true, length = 255)
    private String token;
    
    /**
     * The ID of the user this token belongs to.
     */
    @Column(name = "user_id", nullable = false)
    private Long userId;
    
    /**
     * When this token expires.
     */
    @Column(nullable = false)
    private Instant expiryDate;
    
    /**
     * Information about the device/browser that was used to generate this token.
     * Useful for security auditing and the "Your Sessions" feature.
     */
    @Column(nullable = false, length = 512)
    private String deviceInfo;
    
    /**
     * Whether this token has been manually revoked.
     * Revoked tokens are invalid even if they haven't expired yet.
     */
    @Column(nullable = false)
    private boolean revoked = false;
    
    /**
     * When this token was created.
     */
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    
    /**
     * When this token was last used to refresh an access token.
     */
    @Column(name = "last_used_at")
    private Instant lastUsedAt;
}
