package com.dinkybell.ecommerce.authentication.util;

import lombok.extern.slf4j.Slf4j;
import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.service.TokenBlacklistService;
import com.dinkybell.ecommerce.authentication.service.JwtKeyProvider;
import lombok.RequiredArgsConstructor;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Utility class for JSON Web Token (JWT) operations.
 * 
 * This class handles JWT generation, validation, and parsing using the RS256 algorithm with
 * public/private key pairs for enhanced security. It manages token claims including: - Subject
 * (user email) - User ID - Roles - Issuer (dinkybell-app) - Issued at timestamp - Expiration
 * timestamp - JTI (unique token identifier)
 * 
 * The implementation uses 2048-bit RSA keys that are generated on application startup.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtUtil {    

    /** Token expiration time in milliseconds, loaded from application properties */
    @Value("${jwt.access-token.expiration}")
    private long expirationTime;     
    
    // Inject the JwtKeyProvider to access the RSA key pair for signing and verifying tokens
    private final JwtKeyProvider keyProvider;  
    
    // Inject the TokenBlacklistService to check if a token has been revoked (e.g., on logout)
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Generates a JWT token for the authenticated user.
     * 
     * Creates a token with the following claims: - sub: user email (subject) - userId: user's
     * unique identifier - roles: user's role or permissions - iat: issued at timestamp - exp:
     * expiration timestamp - iss: issuer (dinkybell-app) - jti: unique token ID
     * 
     * The token is signed using RS256 algorithm with the private key.
     * 
     * @param user The authenticated user entity
     * @return JWT token string
     */
    public String generateToken(UserAuthentication user) {
        
        return Jwts.builder().setSubject(user.getEmail()).claim("userId", user.getId()) // Include user ID for easy identification
                .claim("roles", user.getRole()) // Include roles for authorization checks
                .setIssuedAt(new Date()) // Token creation time
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime)) // Token expiry
                .setIssuer("dinkybell-app") // Application identifier
                .setId(UUID.randomUUID().toString()) // Unique token identifier
                .signWith(keyProvider.getPrivateKey(), SignatureAlgorithm.RS256) // Sign with RS256
                .compact();

    }

    /**
     * Extracts the user's email from the JWT token.
     * 
     * @param token The JWT token string
     * @return The user's email address (subject claim)
     * @throws io.jsonwebtoken.JwtException if token is invalid or malformed
     */
    public String extractEmail(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(keyProvider.getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();

    }

    /**
     * Extracts the expiration date from the JWT token.
     * 
     * @param token The JWT token string
     * @return The token's expiration date
     * @throws io.jsonwebtoken.JwtException if token is invalid or malformed
     */
    public Date extractExpirationDate(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(keyProvider.getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();

    }    

    /**
     * Validates a JWT token by checking signature, expiration, matching email, and ensuring it's
     * not in the blacklist.
     * 
     * @param token The JWT token string to validate
     * @param email The expected email (subject) in the token
     * @return true if the token is valid, false otherwise
     */
    public boolean validateToken(String token, String email) {

        try {            
            if (tokenBlacklistService.isBlacklisted(extractJti(token))) {
                return false;
            }
            return (extractEmail(token).equals(email) && !isTokenExpired(token));
        } catch (io.jsonwebtoken.security.SignatureException e) {
            log.warn("JWT signature validation failed in validateToken: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks if a JWT token has expired.
     * 
     * @param token The JWT token string
     * @return true if the token has expired, false otherwise
     */
    public boolean isTokenExpired(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(keyProvider.getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
            //return expiration.before(new Date());
            return false; // Valid token not expired
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            // Token is expired
            Date expiration = e.getClaims().getExpiration();
            long diffMillis = new Date().getTime() - expiration.getTime();
            log.debug("JWT expired at {}, current time: {}, difference: {} milliseconds ({} minutes)", 
                     expiration, new Date(), diffMillis, diffMillis / 60000);
            return true;
        } catch (io.jsonwebtoken.security.SignatureException e) {
            // Token signature is invalid (likely due to app restart with new keys)
            log.warn("JWT signature validation failed - token was likely signed with a different key: {}", e.getMessage());
            return true;
        } catch (Exception e) {
            // If any exception occurs during parsing, consider the token expired
            log.error("Error validating JWT token", e);
            return true;
        }
    }

    /**
     * Extracts all claims from a JWT token.
     * 
     * @param token The JWT token string
     * @return Claims object containing all token claims
     * @throws io.jsonwebtoken.JwtException if token is invalid or malformed
     */
    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(keyProvider.getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody();                
    }

    /**
     * Extracts the JWT ID (jti) from the token.
     * 
     * The JTI is a unique identifier for the token that can be used for token revocation.
     * 
     * @param token The JWT token string
     * @return The JWT ID claim value
     * @throws io.jsonwebtoken.JwtException if token is invalid or malformed
     */
    public String extractJti(String token) {
        return getAllClaimsFromToken(token).getId();
    }    

}
