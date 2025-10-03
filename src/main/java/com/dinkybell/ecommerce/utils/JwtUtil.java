package com.dinkybell.ecommerce.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.dinkybell.ecommerce.entities.UserAuthentication;
import com.dinkybell.ecommerce.services.TokenBlacklistService;
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
public class JwtUtil {

    /** The RSA key pair used for JWT signing and validation */
    private KeyPair keyPair;

    /** Token expiration time in milliseconds, loaded from application properties */
    @Value("${jwt.access-token.expiration}")
    private long expirationTime;

    /**
     * Initializes the RSA key pair for JWT operations. This method is called automatically after
     * dependency injection.
     * 
     * For production environments, consider loading keys from a secure keystore rather than
     * generating them on startup to maintain token validity across restarts.
     * 
     * @throws RuntimeException if key pair generation fails
     */
    @PostConstruct
    public void init() {
        try {
            // Generate a secure RSA key pair for JWT signing and verification
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // Use 2048 bits for strong security
            this.keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize JWT key pair", e);
        }
    }

    /**
     * Gets the private key used for signing JWTs.
     * 
     * @return RSA private key
     */
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    /**
     * Gets the public key used for validating JWT signatures.
     * 
     * @return RSA public key
     */
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

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
        return Jwts.builder().setSubject(user.getEmail()).claim("userId", user.getId()) // Include
                                                                                        // user ID
                                                                                        // for easy
                                                                                        // identification
                .claim("roles", user.getRole()) // Include roles for authorization checks
                .setIssuedAt(new Date()) // Token creation time
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime)) // Token
                                                                                      // expiry
                .setIssuer("dinkybell-app") // Application identifier
                .setId(UUID.randomUUID().toString()) // Unique token identifier
                .signWith(getPrivateKey(), SignatureAlgorithm.RS256) // Sign with RS256
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
        return Jwts.parserBuilder().setSigningKey(getPublicKey()).build().parseClaimsJws(token)
                .getBody().getSubject();
    }

    /**
     * Extracts the expiration date from the JWT token.
     * 
     * @param token The JWT token string
     * @return The token's expiration date
     * @throws io.jsonwebtoken.JwtException if token is invalid or malformed
     */
    public Date extractExpirationDate(String token) {
        return Jwts.parserBuilder().setSigningKey(getPublicKey()).build().parseClaimsJws(token)
                .getBody().getExpiration();
    }

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

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
            final String extractedEmail = extractEmail(token);
            final String jti = extractJti(token);

            // Check if token is blacklisted (was logged out)
            if (tokenBlacklistService.isBlacklisted(jti)) {
                return false;
            }

            return (extractedEmail.equals(email) && !isTokenExpired(token));
        } catch (Exception e) {
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
            final Date expiration = Jwts.parserBuilder().setSigningKey(getPublicKey()).build()
                    .parseClaimsJws(token).getBody().getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            // If any exception occurs during parsing, consider the token expired
            e.printStackTrace(); // Log the exception for debugging
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
        return Jwts.parserBuilder().setSigningKey(getPublicKey()).build().parseClaimsJws(token)
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
