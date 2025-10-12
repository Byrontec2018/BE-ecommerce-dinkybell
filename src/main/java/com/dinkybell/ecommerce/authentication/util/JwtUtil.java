package com.dinkybell.ecommerce.authentication.util;

import lombok.extern.slf4j.Slf4j;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Date;
import java.util.UUID;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.service.TokenBlacklistService;
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

    /** The RSA key pair used for JWT signing and validation */
    private KeyPair keyPair;

    /** Token expiration time in milliseconds, loaded from application properties */
    @Value("${jwt.access-token.expiration}")
    private long expirationTime;
    
    /** Keystore configuration properties */
    @Value("${jwt.keystore.path}")
    private String keystorePath;
    
    @Value("${jwt.keystore.password}")
    private String keystorePassword;
    
    @Value("${jwt.keystore.alias}")
    private String keyAlias;
    
    @Value("${jwt.keystore.type}")
    private String keystoreType;

    /**
     * Initializes the RSA key pair for JWT operations using persistent keystore.
     * This method is called automatically after dependency injection.
     * 
     * If keystore exists, loads the existing key pair. Otherwise, generates a new
     * key pair and saves it to the keystore for future use.
     * 
     * @throws RuntimeException if keystore operations fail
     */
    @PostConstruct
    public void init() {
        try {
            Path keystoreFilePath = Paths.get(keystorePath);
            
            if (Files.exists(keystoreFilePath)) {
                log.info("Loading existing JWT keystore from: {}", keystorePath);
                this.keyPair = loadKeyPairFromKeystore();
            } else {
                log.info("Creating new JWT keystore at: {}", keystorePath);
                this.keyPair = generateAndSaveKeyPair();
            }
            
            log.info("JWT keystore initialized successfully");
            
        } catch (Exception e) {
            log.error("Failed to initialize JWT keystore: {}", e.getMessage());
            // Fallback to in-memory key generation for development
            try {
                log.warn("Falling back to in-memory key generation");
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                this.keyPair = keyPairGenerator.generateKeyPair();
            } catch (NoSuchAlgorithmException fallbackException) {
                throw new RuntimeException("Failed to initialize JWT keys even with fallback", fallbackException);
            }
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
        return Jwts.builder().setSubject(user.getEmail()).claim("userId", user.getId()) // Include user ID for easy identification
                .claim("roles", user.getRole()) // Include roles for authorization checks
                .setIssuedAt(new Date()) // Token creation time
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime)) // Token expiry
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
        return Jwts.parserBuilder()
                .setSigningKey(getPublicKey())
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
                .setSigningKey(getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
    }

    private final TokenBlacklistService tokenBlacklistService;

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
                .setSigningKey(getPublicKey())
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

    /**
     * Loads an existing key pair from the JCEKS keystore file.
     * 
     * @return KeyPair if successfully loaded, null otherwise
     */
    private KeyPair loadKeyPairFromKeystore() throws Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keyStore.load(fis, keystorePassword.toCharArray());
            }
            
            // Load private key (stored as SecretKeySpec)
            SecretKeySpec privateKeySpec = (SecretKeySpec) keyStore.getKey(keyAlias + "_private", 
                                                                          keystorePassword.toCharArray());
            if (privateKeySpec == null) {
                log.error("Private key not found in keystore");
                return null;
            }
            
            // Load public key (stored as SecretKeySpec)
            SecretKeySpec publicKeySpec = (SecretKeySpec) keyStore.getKey(keyAlias + "_public", 
                                                                         keystorePassword.toCharArray());
            if (publicKeySpec == null) {
                log.error("Public key not found in keystore");
                return null;
            }
            
            // Reconstruct keys from encoded bytes
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            // Reconstruct private key
            java.security.spec.PKCS8EncodedKeySpec privateKeySpecPKCS8 = 
                new java.security.spec.PKCS8EncodedKeySpec(privateKeySpec.getEncoded());
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpecPKCS8);
            
            // Reconstruct public key
            X509EncodedKeySpec publicKeySpecX509 = 
                new X509EncodedKeySpec(publicKeySpec.getEncoded());
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpecX509);
            
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            log.error("Failed to load JCEKS keystore: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Generates a new RSA key pair and saves it to a simplified keystore.
     * 
     * @return The generated RSA key pair
     * @throws Exception if key generation or keystore saving fails
     */
    private KeyPair generateAndSaveKeyPair() throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // For development, we'll save keys in a simple format
        // In production, use proper certificate-based keystore
        saveKeyPairSimple(keyPair);
        
        return keyPair;
    }

    /**
     * Saves a key pair to the keystore with simplified approach for development.
     * Uses JCEKS keystore to store both keys as SecretKeySpec entries.
     * 
     * @param keyPair the key pair to save
     * @throws Exception if keystore operations fail
     */
    private void saveKeyPairSimple(KeyPair keyPair) throws Exception {
        // Create parent directories if they don't exist
        Path keystoreFilePath = Paths.get(keystorePath);
        if (keystoreFilePath.getParent() != null) {
            Files.createDirectories(keystoreFilePath.getParent());
        }
        
        // JCEKS can store raw SecretKey directly
        log.info("Note: Using JCEKS keystore for development (stores keys as secret entries)");
        
        // Use JCEKS format which can store secret keys
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(null, null); // Initialize empty keystore
        
        // Store both keys as SecretKeySpec entries to avoid certificate requirements
        SecretKeySpec privateKeySpec = new SecretKeySpec(
            keyPair.getPrivate().getEncoded(), "RSA");
        keyStore.setKeyEntry(keyAlias + "_private", privateKeySpec, 
                           keystorePassword.toCharArray(), null);
        
        SecretKeySpec publicKeySpec = new SecretKeySpec(
            keyPair.getPublic().getEncoded(), "RSA");
        keyStore.setKeyEntry(keyAlias + "_public", publicKeySpec, 
                           keystorePassword.toCharArray(), null);
        
        // Save the keystore to disk
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, keystorePassword.toCharArray());
        }
        
        log.info("JCEKS keystore created at: {}", keystorePath);
    }

}
