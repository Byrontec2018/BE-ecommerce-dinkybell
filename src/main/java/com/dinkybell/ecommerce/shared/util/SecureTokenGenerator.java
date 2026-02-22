package com.dinkybell.ecommerce.shared.util;

import lombok.extern.slf4j.Slf4j;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for generating cryptographically secure random tokens.
 * 
 * This implementation follows OWASP recommendations and OAuth 2.0 RFC 6749 guidelines
 * for bearer token generation. It uses SecureRandom with Base64 URL-safe encoding
 * to produce tokens resistant to brute-force and timing attacks.
 * 
 * Token characteristics:
 * - 256 bits of entropy (vs. UUID's 122 bits)
 * - Cryptographically secure random generation
 * - URL-safe Base64 encoding (no +, /, or = padding)
 * - Timing attack resistant
 * 
 * Suitable for:
 * - Refresh tokens (long-lived, 30 days)
 * - Email confirmation tokens (short-lived, 5-15 minutes)
 * - Password reset tokens (short-lived, 15 minutes)
 * 
 * @author Dinkybell Development Team
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-10.10">RFC 6749 Section 10.10</a>
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html">OWASP Authentication Cheat Sheet</a>
 */
@Slf4j
public final class SecureTokenGenerator {

    /**
     * SecureRandom instance for cryptographically strong random number generation.
     * Thread-safe and reusable across multiple token generations.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Default token length in bytes (32 bytes = 256 bits of entropy).
     * This provides significantly more entropy than UUID v4 (122 bits).
     */
    private static final int DEFAULT_TOKEN_LENGTH = 32;

    /**
     * Base64 URL encoder without padding.
     * URL-safe variant replaces '+' with '-' and '/' with '_', and omits padding '='.
     */
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /**
     * Private constructor to prevent instantiation of utility class.
     * 
     * @throws UnsupportedOperationException if called via reflection
     */
    private SecureTokenGenerator() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Generates a cryptographically secure random token with default length (256 bits).
     * 
     * The token generation process:
     * 1. Creates a byte array of specified length (32 bytes)
     * 2. Fills it with cryptographically strong random bytes using SecureRandom
     * 3. Encodes the bytes to Base64 URL-safe format without padding
     * 
     * Output characteristics:
     * - Length: ~43 characters (for 32 bytes)
     * - Character set: [A-Za-z0-9_-]
     * - No padding characters (=)
     * - URL-safe (can be used in query parameters)
     * 
     * Example output: "xK7vG3mP9nR2wQ5jT8yL4hV6bN1cM0fD9sA7eZ3uY2k"
     * 
     * Security considerations:
     * - Uses SecureRandom which is seeded from OS entropy sources
     * - Suitable for security-sensitive applications
     * - Resistant to brute-force attacks (2^256 possible combinations)
     * - No timing attacks possible due to constant-time operations
     * 
     * @return A Base64 URL-encoded secure random token
     * @see #generateToken(int)
     */
    public static String generateToken() {
        return generateToken(DEFAULT_TOKEN_LENGTH);
    }

    /**
     * Generates a cryptographically secure random token with custom length.
     * 
     * This method allows fine-tuning the token length based on specific security
     * requirements and storage constraints. The resulting Base64-encoded token
     * will be approximately 33% longer than the byte length.
     * 
     * Length recommendations:
     * - 16 bytes (128 bits): Minimum for short-lived tokens (email confirmation)
     * - 32 bytes (256 bits): Recommended for most use cases (default)
     * - 64 bytes (512 bits): High-security applications with strict requirements
     * 
     * Base64 encoding overhead:
     * - 16 bytes → ~22 characters
     * - 32 bytes → ~43 characters
     * - 64 bytes → ~86 characters
     * 
     * @param lengthInBytes The desired token length in bytes (recommended: 16-64)
     * @return A Base64 URL-encoded secure random token
     * @throws IllegalArgumentException if lengthInBytes is less than 1
     * @see #generateToken()
     */
    public static String generateToken(int lengthInBytes) {
        if (lengthInBytes < 1) {
            throw new IllegalArgumentException("Token length must be at least 1 byte");
        }

        byte[] randomBytes = new byte[lengthInBytes];
        SECURE_RANDOM.nextBytes(randomBytes);

        String token = URL_ENCODER.encodeToString(randomBytes);

        log.debug("Generated secure token with {} bytes ({} bits of entropy)", 
                  lengthInBytes, lengthInBytes * 8);

        return token;
    }

    /**
     * Generates a token suitable for short-lived operations (16 bytes, 128 bits).
     * 
     * This method is optimised for tokens with limited lifetime where storage
     * space is a concern. Suitable for:
     * - Email confirmation tokens (5-15 minute expiry)
     * - Password reset tokens (15 minute expiry)
     * - One-time use tokens
     * 
     * Security note: 128 bits of entropy is sufficient for short-lived tokens
     * as the limited validity window reduces brute-force attack opportunities.
     * 
     * @return A Base64 URL-encoded token (~22 characters)
     */
    public static String generateShortToken() {
        return generateToken(16); // 128 bits
    }

    /**
     * Generates a token suitable for long-lived operations (32 bytes, 256 bits).
     * 
     * This method is recommended for tokens with extended lifetime where
     * maximum security is required. Suitable for:
     * - Refresh tokens (30 day expiry)
     * - API keys
     * - Session tokens
     * 
     * Security note: 256 bits of entropy provides robust protection against
     * brute-force attacks even with long validity periods.
     * 
     * @return A Base64 URL-encoded token (~43 characters)
     */
    public static String generateLongToken() {
        return generateToken(32); // 256 bits (default)
    }
}
