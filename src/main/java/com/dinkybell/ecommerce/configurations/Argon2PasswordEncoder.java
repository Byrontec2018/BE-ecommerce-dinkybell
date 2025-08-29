package com.dinkybell.ecommerce.configurations;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Modern password encoder using Argon2id algorithm.
 * 
 * Argon2 is the winner of the Password Hashing Competition (PHC) 2015
 * and is recommended by OWASP as the preferred password hashing algorithm.
 * 
 * Benefits:
 * - Memory-hard function (protects against GPU/ASIC attacks)
 * - Configurable time, memory, and parallelism costs
 * - More resistant to side-channel attacks
 * - Designed specifically for password hashing
 * 
 * This implementation uses Argon2id variant which provides protection
 * against both side-channel and time-memory trade-off attacks.
 */
@Component
public class Argon2PasswordEncoder implements PasswordEncoder {

    private final Argon2 argon2;
    
    // Configuration parameters for Argon2
    private static final int ITERATIONS = 3;        // Time cost (number of iterations)
    private static final int MEMORY_KB = 65536;     // Memory cost in KB (64 MB)
    private static final int PARALLELISM = 1;       // Number of parallel threads
    private static final int HASH_LENGTH = 32;      // Length of the hash in bytes

    public Argon2PasswordEncoder() {
        // Use Argon2id variant (recommended by OWASP)
        this.argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    }

    /**
     * Encodes the raw password using Argon2id.
     * 
     * @param rawPassword the raw password to encode
     * @return the encoded password hash
     * @throws IllegalArgumentException if rawPassword is null
     */
    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("Raw password cannot be null");
        }
        
        try {
            // Hash the password with the configured parameters
            String hash = argon2.hash(
                ITERATIONS,
                MEMORY_KB,
                PARALLELISM,
                rawPassword.toString().toCharArray()
            );
            
            return hash;
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash password with Argon2", e);
        }
    }

    /**
     * Verifies a raw password against an encoded password.
     * 
     * @param rawPassword the raw password to verify
     * @param encodedPassword the encoded password to compare against
     * @return true if the password matches, false otherwise
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        
        try {
            // Verify the password against the hash
            boolean matches = argon2.verify(encodedPassword, rawPassword.toString().toCharArray());
            
            // Clear sensitive data from memory
            if (rawPassword instanceof String) {
                // Note: We can't actually clear a String from memory in Java
                // but we can clear char arrays. Consider using char[] in future.
            }
            
            return matches;
        } catch (Exception e) {
            // Log the error but don't expose details in the return value
            // This prevents timing attacks based on exception handling
            return false;
        }
    }

    /**
     * Checks if the encoded password should be re-encoded.
     * 
     * This can be useful for upgrading password hashes when
     * security parameters change over time.
     * 
     * @param encodedPassword the encoded password to check
     * @return true if the password should be re-encoded
     */
    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        // For now, we don't support automatic upgrades
        // In the future, this could check if the hash uses old parameters
        return false;
    }

    /**
     * Gets the current Argon2 configuration as a string for logging/debugging.
     * 
     * @return configuration string
     */
    public String getConfiguration() {
        return String.format(
            "Argon2id(iterations=%d, memory=%dKB, parallelism=%d, hashLength=%d)",
            ITERATIONS, MEMORY_KB, PARALLELISM, HASH_LENGTH
        );
    }
}
